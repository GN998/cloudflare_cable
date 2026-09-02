// src/tunnelRoom.ts
import { DurableObject } from "cloudflare:workers";
import { Env, Role, DO_STATE_KEYS, SocketAttachment, ContactNotification, DataRole } from "./types";
import { inferRole, generateRoutingId } from "./utils/fido";
import { createError } from "./utils/response";

/**
 * Helper for constant-time string comparison to prevent timing attacks
 */
function timingSafeEqual(a: string, b: string): boolean {
    if (a.length !== b.length) return false;
    let result = 0;
    for (let i = 0; i < a.length; i++) {
        result |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }
    return result === 0;
}

/**
 * FIDO caBLE Tunnel Core Room Class (Durable Object)
 * Responsible for WebSocket interception, state synchronization, lock-free buffering, and lifecycle scheduling.
 */
export class TunnelRoom extends DurableObject<Env> {
    constructor(ctx: DurableObjectState, env: Env) {
        super(ctx, env);
        
        // Lock-free synchronous table creation:
        // DO storage operations are single-threaded and synchronous. We initialize schemas right inside the constructor.
        // Spec Correction: Adhering strictly to official guidelines, blockConcurrencyWhile is used to block incoming 
        // concurrent requests, ensuring the underlying Schema is fully initialized before routing any network traffic or events.
        this.ctx.blockConcurrencyWhile(async () => {
            // Updated schema for data plane message buffering with request_id isolation
            // Default value is set temporarily to prevent legacy code from crashing during step-by-step refactoring
            this.ctx.storage.sql.exec(`
                CREATE TABLE IF NOT EXISTS msg_buffer (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, 
                    sender_role TEXT NOT NULL, 
                    data BLOB NOT NULL, 
                    created_at INTEGER NOT NULL
                )
            `);

            // Execute backward-compatible schema migration to add request_id if missing
            const tableInfo = this.ctx.storage.sql.exec(`PRAGMA table_info(msg_buffer)`);
            let hasRequestId = false;
            for (const row of tableInfo) {
                if ((row as any).name === 'request_id') {
                    hasRequestId = true;
                    break;
                }
            }
            if (!hasRequestId) {
                this.ctx.storage.sql.exec(`ALTER TABLE msg_buffer ADD COLUMN request_id TEXT NOT NULL DEFAULT 'legacy-qr'`);
            }

            // New schema for contact request lifecycle management
            this.ctx.storage.sql.exec(`
                CREATE TABLE IF NOT EXISTS contact_requests (
                    request_id TEXT PRIMARY KEY,
                    accept_token_hash TEXT NOT NULL,
                    state TEXT NOT NULL,      -- 'pending', 'accepted', 'closed'
                    expires_at INTEGER NOT NULL
                )
            `);
        });
    }

    async fetch(request: Request): Promise<Response> {
        const url = new URL(request.url);
        
        // Route incoming traffic to specialized handlers based on the endpoint path
        if (url.pathname.startsWith("/internal/contact/revoke/")) {
            return this.revokeContact(request);
        }
        if (url.pathname.startsWith("/internal/contact/register/")) {
            return this.registerContactControl(request);
        }
        if (url.pathname.startsWith("/internal/contact/accept/")) {
            return this.acceptContactRequest(request);
        }
        if (url.pathname.startsWith("/cable/contact/")) {
            return this.startContactRequest(request);
        }
        
        // Fallback to the legacy QR code tunnel flow for all other requests
        return this.openQrTunnel(request);
    }

    // Handles contact revocation requested by the authenticator, effectively enforcing the 410 Unlink rule
    private async revokeContact(request: Request): Promise<Response> {
        const authHeader = request.headers.get("Authorization") || "";
        const capability = authHeader.replace(/^Bearer\s+/i, "").trim();
        if (!capability) {
            return createError("Unauthorized: Missing capability", 401);
        }

        const encoder = new TextEncoder();
        const capHashBuffer = await crypto.subtle.digest("SHA-256", encoder.encode(capability));
        const presentedCapHash = Array.from(new Uint8Array(capHashBuffer)).map(b => b.toString(16).padStart(2, "0")).join("");

        const storedCapHash = await this.ctx.storage.kv.get(DO_STATE_KEYS.CAPABILITY_HASH);
        
        // Use constant-time comparison for capability validation
        if (!storedCapHash || !timingSafeEqual(presentedCapHash, storedCapHash as string)) {
            return createError("Forbidden: Invalid capability", 403);
        }

        // Persistently mark the contact session as revoked and permanently unlinked
        this.ctx.storage.kv.put(DO_STATE_KEYS.CONTACT_REVOKED, true);

        // Force disconnect any attached sockets across all channels
        const allSockets = this.ctx.getWebSockets();
        for (const sock of allSockets) {
            try { sock.close(4100, "Contact permanently unlinked"); } catch {}
        }

        // Physically delete all pending request and message buffer state
        this.ctx.storage.sql.exec(`DELETE FROM contact_requests`);
        this.ctx.storage.sql.exec(`DELETE FROM msg_buffer`);

        // Explicitly clear any remaining alarms to prevent periodic wakeups for revoked contact instances
        await this.ctx.storage.deleteAlarm();

        return new Response("OK: Contact permanently unlinked", { status: 200 });
    }

    // Processes the authenticator's long-lived control connection registration
    private async registerContactControl(request: Request): Promise<Response> {
        const url = new URL(request.url);
        const parts = url.pathname.split("/").filter(Boolean);
        const contactId = parts[3];

        // Fast failure check before expensive crypto operations to optimize rejection
        if (!!this.ctx.storage.kv.get(DO_STATE_KEYS.CONTACT_REVOKED)) {
            return createError("Gone: Contact ID permanently unlinked", 410);
        }
        const initialControls = this.ctx.getWebSockets("contact-control");
        if (initialControls.length > 0) {
            return createError("Conflict: Authenticator already registered", 409);
        }

        // Derive a unique device capability using HMAC-SHA256 with the global internal token and contact ID
        const encoder = new TextEncoder();
        const keyMaterial = await crypto.subtle.importKey(
            "raw",
            encoder.encode(this.env.CONTACT_INTERNAL_TOKEN),
            { name: "HMAC", hash: "SHA-256" },
            false,
            ["sign"]
        );
        const signature = await crypto.subtle.sign(
            "HMAC",
            keyMaterial,
            encoder.encode(`contact:${contactId}`)
        );
        const capability = Array.from(new Uint8Array(signature))
            .map(b => b.toString(16).padStart(2, "0"))
            .join("");

        // Hash the generated capability before storing it to prevent plaintext credential exposure
        const capHashBuffer = await crypto.subtle.digest("SHA-256", encoder.encode(capability));
        const capabilityHash = Array.from(new Uint8Array(capHashBuffer))
            .map(b => b.toString(16).padStart(2, "0"))
            .join("");

        // Final synchronous critical section: No await allowed from here to acceptWebSocket
        // Enforce the 410 Unlink rule to reject old keys even if they possess the valid capability
        if (!!this.ctx.storage.kv.get(DO_STATE_KEYS.CONTACT_REVOKED)) {
            return createError("Gone: Contact ID permanently unlinked", 410);
        }

        const controls = this.ctx.getWebSockets("contact-control");
        
        // Prevent connection replacement by returning 409 Conflict if a control connection already exists
        if (controls.length > 0) {
            return createError("Conflict: Authenticator already registered", 409);
        }

        this.ctx.storage.kv.put(DO_STATE_KEYS.CAPABILITY_HASH, capabilityHash);

        // Explicitly mark this DO as a Contact Room so that alarm() uses the correct lifecycle logic
        this.ctx.storage.kv.put(DO_STATE_KEYS.IS_CONTACT, true);

        const pair = new WebSocketPair();
        const [client, server] = Object.values(pair);

        // Tag the socket and serialize its state attachment for hibernation recovery
        this.ctx.acceptWebSocket(server, ["contact-control"]);
        server.serializeAttachment({
            role: "contact-control",
            superseded: false
        } as SocketAttachment);

        return new Response(null, {
            status: 101,
            webSocket: client,
            headers: {
                "Sec-WebSocket-Protocol": "fido.cable.contact",
                "X-Contact-Capability": capability
            }
        });
    }

    // Handles a client-initiated state-assisted contact request for this implementation.
    private async startContactRequest(request: Request): Promise<Response> {
        const clientPayload = request.headers.get("X-caBLE-Client-Payload");
        if (!clientPayload) {
            return createError("Bad Request: Missing X-caBLE-Client-Payload", 400);
        }

        // Generate a 16-byte random request ID
        const reqBytes = new Uint8Array(16);
        crypto.getRandomValues(reqBytes);
        const requestId = Array.from(reqBytes).map(b => b.toString(16).padStart(2, "0")).join("");

        // Generate a 16-byte one-time accept token
        const tokenBytes = new Uint8Array(16);
        crypto.getRandomValues(tokenBytes);
        const acceptToken = Array.from(tokenBytes).map(b => b.toString(16).padStart(2, "0")).join("");

        // Perform async crypto operations before the final authoritative state checks
        // Hash the accept token before storing it in SQLite
        const encoder = new TextEncoder();
        const hashBuffer = await crypto.subtle.digest("SHA-256", encoder.encode(acceptToken));
        const acceptTokenHash = Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, "0")).join("");

        // Set request expiration (e.g., 60 seconds TTL)
        const expiresAt = Date.now() + 60 * 1000;

        // Final synchronous critical section: No await allowed from here to acceptWebSocket
        // Enforce the 410 Unlink rule by checking the revocation state
        if (!!this.ctx.storage.kv.get(DO_STATE_KEYS.CONTACT_REVOKED)) {
            return createError("Gone: Contact ID permanently unlinked", 410);
        }

        // Ensure the authenticator's control channel is online
        const controls = this.ctx.getWebSockets("contact-control");
        if (controls.length === 0) {
            return createError("Service Unavailable: Authenticator offline", 503);
        }

        // Enforce Phase 0 constraint: Only one active transaction per Contact ID
        const activeClients = this.ctx.getWebSockets("client");
        if (activeClients.length > 0) {
            return createError("Conflict: Transaction already in progress", 409);
        }

        // Persist the pending request state
        this.ctx.storage.sql.exec(
            `INSERT INTO contact_requests (request_id, accept_token_hash, state, expires_at) VALUES (?, ?, 'pending', ?)`,
            requestId, acceptTokenHash, expiresAt
        );

        const pair = new WebSocketPair();
        const [client, server] = Object.values(pair);

        // Bind the client socket to the newly generated request scope
        this.ctx.acceptWebSocket(server, ["client", `req:${requestId}`]);
        server.serializeAttachment({
            role: "client",
            requestId,
            superseded: false
        } as SocketAttachment);

        // Dispatch the JSON notification through the control channel
        const notification: ContactNotification = {
            type: "contact",
            requestId,
            acceptToken,
            clientPayload
        };

        try {
            controls[0].send(JSON.stringify(notification));
        } catch (e) {
            // Explicitly rollback pending state and associated buffers upon notification failure using physical deletion
            this.ctx.storage.sql.exec(`DELETE FROM contact_requests WHERE request_id = ?`, requestId);
            this.ctx.storage.sql.exec(`DELETE FROM msg_buffer WHERE request_id = ?`, requestId);
            try { server.close(1011, "Authenticator notification failed"); } catch (err) {}
            await this.scheduleNextAlarm();
            
            return createError("Service Unavailable: Failed to notify authenticator", 503);
        }

        // Trigger dynamic alarm recalculation
        await this.scheduleNextAlarm();

        return new Response(null, {
            status: 101,
            webSocket: client,
            headers: {
                "Sec-WebSocket-Protocol": "fido.cable"
            }
        });
    }

    // Completes acceptance of a pending contact request and establishes the relay channel.
    private async acceptContactRequest(request: Request): Promise<Response> {
        // Enforce the 410 Unlink rule prior to processing the accept sequence
        if (!!this.ctx.storage.kv.get(DO_STATE_KEYS.CONTACT_REVOKED)) {
            return createError("Gone: Contact ID permanently unlinked", 410);
        }

        const url = new URL(request.url);
        const parts = url.pathname.split("/").filter(Boolean);
        const requestId = parts[4]; // Path structure: /internal/contact/accept/{contactID}/{requestID}

        // Apply strict Regex validation against the provided Request ID format
        if (!requestId || !/^[a-f0-9]{32}$/.test(requestId)) {
            return createError("Bad Request: Invalid request ID format", 400);
        }

        const encoder = new TextEncoder();

        // 1. Verify capability ownership
        const authHeader = request.headers.get("Authorization") || "";
        const capability = authHeader.replace(/^Bearer\s+/i, "").trim();
        if (!capability) {
            return createError("Unauthorized: Missing capability", 401);
        }

        const capHashBuffer = await crypto.subtle.digest("SHA-256", encoder.encode(capability));
        const presentedCapHash = Array.from(new Uint8Array(capHashBuffer)).map(b => b.toString(16).padStart(2, "0")).join("");
        
        const storedCapHash = await this.ctx.storage.kv.get(DO_STATE_KEYS.CAPABILITY_HASH);
        
        // Use constant-time comparison for capability validation
        if (!storedCapHash || !timingSafeEqual(presentedCapHash, storedCapHash as string)) {
            return createError("Forbidden: Invalid capability", 403);
        }

        // 2. Verify the one-time accept token
        const acceptToken = request.headers.get("X-Contact-Accept-Token");
        if (!acceptToken) {
            return createError("Unauthorized: Missing accept token", 401);
        }
        
        const tokenHashBuffer = await crypto.subtle.digest("SHA-256", encoder.encode(acceptToken));
        const presentedTokenHash = Array.from(new Uint8Array(tokenHashBuffer)).map(b => b.toString(16).padStart(2, "0")).join("");

        const reqCursor = this.ctx.storage.sql.exec(
            `SELECT state, accept_token_hash, expires_at FROM contact_requests WHERE request_id = ?`,
            requestId
        );
        const rows = Array.from(reqCursor) as any[];
        const reqRow = rows[0];

        if (!reqRow) {
            return createError("Not Found: Invalid request ID", 404);
        }
        if (reqRow.state !== "pending") {
            return createError("Conflict: Request already accepted or closed", 409);
        }
        if (Date.now() > reqRow.expires_at) {
            return createError("Gone: Request expired", 410);
        }
        
        // Use constant-time comparison for accept token validation
        if (!timingSafeEqual(reqRow.accept_token_hash, presentedTokenHash)) {
            return createError("Forbidden: Invalid accept token", 403);
        }

        // Enforce Phase 0 single-transaction limits on the authenticator side
        const existingAuth = this.ctx.getWebSockets("authenticator");
        if (existingAuth.length > 0) {
            return createError("Conflict: Authenticator data channel already engaged", 409);
        }

        // 3. Mark the transaction as accepted and invalidate the one-time token
        // Ensure atomic transition from pending to accepted using strict conditions
        this.ctx.storage.sql.exec(
            `UPDATE contact_requests SET state = 'accepted', accept_token_hash = '' WHERE request_id = ? AND state = 'pending'`,
            requestId
        );

        const pair = new WebSocketPair();
        const [client, server] = Object.values(pair);

        // Attach to the scoped data channel
        this.ctx.acceptWebSocket(server, ["authenticator", `req:${requestId}`]);
        server.serializeAttachment({
            role: "authenticator",
            requestId,
            superseded: false
        } as SocketAttachment);

        // Atomically fetch buffered messages sent by the client before the authenticator connected
        const bufferedRows = this.ctx.storage.transactionSync(() => {
            const cursor = this.ctx.storage.sql.exec(
                `SELECT id, data FROM msg_buffer WHERE request_id = ? AND sender_role != 'authenticator' ORDER BY created_at ASC`,
                requestId
            );
            
            const rows: { id: number, data: ArrayBuffer }[] = [];
            for (const row of cursor) {
                rows.push({
                    id: (row as any).id,
                    data: (row as any).data as ArrayBuffer
                });
            }
            
            return rows;
        });

        // Dispatch messages one by one, deleting them from storage only upon successful transmission
        for (const row of bufferedRows) {
            try {
                server.send(row.data);
                this.ctx.storage.sql.exec(`DELETE FROM msg_buffer WHERE id = ?`, row.id);
            } catch (e) {
                console.warn("Buffered message dispatch interrupted due to send failure", e);
                break;
            }
        }

        return new Response(null, {
            status: 101,
            webSocket: client,
            headers: {
                "Sec-WebSocket-Protocol": "fido.cable"
            }
        });
    }

    // Legacy QR tunnel setup extracted from the original fetch method
    private async openQrTunnel(request: Request): Promise<Response> {
        const url = new URL(request.url);
        
        // 1. Extract context and infer the operational role
        const hasClientPayload = request.headers.has("X-caBLE-Client-Payload");
        const role = inferRole(url.pathname, hasClientPayload);
        const isCustom = url.pathname.startsWith("/cable/new/");

        // 2. Inspect tunnel lifecycle status (Tombstone mechanism)
        // Use Synchronous KV API with boolean coercion to prevent undefined issues
        if (!!this.ctx.storage.kv.get(DO_STATE_KEYS.TOMBSTONED)) {
            return createError("Gone: Tunnel is exhausted and permanently sealed", 410);
        }

        // Core Mechanic: Exclusive eviction for identical roles & capacity restrictions
        // Filter and retrieve WebSockets directly via 'Role' tags at the framework layer, eliminating complex in-memory Maps.
        const existingSameRoleSockets = this.ctx.getWebSockets(role);
        
        // Directly reject colliding roles with 409 Conflict instead of kicking out the existing connection
        if (existingSameRoleSockets.length > 0) {
            return createError("Conflict: Role already connected", 409);
        }

        const allSockets = this.ctx.getWebSockets();
        if (allSockets.length >= 2 && existingSameRoleSockets.length === 0) {
            return createError("Forbidden: Room is full", 403);
        }

        // 4. Initialize and intercept the WebSocket handshake
        const pair = new WebSocketPair();
        const [client, server] = Object.values(pair);

        // Core Mechanic: Lightweight containment based on Tags
        // Attach the role string as a tag onto the WebSocket, allowing immediate identification upon hibernation wakeups.
        this.ctx.acceptWebSocket(server, [role]);

        // Persist the socket role state across hibernations using attachments
        server.serializeAttachment({
            role: role,
            superseded: false
        } as SocketAttachment);

        // 5. Update pairing status
        const targetRole: Role = role === "client" ? "authenticator" : "client";
        const peerSockets = this.ctx.getWebSockets(targetRole);
        if (peerSockets.length > 0) {
            // Replace async put with Synchronous KV API
            this.ctx.storage.kv.put(DO_STATE_KEYS.HAS_PAIRED, true);
        }

        // Implementation strategy: Atomically read and delete buffered peer messages
        // within transactionSync, then deliver them over WebSocket after the
        // storage transaction completes.
        const bufferedRows = this.ctx.storage.transactionSync(() => {
            // Fetch offline messages emitted by the peer
            // Enforce legacy-qr request_id scope to avoid cross-talk with new contact flows
            const cursor = this.ctx.storage.sql.exec(
                `SELECT id, data FROM msg_buffer WHERE sender_role != ? AND request_id = 'legacy-qr' ORDER BY created_at ASC`,
                role
            );
            
            const rows: { id: number, data: ArrayBuffer }[] = [];
            for (const row of cursor) {
                // SQLite BLOB is streamed directly into an ArrayBuffer, incurring zero serialization overhead
                rows.push({
                    id: (row as any).id,
                    data: (row as any).data as ArrayBuffer
                });
            }
            
            return rows;
        });

        // Deliver buffered messages after the transaction commits.
        // Delivery is best-effort: a send failure does not restore messages
        // already removed from the persistent buffer.
        for (const row of bufferedRows) {
            try {
                server.send(row.data);
                // Execute physical deletion solely after a successful transmission
                this.ctx.storage.sql.exec(`DELETE FROM msg_buffer WHERE id = ?`, row.id);
            } catch (e) {
                console.warn("Buffered message dispatch interrupted due to send failure", e);
                break;
            }
        }

        // 6. Assemble protocol response headers
        const headers = new Headers();
        
        // Gateway has already performed strict exact token matching validation
        // Safely set the protocol without redundant and insecure substring checks
        headers.set("Sec-WebSocket-Protocol", "fido.cable"); 

        // If it is a newly customized creation request, supply a Routing ID to formulate the QR code
        if (isCustom) {
            headers.set("X-Cable-Routing-Id", generateRoutingId());
        }

        return new Response(null, { status: 101, webSocket: client, headers });
    }

    /**
     * [Hibernation API] Processes incoming WebSocket messages
     */
    async webSocketMessage(ws: WebSocket, message: ArrayBuffer | string) {
        // Extract socket state using attachments to retrieve precise role and request scope
        const attachment = ws.deserializeAttachment() as SocketAttachment | null;
        if (!attachment) {
            ws.close(1011, "Missing socket state");
            return;
        }

        // Drop messages sent to the control plane, as it is only for JSON notifications.
        // This check is intentionally placed before frame type validations to safely ignore text/heartbeat frames on the control socket.
        if (attachment.role === "contact-control") {
            return;
        }

        // For caBLE data-transfer channels, CTAP 2.3 §11.5.1.1.1 permits only binary WebSocket frames.
        if (typeof message === "string") {
            ws.close(1003, "Unsupported Data: FIDO caBLE requires binary frames");
            return;
        }

        // Reject an empty binary WebSocket payload as a service-level framing check.
        // This does not implement CTAP 2.3 §11.5.1.2's post-decryption
        // validation of an empty plaintext message because the tunnel service
        // relays encrypted records without decrypting them.
        if (message.byteLength === 0) {
            ws.close(1002, "Protocol Error: Empty binary WebSocket payload");
            return;
        }

        // Defensive Interception 3: Service-level DoS and memory-depletion protection.
        // The CTAP 2.3 §11.5.1.2 example implementation caps plaintext
        // messages at 1 MiB. With its 32-byte padding granularity and a
        // 16-byte AES-GCM tag, the maximum corresponding ciphertext size
        // is 1,048,624 bytes.
        // This service uses a slightly higher, implementation-defined rounded
        // limit of 1,049,600 bytes.
        if (message.byteLength > 1049600) {
            ws.close(1009, "Message Too Big: Exceeds service-defined ciphertext limit");
            return;
        }

        const myRole = attachment.role as DataRole;
        const targetRole: DataRole = myRole === "client" ? "authenticator" : "client";
        
        let peer: WebSocket | undefined;

        // Perform exact matching for transaction scopes, falling back to legacy QR mode
        if (attachment.requestId) {
            const candidates = this.ctx.getWebSockets(`req:${attachment.requestId}`);
            peer = candidates.find(candidate => {
                const state = candidate.deserializeAttachment() as SocketAttachment | null;
                return state?.role === targetRole && state.requestId === attachment.requestId;
            });
        } else {
            const peerSockets = this.ctx.getWebSockets(targetRole);
            peer = peerSockets.length > 0 ? peerSockets[0] : undefined;
        }

        // Core Mechanic: Ultra-fast relaying vs lock-free buffering
        if (peer) {
            // Peer is online: direct memory pass-through bypassing storage for zero latency
            try { 
                peer.send(message); 
            } catch (e) {
                // Explicitly close both endpoints when delivery fails to avoid silent zombie tunnels
                try { peer.close(1011, "Internal Error: Relay delivery failed"); } catch (err) {}
                try { ws.close(1011, "Internal Error: Relay delivery failed"); } catch (err) {}
            }
        } else {
            // Peer is offline: synchronous buffer flush to disk
            // Bind exactly to the request scope to prevent cross-transaction leakage
            const reqIdForBuffer = attachment.requestId || 'legacy-qr';
            
            // Threshold protection (max 10 items) to prevent malicious SQLite storage flooding
            const countRow = this.ctx.storage.sql.exec(`SELECT count(*) as count FROM msg_buffer WHERE request_id = ?`, reqIdForBuffer).one();
            if ((countRow as any).count < 10) { 
                this.ctx.storage.sql.exec(
                    `INSERT INTO msg_buffer (request_id, sender_role, data, created_at) VALUES (?, ?, ?, ?)`, 
                    reqIdForBuffer, myRole, message, Date.now()
                );
            } else {
                ws.close(1009, "Message Too Big: Buffer overflow before peer connected");
            }
        }
    }

    async webSocketClose(ws: WebSocket, code: number, reason: string, wasClean: boolean) {
        await this.handleDisconnect(ws);
    }

    async webSocketError(ws: WebSocket, error: unknown) {
        await this.handleDisconnect(ws);
    }

    /**
     * Core Mechanic: Full-duplex cascading termination & lifecycle orchestration
     */
    private async handleDisconnect(ws: WebSocket) {
        // Extract attachment to process disconnection within specific scope
        const attachment = ws.deserializeAttachment() as SocketAttachment | null;
        if (!attachment) return; // Already processed/cleaned up

        // Disconnecting the control plane must never tear down active data tunnels
        if (attachment.role === "contact-control") {
            // Clean up any pending requests when the control channel drops
            const pendingCursor = this.ctx.storage.sql.exec(`SELECT request_id FROM contact_requests WHERE state = 'pending'`);
            const pendingIds: string[] = [];
            for (const row of pendingCursor) {
                pendingIds.push((row as any).request_id);
            }
            
            for (const reqId of pendingIds) {
                const clientSockets = this.ctx.getWebSockets(`req:${reqId}`);
                for (const sock of clientSockets) {
                    try { sock.close(1011, "Authenticator offline"); } catch (e) {}
                }
                this.ctx.storage.sql.exec(`DELETE FROM contact_requests WHERE request_id = ?`, reqId);
                this.ctx.storage.sql.exec(`DELETE FROM msg_buffer WHERE request_id = ?`, reqId);
            }
            
            // Recalculate alarm to prevent ghost wakeups after clearing pending requests
            await this.scheduleNextAlarm();
            return;
        }

        // Ignore cleanup if the socket was actively superseded (safety guard)
        if (attachment.superseded) {
            return;
        }

        const myRole = attachment.role as DataRole;
        const targetRole: DataRole = myRole === "client" ? "authenticator" : "client";

        if (attachment.requestId) {
            // Scope the teardown strictly to the current request ID to avoid cross-talk
            const candidates = this.ctx.getWebSockets(`req:${attachment.requestId}`);
            for (const candidate of candidates) {
                const state = candidate.deserializeAttachment() as SocketAttachment | null;
                if (state?.role === targetRole && state.requestId === attachment.requestId) {
                    try { candidate.close(1001, "Peer disconnected"); } catch (e) {}
                }
            }

            // Immediately delete the closed request and physically wipe its specific message buffer to prevent storage bloating
            this.ctx.storage.sql.exec(`DELETE FROM contact_requests WHERE request_id = ?`, attachment.requestId);
            this.ctx.storage.sql.exec(`DELETE FROM msg_buffer WHERE request_id = ?`, attachment.requestId);

            await this.scheduleNextAlarm();
        } else {
            // Cascading teardown: If one side of a legacy QR FIDO tunnel drops, the whole session becomes obsolete
            const peerSockets = this.ctx.getWebSockets(targetRole);
            for (const peer of peerSockets) {
                try { peer.close(1001, "Peer disconnected"); } catch (e) {}
            }

            // Schedule lifecycles via Alarms TTL
            // Use Synchronous KV API with boolean coercion to prevent undefined issues
            const isContact = !!this.ctx.storage.kv.get(DO_STATE_KEYS.IS_CONTACT);
            const hasPaired = !!this.ctx.storage.kv.get(DO_STATE_KEYS.HAS_PAIRED);
            const tombstoned = !!this.ctx.storage.kv.get(DO_STATE_KEYS.TOMBSTONED);
            
            if (!isContact && hasPaired && !tombstoned) {
                // Ephemeral session already paired: Mark as dead, queue physical purge in 1 minute
                // Replace async put with Synchronous KV API
                this.ctx.storage.kv.put(DO_STATE_KEYS.TOMBSTONED, true);
                await this.ctx.storage.setAlarm(Date.now() + 60 * 1000); 
            } else if (isContact) {
                // Persistent contact: Silently extend lease for 30 days
                await this.ctx.storage.setAlarm(Date.now() + 30 * 24 * 60 * 60 * 1000);
            } else {
                // Not paired yet (peer hasn't joined), provide a 3-minute grace period
                await this.ctx.storage.setAlarm(Date.now() + 3 * 60 * 1000);
            }
        }
    }

    // Dynamically recalculate and schedule the next alarm for scoped Contact requests
    private async scheduleNextAlarm() {
        // Only target pending requests to avoid aggressively killing active sessions
        const cursor = this.ctx.storage.sql.exec(`SELECT MIN(expires_at) as next_expire FROM contact_requests WHERE state = 'pending'`);
        const row = [...cursor][0] as any;
        if (row && row.next_expire !== null) {
            // Guarantee alarm is set in the future
            const nextAlarm = Math.max(Date.now() + 1000, row.next_expire);
            await this.ctx.storage.setAlarm(nextAlarm);
        } else {
            // Fallback to persistent lease if no pending requests exist to prevent ghost alarms
            const isContact = !!this.ctx.storage.kv.get(DO_STATE_KEYS.IS_CONTACT);
            if (isContact) {
                // Cancel ghost wakeups when there are no pending requests to avoid an infinite loop
                await this.ctx.storage.deleteAlarm();
            }
        }
    }

    /**
     * Core Mechanic: Dynamic Recovery and Absolute Physical Destruction
     * Isolates the destruction of legacy QR setups from Contact requests to preserve control channels.
     */
    async alarm() {
        const isContact = !!this.ctx.storage.kv.get(DO_STATE_KEYS.IS_CONTACT);
        
        if (isContact) {
            const now = Date.now();
            
            // Sweep expired scoped requests
            // Strictly limit cleanup to pending requests to prevent P0-B TTL destruction of active tunnels
            const expiredCursor = this.ctx.storage.sql.exec(`SELECT request_id FROM contact_requests WHERE state = 'pending' AND expires_at <= ?`, now);
            const expiredIds: string[] = [];
            for (const row of expiredCursor) {
                expiredIds.push((row as any).request_id);
            }
            
            for (const reqId of expiredIds) {
                const sockets = this.ctx.getWebSockets(`req:${reqId}`);
                for (const sock of sockets) {
                    try { sock.close(1000, "Request TTL expired"); } catch (e) {}
                }
                // Physically remove expired records instead of just setting state='closed'
                this.ctx.storage.sql.exec(`DELETE FROM contact_requests WHERE request_id = ?`, reqId);
                this.ctx.storage.sql.exec(`DELETE FROM msg_buffer WHERE request_id = ?`, reqId);
            }

            // Queue the next cycle
            await this.scheduleNextAlarm();
        } else {
            const allSockets = this.ctx.getWebSockets();
            for (const sock of allSockets) {
                try { sock.close(1000, "Tunnel absolute TTL expired"); } catch (e) {}
            }
            
            // Completely reclaim storage blocks and self-destruct
            await this.ctx.storage.deleteAll();
        }
    }
}