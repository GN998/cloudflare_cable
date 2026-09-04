// src/tunnelRoom.ts
import { DurableObject } from "cloudflare:workers";
import { Env, Role, DO_STATE_KEYS } from "./types";
import { inferRole, generateRoutingId } from "./utils/fido";
import { createError } from "./utils/response";

/**
 * FIDO caBLE Tunnel Core Room Class (Durable Object)
 * Responsible for WebSocket interception, state synchronization, lock-free buffering, and lifecycle scheduling.
 */
export class TunnelRoom extends DurableObject<Env> {
    constructor(ctx: DurableObjectState, env: Env) {
        super(ctx, env);
        
        // Lock-free synchronous table creation:
        // DO storage operations are single-threaded and synchronous. We initialize schemas right inside the constructor.
        // Spec Correction: blockConcurrencyWhile is used to block incoming concurrent requests,
        // ensuring the underlying Schema is fully initialized before routing any network traffic.
        this.ctx.blockConcurrencyWhile(async () => {
            this.ctx.storage.sql.exec(`
                CREATE TABLE IF NOT EXISTS msg_buffer (
                    id INTEGER PRIMARY KEY, 
                    sender_role TEXT, 
                    data BLOB, 
                    created_at INTEGER
                )
            `);
        });
    }

    async fetch(request: Request): Promise<Response> {
        const url = new URL(request.url);
        
        // 1. Extract context and infer the operational role
        const hasClientPayload = request.headers.has("X-caBLE-Client-Payload");
        const role = inferRole(url.pathname, hasClientPayload);
        const isContact = url.pathname.startsWith("/cable/contact/");
        const isNew = url.pathname.startsWith("/cable/new/");

        // 2. Inspect tunnel lifecycle status (Tombstone mechanism)
        const isTombstoned = !!(await this.ctx.storage.get(DO_STATE_KEYS.TOMBSTONED));
        if (isTombstoned) {
            return createError("Gone: Tunnel is exhausted and permanently sealed", 410);
        }

        // 3. Record Contact status
        if (isContact) {
            await this.ctx.storage.put(DO_STATE_KEYS.IS_CONTACT, true);
        }

        // Core Mechanic: Exclusive eviction for identical roles & capacity restrictions
        // Filter and retrieve WebSockets directly via 'Role' tags at the framework layer, eliminating complex in-memory Maps.
        const existingSameRoleSockets = this.ctx.getWebSockets(role);
        for (const sock of existingSameRoleSockets) {
            try { 
                sock.close(1000, "Replaced by new connection"); 
            } catch (e) { /* Ignore errors from stale connections */ }
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

        // 5. Update pairing status
        const targetRole: Role = role === "client" ? "authenticator" : "client";
        const peerSockets = this.ctx.getWebSockets(targetRole);
        if (peerSockets.length > 0) {
            await this.ctx.storage.put(DO_STATE_KEYS.HAS_PAIRED, true);
        }

        // Implementation strategy: Atomically read and delete buffered peer messages
        // within transactionSync, then deliver them over WebSocket after the
        // storage transaction completes.
        const messagesToDispatch = this.ctx.storage.transactionSync(() => {
            // Fetch offline messages emitted by the peer
            const cursor = this.ctx.storage.sql.exec(
                `SELECT data FROM msg_buffer WHERE sender_role != ? ORDER BY created_at ASC`,
                role
            );
            
            const msgs: ArrayBuffer[] = [];
            for (const row of cursor) {
                // SQLite BLOB is streamed directly into an ArrayBuffer, incurring zero serialization overhead
                msgs.push(row.data as ArrayBuffer);
            }
            
            // Once securely pulled into memory, wipe them out within the same physical transaction
            if (msgs.length > 0) {
                // Delete only the messages sent by the peer to prevent wiping out unread messages sent by myself
                this.ctx.storage.sql.exec(`DELETE FROM msg_buffer WHERE sender_role != ?`, role);
            }
            
            return msgs;
        });

        // Deliver buffered messages after the transaction commits.
        for (const msg of messagesToDispatch) {
            try {
                server.send(msg);
            } catch (e) {
                console.warn("Buffered message dispatch failed", e);
            }
        }

        // 6. Assemble protocol response headers
        const headers = new Headers();
        const requestedProtocols = request.headers.get("Sec-WebSocket-Protocol") || "";
        const protocolsList = requestedProtocols.split(",").map(p => p.trim());
        if (protocolsList.includes("fido.cable")) {
            headers.set("Sec-WebSocket-Protocol", "fido.cable"); 
        }

        // If it is a newly customized creation request, supply a Routing ID to formulate the QR code
        if (isNew) {
            headers.set("X-Cable-Routing-Id", generateRoutingId());
        }

        return new Response(null, { status: 101, webSocket: client, headers });
    }

    /**
     * [Hibernation API] Processes incoming WebSocket messages
     */
    async webSocketMessage(ws: WebSocket, message: ArrayBuffer | string) {
        // Defensive Interception 1: CTAP2.3 Spec dictates only binary frames are valid
        if (typeof message === "string") {
            ws.close(1003, "Unsupported Data: FIDO caBLE requires binary frames");
            return;
        }

        // Defensive Interception 2: CTAP 2.3 Spec Section 11.5.1.2 declares empty messages as explicit protocol violations
        if (message.byteLength === 0) {
            ws.close(1002, "Protocol Error: Empty message is not allowed in caBLE");
            return;
        }

        // Defensive Interception 3: Service-level DoS and memory-depletion protection.
        if (message.byteLength > 1049600) {
            ws.close(1009, "Message Too Big: Exceeds service-defined ciphertext limit");
            return;
        }

        // Rapidly restore role context via tags
        const tags = this.ctx.getTags(ws);
        const myRole = (tags[0] || "client") as Role; 
        const targetRole: Role = myRole === "client" ? "authenticator" : "client";
        const peerSockets = this.ctx.getWebSockets(targetRole);

        // Core Mechanic: Ultra-fast relaying vs lock-free buffering
        if (peerSockets.length > 0) {
            // Peer is online: direct memory pass-through bypassing storage for zero latency
            for (const peer of peerSockets) {
                try { peer.send(message); } catch (e) {}
            }
        } else {
            // Peer is offline: synchronous buffer flush to disk
            const countRow = this.ctx.storage.sql.exec(`SELECT count(*) as count FROM msg_buffer`).one();
            if ((countRow as any).count < 10) { 
                this.ctx.storage.sql.exec(
                    `INSERT INTO msg_buffer (sender_role, data, created_at) VALUES (?, ?, ?)`, 
                    myRole, message, Date.now()
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
        const tags = this.ctx.getTags(ws);
        if (tags.length === 0) return; // Already processed/cleaned up

        const myRole = tags[0] as Role;
        const targetRole: Role = myRole === "client" ? "authenticator" : "client";

        // Cascading teardown: If one side of a FIDO tunnel drops, the whole session becomes obsolete
        const peerSockets = this.ctx.getWebSockets(targetRole);
        for (const peer of peerSockets) {
            try { peer.close(1001, "Peer disconnected"); } catch (e) {}
        }

        // Schedule lifecycles via Alarms TTL
        const isContact = !!(await this.ctx.storage.get(DO_STATE_KEYS.IS_CONTACT));
        const hasPaired = !!(await this.ctx.storage.get(DO_STATE_KEYS.HAS_PAIRED));
        const tombstoned = !!(await this.ctx.storage.get(DO_STATE_KEYS.TOMBSTONED));
        
        if (!isContact && hasPaired && !tombstoned) {
            // Ephemeral session already paired: Mark as dead, queue physical purge in 1 minute
            await this.ctx.storage.put(DO_STATE_KEYS.TOMBSTONED, true);
            await this.ctx.storage.setAlarm(Date.now() + 60 * 1000); 
        } else if (isContact) {
            // Persistent contact: Silently extend lease for 30 days
            await this.ctx.storage.setAlarm(Date.now() + 30 * 24 * 60 * 60 * 1000);
        } else {
            // Not paired yet (peer hasn't joined), provide a 3-minute grace period
            await this.ctx.storage.setAlarm(Date.now() + 3 * 60 * 1000);
        }
    }

    /**
     * Core Mechanic: Absolute Physical Destruction
     */
    async alarm() {
        const allSockets = this.ctx.getWebSockets();
        for (const sock of allSockets) {
            try { sock.close(1000, "Tunnel absolute TTL expired"); } catch (e) {}
        }
        
        // Completely reclaim storage blocks and self-destruct
        await this.ctx.storage.deleteAll();
    }
}
