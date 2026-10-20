// src/tunnelRoom.ts
import { DurableObject } from "cloudflare:workers";
import { Env, Role, DO_STATE_KEYS, DB_CONFIG } from "./types";
import { BufferStore } from "./db/bufferStore";
import { inferRole, validateFrame, generateRoutingId } from "./utils/fido";
import { createError } from "./utils/response";

/**
 * FIDO caBLE Tunnel Core Room Class (Durable Object) - v4.3 (Fixed)
 * Standard-compliant PASSKEY tunnel with hibernation support and offline SQLite buffering.
 */
export class TunnelRoom extends DurableObject<Env> {
    private db: BufferStore;

    /**
     * Cache persistent state flags in memory to prevent redundant billed storage reads within the same isolate lifecycle.
     */
    private isTombstonedCache: boolean | null = null;
    private isContactCache: boolean | null = null;
    private clientPayloadCache: string | null = null;

    constructor(ctx: DurableObjectState, env: Env) {
        super(ctx, env);
        
        // Instantiate the built-in SQLite data access layer
        this.db = new BufferStore(this.ctx.storage.sql);

        // Use blockConcurrencyWhile for asynchronous schema initialization, blocking concurrent requests.
        this.ctx.blockConcurrencyWhile(async () => {
            try {
                // Skip schema creation when waking a tombstoned instance for final eviction to avoid billed SQLite page writes.
                this.isTombstonedCache = !!(await this.ctx.storage.get(DO_STATE_KEYS.TOMBSTONED));
                if (!this.isTombstonedCache) {
                    this.db.initSchema();
                }
            } catch (error) {
                console.error("[caBLE] Failed to initialize SQLite database:", error);
            }
        });
    }

    async fetch(request: Request): Promise<Response> {
        const url = new URL(request.url);
        const path = url.pathname;
        
        // 1. Return 410 Gone if tombstoned to prevent session reuse and replay attacks.
        if (this.isTombstonedCache === null) {
            this.isTombstonedCache = !!(await this.ctx.storage.get(DO_STATE_KEYS.TOMBSTONED));
        }
        if (this.isTombstonedCache) {
            return createError("Gone: Tunnel is exhausted and permanently sealed", 410);
        }

        const isContact = path.startsWith("/cable/contact/");
        const isNew = path.startsWith("/cable/new/");

        // 2. Persist state indicating a state-assisted link transaction only once per room lifecycle.
        if (isContact && !this.isContactCache) {
            await this.ctx.storage.put(DO_STATE_KEYS.IS_CONTACT, true);
        }
        this.isContactCache = isContact;

        // 3. Extract client payload and check active sockets to initialize fresh session state.
        const clientPayload = request.headers.get("X-caBLE-Client-Payload");
        const hasClientPayload = clientPayload !== null;

        // Persist X-caBLE-Client-Payload when the client initiates a state-assisted transaction so the authenticator can retrieve it upon connecting.
        if (isContact && hasClientPayload) {
            const normalizedPayload = clientPayload.toLowerCase();
            const activeAuthSockets = this.ctx.getWebSockets("authenticator").filter(s => s.readyState === 1);
            // Purge unconsumed frames from aborted prior transactions to prevent Noise NKpsk0 handshake corruption.
            if (this.clientPayloadCache !== normalizedPayload && activeAuthSockets.length === 0) {
                this.db.clearAll();
            }
            this.clientPayloadCache = normalizedPayload;
            await this.ctx.storage.put(DO_STATE_KEYS.CLIENT_PAYLOAD, normalizedPayload);
        }

        // Mark buffer empty only when the first peer arrives in a fresh session with no pending alarm.
        const pendingAlarm = await this.ctx.storage.getAlarm();
        const hasActivePeers = this.ctx.getWebSockets().some(s => s.readyState === 1);
        if (!hasActivePeers && pendingAlarm === null) {
            this.db.markEmpty();
        }

        // Resolve participant role directly from endpoint semantics to support non-browser native clients.
        const role = inferRole(path, hasClientPayload);

        // 4. Close any stale connection of the same role and inherit its frame counter to prevent reconnect quota bypass.
        const existingSameRoleSockets = this.ctx.getWebSockets(role).filter(s => s.readyState === 1);
        let inheritedFrames = 0;
        for (const sock of existingSameRoleSockets) {
            const prevAttachment = sock.deserializeAttachment() as { relayedFrames?: number } | null;
            if (prevAttachment?.relayedFrames && prevAttachment.relayedFrames > inheritedFrames) {
                inheritedFrames = prevAttachment.relayedFrames;
            }
            try { 
                sock.close(1000, "Replaced by new connection session"); 
            } catch (e) {}
        }

        // Enforce maximum capacity of 2 active peers per tunnel.
        const updatedSockets = this.ctx.getWebSockets().filter(s => s.readyState === 1);
        if (updatedSockets.length >= 2 && existingSameRoleSockets.length === 0) {
            return createError("Forbidden: Room is full", 403);
        }

        // 5. Perform WebSocket handshake and upgrade.
        const pair = new WebSocketPair();
        const [client, server] = Object.values(pair);

        // Accept WebSocket with the role tag for hibernation state recovery.
        this.ctx.acceptWebSocket(server, [role]);

        // Attach frame counter to the WebSocket to survive Durable Object hibernation without billed storage writes.
        server.serializeAttachment({ relayedFrames: inheritedFrames });

        // Schedule or extend absolute session TTL alarm to guarantee cleanup of orphaned or stalled rooms.
        await this.ctx.storage.setAlarm(Date.now() + DB_CONFIG.SESSION_TTL_MS);

        // 6. Retrieve and dispatch offline buffered messages.
        try {
            const messagesToDispatch = this.db.consumeMessages(role);
            for (const msg of messagesToDispatch) {
                try {
                    server.send(msg);
                } catch (e) {
                    console.error("Failed to deliver recovered buffer message to reconnected peer", e);
                }
            }
        } catch (error) {
            console.error("Failed to consume offline buffered messages:", error);
        }

        // 7. Construct compliant response headers.
        const headers = new Headers();
        headers.set("Sec-WebSocket-Protocol", "fido.cable");
        
        if (isNew) {
            headers.set("X-Cable-Routing-Id", generateRoutingId());
        }

        // Forward the client payload header to the mobile authenticator on state-assisted transactions so it can derive the BLE EID key and Noise PSK.
        if (isContact && role === "authenticator") {
            if (this.clientPayloadCache === null) {
                this.clientPayloadCache = (await this.ctx.storage.get<string>(DO_STATE_KEYS.CLIENT_PAYLOAD)) ?? null;
            }
            if (this.clientPayloadCache) {
                headers.set("X-caBLE-Client-Payload", this.clientPayloadCache);
            }
        }

        return new Response(null, { status: 101, webSocket: client, headers });
    }

    /**
     * [Hibernation API] Handle incoming WebSocket message frames.
     */
    async webSocketMessage(ws: WebSocket, message: ArrayBuffer | string) {
        const check = validateFrame(message);
        if (!check.valid) {
            ws.close(check.code!, check.reason);
            return;
        }

        // Persist frame count in WebSocket attachment so hibernation eviction cannot reset the rate limit and contact rooms isolate counts per connection.
        const attachment = (ws.deserializeAttachment() as { relayedFrames?: number } | null) ?? { relayedFrames: 0 };
        const currentFrames = (attachment.relayedFrames ?? 0) + 1;
        if (currentFrames > DB_CONFIG.MAX_RELAYED_FRAMES) {
            ws.close(1008, "Policy Violation: Maximum session frame limit exceeded");
            return;
        }
        ws.serializeAttachment({ relayedFrames: currentFrames });

        const tags = this.ctx.getTags(ws);
        const myRole = (tags && tags.length > 0 ? tags[0] : "client") as Role; // Retrieve role from socket tags.
        const targetRole: Role = myRole === "client" ? "authenticator" : "client";
        
        const peerSockets = this.ctx.getWebSockets(targetRole).filter(s => s.readyState === 1);

        if (peerSockets.length > 0) {
            for (const peer of peerSockets) {
                try { 
                    peer.send(message); 
                } catch (e) {
                    console.error("Relay fail, buffered locally instead", e);
                    try {
                        this.db.saveMessage(myRole, message as ArrayBuffer);
                    } catch (dbError) {
                        this.handleBufferError(ws, dbError);
                    }
                }
            }
        } else {
            try {
                this.db.saveMessage(myRole, message as ArrayBuffer);
            } catch (dbError) {
                this.handleBufferError(ws, dbError);
            }
        }
    }

    private handleBufferError(ws: WebSocket, error: unknown) {
        const reason = error instanceof Error ? error.message : "Unknown buffer failure";
        if (reason.includes("Buffer overflow")) {
            ws.close(1009, "Offline buffer capacity exceeded");
        } else {
            console.error("[caBLE] Offline buffer storage failure:", error);
            ws.close(1011, "Internal offline buffer failure");
        }
    }

    async webSocketClose(ws: WebSocket, code: number, reason: string, wasClean: boolean) {
        // Process disconnect routing before completing the close handshake so socket tags remain accessible.
        await this.handleDisconnect(ws);

        // Complete the WebSocket closing handshake using a valid status code to prevent hanging TCP connections.
        const safeCode = (code >= 1000 && code <= 4999 && code !== 1005 && code !== 1006) ? code : 1000;
        try {
            ws.close(safeCode, reason || "Connection closed");
        } catch (e) {}
    }

    async webSocketError(ws: WebSocket, error: unknown) {
        await this.handleDisconnect(ws);
    }

    /**
     * Schedule reconnect grace period or immediate teardown without persisting redundant state keys.
     */
    private async handleDisconnect(ws: WebSocket) {
        // Short-circuit if the room is already tombstoned in memory.
        if (this.isTombstonedCache) return;

        const tags = this.ctx.getTags(ws);
        if (!tags || tags.length === 0) return;

        // Ignore late close events from sockets evicted by sealTunnel() after the lifecycle alarm was already cleared.
        const currentAlarm = await this.ctx.storage.getAlarm();
        if (currentAlarm === null) return;

        const myRole = tags[0] as Role; // Safe index of the first tag element.
        
        const activeSameRoleSockets = this.ctx.getWebSockets(myRole).filter(s => s !== ws && s.readyState === 1);
        if (activeSameRoleSockets.length > 0) {
            console.log(`[caBLE] Old socket of role [${myRole}] closed after replacement. Keeping session active.`);
            return;
        }

        const targetRole: Role = myRole === "client" ? "authenticator" : "client";
        const peerSockets = this.ctx.getWebSockets(targetRole).filter(s => s.readyState === 1);
        
        if (peerSockets.length > 0) {
            // Use RECONNECT_GRACE_MS or default to 30s.
            const configuredGrace = Number(this.env.RECONNECT_GRACE_MS ?? "30000");
            const gracePeriodMs = Number.isFinite(configuredGrace) && configuredGrace >= 1000 ? configuredGrace : 30000;
            
            await this.ctx.storage.setAlarm(Date.now() + gracePeriodMs); 
            console.log(`[caBLE] Peer [${myRole}] disconnected. Initiating ${gracePeriodMs / 1000}s reconnection grace period.`);
        } else {
            // Both peers disconnected; schedule teardown in 1 second.
            await this.ctx.storage.setAlarm(Date.now() + 1000);
            console.log(`[caBLE] Both peers disconnected. Scheduling absolute teardown in 1s.`);
        }
    }

    /**
     * Execute tunnel teardown or final storage eviction when lifecycle alarm expires.
     */
    async alarm() {
        // Purge all persistent storage once the tombstone anti-replay window expires so Cloudflare garbage-collects the instance.
        if (this.isTombstonedCache) {
            console.log(`[caBLE] Tombstone TTL expired. Purging all storage to release SQLite allocation.`);
            await this.ctx.storage.deleteAll();
            return;
        }

        console.log(`[caBLE] Lifecycle alarm triggered. Sealing tunnel room.`);
        await this.sealTunnel();
    }

    /**
     * Seal the tunnel room, close sockets, and persist tombstone state if applicable.
     */
    private async sealTunnel() {
        // 1. Close all remaining sockets.
        const survivingSockets = this.ctx.getWebSockets();
        for (const sock of survivingSockets) {
            try { 
                sock.close(1001, "FIDO Connection Lifetime Expired / Timeout"); 
            } catch (e) {}
        }
        
        if (this.isContactCache === null) {
            this.isContactCache = !!(await this.ctx.storage.get(DO_STATE_KEYS.IS_CONTACT));
        }

        // 2. Clear SQL message buffer with error handling.
        try {
            this.db.clearAll();
        } catch (error) {
            console.error("[caBLE] SQLite cleanup failed:", error);
        }

        if (this.isContactCache) {
            // Purge cached client payload from previous transaction while retaining contact room availability for future linked sessions.
            this.clientPayloadCache = null;
            await this.ctx.storage.delete(DO_STATE_KEYS.CLIENT_PAYLOAD);
            await this.ctx.storage.deleteAlarm();
            console.log("[caBLE] Resetting contact session state for reuse.");
        } else {
            // Tombstone symmetric QR-initiated session to prevent replay attacks, then schedule final storage eviction.
            this.isTombstonedCache = true;
            await this.ctx.storage.put(DO_STATE_KEYS.TOMBSTONED, true);
            await this.ctx.storage.setAlarm(Date.now() + DB_CONFIG.TOMBSTONE_TTL_MS);
            console.log("[caBLE] Durable Object instance sealed. Scheduled storage eviction in 3m.");
        }
    }
}