// src/index.ts
import { Env } from "./types";
import { TunnelRoom } from "./tunnelRoom";
import { validateIdentifier } from "./utils/fido";
import { createError, createOptionsResponse } from "./utils/response";
import { withExponentialBackoff } from "./utils/retry";

// Export the Durable Object class so the Cloudflare Workers runtime can discover, bind, and instantiate it.
export { TunnelRoom };

export default {
    /**
     * Gateway Fetch Interceptor
     * Stateless router focused on protocol validation, security checks, and Durable Objects routing.
     */
    async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
        // 1. Fast path for CORS OPTIONS preflight request
        if (request.method === "OPTIONS") {
            return createOptionsResponse();
        }

        // 2. HTTP method constraint: WebSocket upgrades must use GET requests
        if (request.method !== "GET") {
            return createError("Method Not Allowed", 405);
        }

        // 3. Strict WebSocket upgrade headers validation
        const upgradeHeader = request.headers.get("Upgrade") || "";
        const isWebSocketUpgrade = upgradeHeader.toLowerCase().split(",").map(s => s.trim()).includes("websocket");
        if (!isWebSocketUpgrade) {
            return createError("Expected Upgrade: websocket", 426);
        }

        const protocols = request.headers.get("Sec-WebSocket-Protocol") || "";
        const hasFidoCable = protocols.split(",").map(p => p.trim()).includes("fido.cable");
        if (!hasFidoCable) {
            return createError("Forbidden: Invalid WebSocket Protocol", 403);
        }

        // 4. Endpoint and route analysis
        const url = new URL(request.url);
        const path = url.pathname;
        
        // Enforce strict prefix matching because CTAP 2.3 requires pre-derived identifiers in all tunnel paths.
        const isNew = path.startsWith("/cable/new/");
        const isConnect = path.startsWith("/cable/connect/");
        const isContact = path.startsWith("/cable/contact/"); 

        if (!isNew && !isConnect && !isContact) {
            return createError("Not Found: Invalid FIDO endpoint", 404);
        }

        // Return 410 Gone on state-assisted transactions per CTAP 2.3 Section 11.5.2 so clients evict stale linking data and fall back to QR-initiated flows.
        if (isContact) {
            return createError("Gone: State-assisted transactions are not supported", 410);
        }

        const parts = path.split("/").filter(Boolean);

        // Extract identifier (Tunnel ID)
        let identifier: string;

        if (isConnect) {
            // Require exactly 4 segments (/cable/connect/<routing_id>/<tunnel_id>) per CTAP 2.3 Section 11.5.1.1.1.
            if (parts.length !== 4) {
                return createError("Bad Request: Malformed connect URL", 400);
            }

            // Enforce 6-character lowercase hex format for routing ID.
            const routingId = parts[2];
            if (!/^[a-f0-9]{6}$/.test(routingId)) {
                return createError("Bad Request: Invalid Routing ID format", 400);
            }
            
            identifier = parts[3];
        } else {
            // Enforce exactly 3 parts for "/cable/new/<tunnel_id>" pursuant to CTAP 2.3 strict path formatting constraints.
            if (parts.length !== 3) {
                return createError("Bad Request: Malformed URL path", 400);
            }
            identifier = parts[2];
        }

        // 5. Strict identifier format validation to defend against path traversal or injection.
        if (!validateIdentifier(identifier, isContact)) {
            return createError("Bad Request: Invalid Identifier format", 400);
        }

        // 6. Routing: Map request to a unique Durable Object instance.
        const namespaceKey = `tunnel:${identifier}`;
        const doId = env.TUNNEL_ROOM.idFromName(namespaceKey);

        // 7. Forward request with exponential backoff retries.
        try {
            // Return the Durable Object response directly to preserve WebSocket hibernation context.
            return await withExponentialBackoff(async () => {
                // Fetch a fresh stub on retry to prevent stale connection errors.
                const stub = env.TUNNEL_ROOM.get(doId);
                return await stub.fetch(request);
            });
        } catch (error) {
            console.error(`Gateway failed to forward request to DO [${namespaceKey}]:`, error);
            // Sanitize stack traces to avoid leaking internal system details.
            return createError("Service Unavailable: Tunnel creation failed", 503);
        }
    },
};