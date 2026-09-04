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
     * Global Gateway Fetch Interceptor
     * Maintains absolute statelessness, focusing entirely on protocol validation, security enforcement, and DO routing.
     */
    async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
        // 1. Short-circuit evaluate CORS preflight requests
        if (request.method === "OPTIONS") {
            return createOptionsResponse();
        }

        // 2. HTTP Method constraints: WebSocket handshakes must use GET
        if (request.method !== "GET") {
            return createError("Method Not Allowed", 405);
        }

        // 3. Strict protocol compliance verification
        const upgradeHeader = request.headers.get("Upgrade") || "";
        // Compatible with multi-valued upgrade headers (e.g., "keep-alive, Upgrade")
        const isWebSocketUpgrade = upgradeHeader.toLowerCase().split(",").map(s => s.trim()).includes("websocket");
        if (!isWebSocketUpgrade) {
            return createError("Expected Upgrade: websocket", 426);
        }

        const protocols = request.headers.get("Sec-WebSocket-Protocol") || "";
        // Parse comma-separated protocols robustly
        const hasFidoCable = protocols.split(",").map(p => p.trim()).includes("fido.cable");
        if (!hasFidoCable) {
            return createError("Forbidden: Invalid WebSocket Protocol", 403);
        }

        // 4. Routing & endpoint evaluation
        const url = new URL(request.url);
        const path = url.pathname;
        
        // Exclusively support '/cable/new/' as the registration/creation endpoint (abandoned /cable/custom/)
        const isNew = path.startsWith("/cable/new/");
        const isConnect = path.startsWith("/cable/connect/");
        const isContact = path.startsWith("/cable/contact/"); 

        if (!isNew && !isConnect && !isContact) {
            return createError("Not Found: Invalid FIDO endpoint", 404);
        }

        // Protocol validation: Require X-caBLE-Client-Payload for state-assisted transactions (CTAP 2.3 11.5.2)
        const clientPayload = request.headers.get("X-caBLE-Client-Payload");
        if (isContact && clientPayload === null) {
            return createError("Bad Request: Missing X-caBLE-Client-Payload header for state-assisted transaction", 400);
        }

        // Implementation-defined security limit: Accept at most 64 decoded bytes (128 hex characters)
        if (clientPayload !== null && !/^(?:[a-f0-9]{2}){1,64}$/i.test(clientPayload)) {
            return createError("Bad Request: Invalid Client Payload encoding", 400);
        }

        const parts = path.split("/").filter(Boolean);
        if (parts.length < 3) {
            return createError("Bad Request: Missing parameters", 400);
        }

        // Extract identifier strings (Tunnel ID or Contact ID)
        let identifier: string;
        if (isConnect) {
            if (parts.length !== 4) return createError("Bad Request: Malformed connect URL", 400);
            
            // Security Enforcement: Pursuant to CTAP 2.3 spec, enforce 24-bit (6-char) lowercase Hex formatting on Routing IDs
            const routingId = parts[2];
            if (!/^[a-f0-9]{6}$/.test(routingId)) {
                return createError("Bad Request: Invalid Routing ID format", 400);
            }
            
            identifier = parts[3];
        } else {
            identifier = parts[parts.length - 1];
        }

        // 5. Structural identifier checks (defends against path traversal and malicious script injections)
        if (!validateIdentifier(identifier, isContact)) {
            return createError("Bad Request: Invalid Identifier format", 400);
        }

        // 6. Routing Strategy: Generate a unique namespace key to map out the corresponding DO instances
        const namespaceKey = isContact ? `contact:${identifier}` : `tunnel:${identifier}`;
        const doId = env.TUNNEL_ROOM.idFromName(namespaceKey);

        // 7. Intelligent Retry & Request Forwarding
        try {
            return await withExponentialBackoff(() => {
                // Cloudflare Durable Objects error handling:
                // Acquire a new stub for each attempt to avoid broken stub state issues.
                const stub = env.TUNNEL_ROOM.get(doId);
                return stub.fetch(request);
            });
        } catch (error) {
            console.error(`Gateway failed to forward request to DO [${namespaceKey}]:`, error);
            
            // Mask underlying stack traces to avoid leaking infrastructural details
            return createError("Service Unavailable: Tunnel creation failed", 503);
        }
    },
};
