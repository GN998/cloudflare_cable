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
        if (upgradeHeader.toLowerCase() !== "websocket") {
            return createError("Expected Upgrade: websocket", 426);
        }

        const protocols = request.headers.get("Sec-WebSocket-Protocol") || "";
        if (!protocols.includes("fido.cable")) {
            return createError("Forbidden: Invalid WebSocket Protocol", 403);
        }

        // Protocol validation: Require X-caBLE-Client-Payload to be hex-encoded,
        // as specified for state-assisted transactions in CTAP 2.3 11.5.2.
        // Implementation-defined security limit: Accept at most 64 decoded bytes
        // (128 hexadecimal characters) to reduce resource-exhaustion risk.
        const clientPayload = request.headers.get("X-caBLE-Client-Payload");
        if (clientPayload !== null && !/^(?:[a-f0-9]{2}){1,64}$/i.test(clientPayload)) {
            return createError("Bad Request: Invalid Client Payload encoding", 400);
        }

        // 4. Routing & endpoint evaluation
        const url = new URL(request.url);
        const path = url.pathname;
        
        const isCustom = path.startsWith("/cable/custom/");
        const isConnect = path.startsWith("/cable/connect/");
        const isContact = path.startsWith("/cable/contact/"); 

        if (!isCustom && !isConnect && !isContact) {
            return createError("Not Found: Invalid FIDO endpoint", 404);
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
            // Wrap the DO invocation with the exponential backoff utility.
            // Since GET requests contain no bodies, retrying avoids any "body already used" runtime TypeErrors.
            return await withExponentialBackoff(() => {
                // Cloudflare Durable Objects error handling:
                // Acquire a new stub for each attempt because certain exceptions may leave
                // the previous stub in a broken state and cause subsequent calls to fail.
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