// src/utils/fido.ts
import { Role } from "../types";

/**
 * Assign participant role deterministically from the FIDO CTAP 2.3 endpoint path.
 *
 * Map `/cable/new/` to the mobile authenticator registering the tunnel and `/cable/connect/`
 * to the client platform joining after BLE advertisement decryption, avoiding fragile browser
 * `Origin` header heuristics that fail on native OS WebAuthn clients.
 * @param path Incoming HTTP/WebSocket URL pathname
 * @param hasClientPayload Indicates if 'X-caBLE-Client-Payload' header exists
 */
export function inferRole(
    path: string, 
    hasClientPayload: boolean
): Role {
    const isContact = path.startsWith("/cable/contact/");
    const isConnect = path.startsWith("/cable/connect/");
    const isNew = path.startsWith("/cable/new/");
    
    // 0. New Tunnel Creation Routing
    // Assign "authenticator" because the mobile CMHD scans the QR code, selects the tunnel domain, and allocates the tunnel on /cable/new/ before broadcasting the routing ID over BLE.
    if (isNew) {
        return "authenticator";
    }

    // 1. State-assisted Transactions (Link Routing)
    if (isContact) {
        // Assign "client" when X-caBLE-Client-Payload is present per CTAP 2.3 Section 11.5.2, mapping payload-free connections to the authenticator's transport channel.
        return hasClientPayload ? "client" : "authenticator";
    }

    // 2. QR-initiated Client Connection Routing
    // Assign "client" because the client platform always connects via /cable/connect/<routing_id>/<tunnel_id> after decrypting the BLE proximity advertisement.
    if (isConnect) {
        return "client";
    }

    // Default fallback
    return hasClientPayload ? "client" : "authenticator";
}

/**
 * Generates a cryptographically secure 3-byte (6-character Hex) Routing ID roll over.
 */
export function generateRoutingId(): string {
    const bytes = new Uint8Array(3);
    crypto.getRandomValues(bytes);
    return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Strictly validates identifiers extracted from the URL to defend against path traversal or injection.
 * @param identifier The extracted ID string
 * @param isContact Whether the path is a contact-assisted transaction
 */
export function validateIdentifier(identifier: string, isContact: boolean): boolean {
    if (isContact) {
        // Contact IDs are Base64Url encoded strings. Tolerates trailing '='.
        return /^[A-Za-z0-9_-]{1,512}=*$/.test(identifier);
    }
    // Pursuant to CTAP 2.3 spec, ephemeral tunnel IDs must be a lowercase 32-character Hex string.
    return /^[a-f0-9]{32}$/.test(identifier);
}

/**
 * Robust WebSocket Frame Validation
 * Prevents text frame injection, empty frames, and DoS buffer overflow attacks.
 * @param message The raw message frame payload
 */
export function validateFrame(message: ArrayBuffer | string): { valid: boolean; code?: number; reason?: string } {
    // Defensive Rule 1: Text frames are forbidden under CTAP 2.3 Section 11.5.1.1.1
    if (typeof message === "string") {
        return { valid: false, code: 1003, reason: "Unsupported Data: FIDO caBLE requires binary frames" };
    }

    // Defensive Rule 2: Empty application messages are protocol errors under CTAP 2.3 Section 11.5.1.2
    if (message.byteLength === 0) {
        return { valid: false, code: 1002, reason: "Protocol Error: Empty message is not allowed in caBLE" };
    }

    // Defensive Rule 3: Enforce a limit of 1 MiB (plus a tolerance buffer) as defined in CTAP 2.3 Section 11.5.1.1.2
    if (message.byteLength > 1049600) {
        return { valid: false, code: 1009, reason: "Message Too Big: Exceeds 1,049,600 byte ciphertext limit" };
    }

    return { valid: true };
}