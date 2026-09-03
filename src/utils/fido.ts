// src/utils/fido.ts
import { Role } from "../types";

/**
 * Infers the connection role based on the FIDO caBLE specifications.
 * @param path The incoming request URL pathname.
 * @param hasClientPayload Indicates if the 'X-caBLE-Client-Payload' header is provided.
 */
export function inferRole(path: string, hasClientPayload: boolean): Role {
    const isConnect = path.startsWith("/cable/connect/");
    // The Client side is the device that displays the QR code (/connect) or initiates the call with a ClientPayload.
    if (isConnect || hasClientPayload) {
        return "client";
    }
    // The Authenticator side is the device that scans the QR code or gets woken up for verification (/custom or /contact).
    return "authenticator";
}

/**
 * Generates a cryptographically secure 3-byte (6-character Hex) Routing ID.
 */
export function generateRoutingId(): string {
    const bytes = new Uint8Array(3);
    crypto.getRandomValues(bytes);
    return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Strictly validates identifiers extracted from the URL to defend against injection attacks.
 * @param identifier The extracted ID string.
 * @param isContact Whether the request is in persistent contact mode.
 */
export function validateIdentifier(identifier: string, isContact: boolean): boolean {
    if (isContact) {
        // Contact IDs are typically Base64Url encoded strings.
        return /^[A-Za-z0-9_-]{1,256}$/.test(identifier);
    }
    // Updated: Following CTAP 2.3 spec, ephemeral tunnel IDs must be a lowercase 32-character Hex string.
    return /^[a-f0-9]{32}$/.test(identifier);
}