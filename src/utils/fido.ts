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

// Helper function to strictly validate Canonical Base64url encoding
export function validateContactId(identifier: string): boolean {
    if (!/^[A-Za-z0-9_-]{1,256}$/.test(identifier)) return false;
    try {
        // Standard Base64url decoding
        const base64 = identifier.replace(/-/g, "+").replace(/_/g, "/");
        const padding = "=".repeat((4 - (base64.length % 4)) % 4);
        const decoded = atob(base64 + padding);
        if (decoded.length === 0) return false;

        // Re-encode to unpadded Canonical Base64url and strictly compare to the original string
        const reEncoded = btoa(decoded)
            .replace(/\+/g, "-")
            .replace(/\//g, "_")
            .replace(/=+$/, "");

        return reEncoded === identifier;
    } catch {
        return false;
    }
}

/**
 * Strictly validates identifiers extracted from the URL to defend against injection attacks.
 * @param identifier The extracted ID string.
 * @param isContact Whether the request is in persistent contact mode.
 */
export function validateIdentifier(identifier: string, isContact: boolean): boolean {
    if (isContact) {
        // Strictly validate Contact IDs against Canonical Base64url encoding rules
        return validateContactId(identifier);
    }
    // Tunnel IDs are 128-bit identifiers. In the WebSocket URL they are represented as 32 lowercase hexadecimal characters, per CTAP 2.3 §11.5.1.1.1.
    return /^[a-f0-9]{32}$/.test(identifier);
}