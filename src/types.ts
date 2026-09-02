// src/types.ts

/**
 * Cloudflare Workers environment bindings interface.
 * These fields must perfectly match the bindings configured in wrangler.toml.
 */
export interface Env {
    // Namespace binding for the TunnelRoom Durable Object class
    TUNNEL_ROOM: DurableObjectNamespace;
    // Global service token to protect internal control endpoints
    CONTACT_INTERNAL_TOKEN: string;
}

/**
 * Standard role definitions for both ends of the FIDO caBLE tunnel.
 * - authenticator: The credential-providing side (e.g., a smartphone), responsible for scanning or receiving contact requests.
 * - client: The relying side initiating the authentication (e.g., a PC browser), responsible for displaying QR codes or firing requests.
 */
export type Role = "client" | "authenticator";

// Data channel roles mapped for the new architecture
export type DataRole = Role;

// Expanded socket roles including the contact control plane
export type SocketRole = DataRole | "contact-control";

// Persistent socket state attachment used during hibernation wakeups
export interface SocketAttachment {
    role: SocketRole;
    requestId?: string;
    superseded?: boolean;
}

// JSON payload structure for control plane notifications
export interface ContactNotification {
    type: "contact";
    requestId: string;
    acceptToken: string;
    clientPayload: string;
}

/**
 * Core state keys utilized inside the Durable Object.
 * Used for managing the tunnel lifecycle within SQLite/KV storage.
 */
export const DO_STATE_KEYS = {
    IS_CONTACT: "isContact",
    HAS_PAIRED: "hasPaired",
    TOMBSTONED: "tombstoned",
    // Capability credential hash for Contact DO ownership verification
    CAPABILITY_HASH: "capabilityHash",
    // Persistent state indicating the contact ID has been permanently unlinked
    CONTACT_REVOKED: "contactRevoked"
} as const;

/**
 * Custom extension on the Error object.
 * Used in conjunction with the gateway's smart retry and circuit breaker mechanisms.
 */
export interface DOError extends Error {
    retryable?: boolean;
    overloaded?: boolean;
}