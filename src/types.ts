// src/types.ts

/**
 * Cloudflare Workers environment bindings interface.
 * These fields must perfectly match the bindings configured in wrangler.toml.
 */
export interface Env {
    // Namespace binding for the TunnelRoom Durable Object class
    TUNNEL_ROOM: DurableObjectNamespace;
}

/**
 * Standard role definitions for both ends of the FIDO caBLE tunnel.
 * - authenticator: The credential-providing side (e.g., a smartphone), responsible for scanning or receiving contact requests.
 * - client: The relying side initiating the authentication (e.g., a PC browser), responsible for displaying QR codes or firing requests.
 */
export type Role = "client" | "authenticator";

/**
 * Core state keys utilized inside the Durable Object.
 * Used for managing the tunnel lifecycle within SQLite/KV storage.
 */
export const DO_STATE_KEYS = {
    IS_CONTACT: "isContact",
    HAS_PAIRED: "hasPaired",
    TOMBSTONED: "tombstoned"
} as const;

/**
 * Custom extension on the Error object.
 * Used in conjunction with the gateway's smart retry and circuit breaker mechanisms.
 */
export interface DOError extends Error {
    retryable?: boolean;
    overloaded?: boolean;
}