// src/types.ts

/**
 * Define participant roles for FIDO CTAP 2.3 Hybrid WebSocket tunnels.
 *
 * Direct role assignment according to protocol initiator semantics:
 * - `client`: Initiates authentication flow (e.g., desktop browser displaying QR code or dispatching caBLE client payload).
 * - `authenticator`: Holds passkey credentials and performs verification (e.g., mobile device scanning QR code or connecting via state-assisted proxy).
 */
export type Role = "client" | "authenticator";

/**
 * Declare environment bindings injected by the Cloudflare Workers runtime.
 *
 * Align strictly with `wrangler.toml` bindings to guarantee compile-time type safety across Worker and Durable Object execution contexts.
 */
export interface Env {
    /**
     * Provide namespace access for routing requests to Durable Object instances.
     */
    TUNNEL_ROOM: DurableObjectNamespace;

    /**
     * Override default reconnect grace period (in milliseconds) before tearing down disconnected sessions.
     */
    RECONNECT_GRACE_MS?: string;
}

/**
 * Define state storage keys for Durable Object persistent storage.
 *
 * Omit transient lifecycle keys to eliminate redundant SQLite row reads and writes across WebSocket sessions.
 */
export const DO_STATE_KEYS = {
    /**
     * Mark session as a state-assisted contact transaction (CTAP 2.3 Section 11.5.2) to prevent permanent tombstoning upon teardown.
     */
    IS_CONTACT: "state:is_contact",

    /**
     * Persist hex-encoded X-caBLE-Client-Payload across hibernation so the mobile authenticator can derive EID and PSK keys upon joining.
     */
    CLIENT_PAYLOAD: "state:client_payload",

    /**
     * Seal QR-initiated sessions permanently upon completion to prevent replay attacks.
     */
    TOMBSTONED: "state:tombstoned"
} as const;

/**
 * Enforce storage limits and schema configurations for offline message buffering.
 */
export const DB_CONFIG = {
    /**
     * Specify target table for storing offline WebSocket message frames.
     */
    TABLE_NAME: "msg_buffer",

    /**
     * Cap offline message queue per tunnel to prevent resource exhaustion and DoS vectors.
     */
    MAX_CAPACITY: 30,

    /**
     * Cap total relayed frames per session to prevent unauthorized data tunneling abuse.
     */
    MAX_RELAYED_FRAMES: 200,

    /**
     * Enforce absolute session lifetime (in milliseconds) to accommodate user verification and the 2-minute post-shutdown window required by CTAP 2.3.
     */
    SESSION_TTL_MS: 240000,
} as const;

/**
 * Represent proxy and gateway error attributes during Durable Object forwarding.
 *
 * Enable exponential backoff retries while breaking circuits on overloaded instances.
 */
export interface DOError extends Error {
    /**
     * Indicate whether gateway should attempt exponential backoff retries.
     */
    retryable?: boolean;

    /**
     * Signal Durable Object overload to trigger immediate circuit breaking.
     */
    overloaded?: boolean;
}