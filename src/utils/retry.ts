// src/utils/retry.ts
import { DOError } from "../types";

const MAX_RETRIES = 2;
const INITIAL_BACKOFF_MS = 20;

/**
 * Asynchronous operation wrapper equipped with an Exponential Backoff algorithm.
 * Specifically designed for the Cloudflare Durable Objects infrastructure.
 * @param operation Asynchronous function wrapping the DO call.
 */
export async function withExponentialBackoff<T>(
    operation: () => Promise<T>
): Promise<T> {
    let retries = 0;
    
    while (true) {
        try {
            return await operation();
        } catch (error) {
            const doError = error as DOError;
            
            // Rule 1: If the DO explicitly flags itself as overloaded, never retry to prevent a cascading failure.
            if (doError.overloaded) {
                console.error("Durable Object overloaded. Circuit broken.");
                throw doError;
            }
            
            // Rule 2: If the system explicitly marks the error as non-retryable, or retries are exhausted, abort.
            if (doError.retryable === false || retries >= MAX_RETRIES) {
                throw doError;
            }

            retries++;
            
            // Exponential Backoff: 20ms -> 40ms
            const backoff = INITIAL_BACKOFF_MS * Math.pow(2, retries - 1);
            // Add jitter (0~50ms) to randomize retry traffic and prevent the thundering herd problem.
            const jitter = Math.random() * 50;
            
            await new Promise(resolve => setTimeout(resolve, backoff + jitter));
        }
    }
}