// src/db/bufferStore.ts
import { DB_CONFIG } from "../types";

export class BufferStore {
    /**
     * Track whether the buffer may contain unconsumed messages to bypass unnecessary SQLite queries on empty rooms.
     * Default to true so instances waking from hibernation always check persistent storage safely.
     */
    private mayHaveMessages: boolean = true;

    /**
     * Data Access Object (DAO) for Durable Object SQLite engine
     * @param sql Cloudflare Durable Object SQL interface (this.ctx.storage.sql)
     */
    constructor(private sql: any) {}

    /**
     * Enforces that the SQLite engine is available, failing fast if not.
     */
    private requireSql(): any {
        if (!this.sql) {
            throw new Error("[BufferStore] SQLite engine is not available. Please verify your wrangler.toml or DO namespace migrations.");
        }
        return this.sql;
    }

    /**
     * Mark buffer as empty when initializing a fresh room with zero active peers to skip redundant SQL reads.
     */
    public markEmpty(): void {
        this.mayHaveMessages = false;
    }

    /**
     * Initializes the SQLite schema. Called inside blockConcurrencyWhile to prevent concurrent requests.
     */
    public initSchema() {
        const sql = this.requireSql();
        sql.exec(`
            CREATE TABLE IF NOT EXISTS msg_buffer (
                id INTEGER PRIMARY KEY, 
                sender_role TEXT, 
                data BLOB
            )
        `);
    }

    /**
     * Safely buffers an offline peer message to SQLite.
     * Enforces strict buffer-overflow caps in a single atomic SQL statement to prevent DoS attacks and reduce query overhead.
     * @param senderRole The role of the peer emitting the message ("client" | "authenticator")
     * @param data Binary payload to buffer
     */
    public saveMessage(senderRole: string, data: ArrayBuffer): void {
        const sql = this.requireSql();
        try {
            const binaryData = data instanceof ArrayBuffer ? new Uint8Array(data) : data;
            const cursor = sql.exec(
                `INSERT INTO msg_buffer (sender_role, data) SELECT ?, ? WHERE (SELECT count(*) FROM msg_buffer) < ?`,
                senderRole,
                binaryData,
                DB_CONFIG.MAX_CAPACITY
            );

            if (cursor.rowsWritten > 0) {
                this.mayHaveMessages = true;
            } else {
                throw new Error(`Buffer overflow: Exceeded maximum capacity of ${DB_CONFIG.MAX_CAPACITY} frames.`);
            }
        } catch (error) {
            console.error("[BufferStore] Fatal exception during saveMessage database call:", error);
            throw error;
        }
    }

    /**
     * Atomically retrieves and deletes buffered messages targeted at the receiver role.
     * Orders strictly by primary key rowid to preserve CTAP 2.3 AEAD nonce sequence integrity across sub-millisecond bursts.
     * @param receiverRole The role of the peer currently online ("client" | "authenticator")
     */
    public consumeMessages(receiverRole: string): ArrayBuffer[] {
        // Short-circuit database query when no offline messages have been buffered in this room.
        if (!this.mayHaveMessages) {
            return [];
        }

        const sql = this.requireSql();
        try {
            // Order by primary key 'id' instead of timestamp to leverage B-tree index and prevent same-millisecond frame reordering.
            const cursor = sql.exec(
                `SELECT data FROM msg_buffer WHERE sender_role != ? ORDER BY id ASC`,
                receiverRole
            );
            
            const messages: ArrayBuffer[] = [];
            
            for (const row of cursor) {
                let buffer: ArrayBuffer;
                if (row.data instanceof Uint8Array) {
                    buffer = row.data.buffer.slice(row.data.byteOffset, row.data.byteOffset + row.data.byteLength);
                } else {
                    buffer = row.data as ArrayBuffer;
                }
                messages.push(buffer);
            }
            
            // Purge consumed peer messages via parameterized query to guarantee exactly-once delivery.
            if (messages.length > 0) {
                sql.exec(
                    `DELETE FROM msg_buffer WHERE sender_role != ?`,
                    receiverRole
                );
            } else {
                this.mayHaveMessages = false;
            }
            
            return messages;
        } catch (error) {
            console.error("[BufferStore] Fatal exception during consumeMessages:", error);
            throw error;
        }
    }

    /**
     * Completely wipes the SQLite message buffer table on room termination or garbage collection.
     */
    public clearAll(): void {
        // Execute unconditional DELETE on tunnel teardown so hibernated instances waking on alarm never leak buffered frames.
        const sql = this.requireSql();
        sql.exec(`DELETE FROM msg_buffer`);
        this.mayHaveMessages = false;
    }
}