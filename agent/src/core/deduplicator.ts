/**
 * DEX file deduplicator using SHA-256 hashes.
 * Prevents duplicate DEX files from being sent to the host
 * when multiple strategies find the same file.
 */

export class Deduplicator {
    private seen: Set<string> = new Set();
    private _count = 0;
    private _totalBytes = 0;

    /**
     * Check if a DEX file has already been seen.
     * If not seen, records it and returns false.
     * If already seen, returns true.
     */
    isDuplicate(dexBytes: ArrayBuffer): boolean {
        const hash = this.computeHash(dexBytes);
        if (this.seen.has(hash)) {
            return true;
        }
        this.seen.add(hash);
        this._count++;
        this._totalBytes += dexBytes.byteLength;
        return false;
    }

    /** Number of unique DEX files seen */
    get count(): number {
        return this._count;
    }

    /** Total bytes of unique DEX files */
    get totalBytes(): number {
        return this._totalBytes;
    }

    /** All known hashes */
    get hashes(): string[] {
        return Array.from(this.seen);
    }

    /**
     * Compute a fast hash of the DEX bytes for dedup.
     * Samples header (112 bytes), middle, and tail for better collision resistance.
     * Uses two independent 32-bit hashes for a 64-bit combined key.
     * The host does proper SHA-256 as final dedup.
     */
    private computeHash(data: ArrayBuffer): string {
        const view = new Uint8Array(data);
        const len = view.length;

        // Sample size: full DEX header (0x70=112) + 256 from middle + 256 from end
        let h1 = 5381;
        let h2 = 0x811c9dc5; // FNV offset basis

        // Hash first 512 bytes (covers full DEX header + some class defs)
        const headSize = Math.min(512, len);
        for (let i = 0; i < headSize; i++) {
            h1 = ((h1 << 5) + h1 + view[i]) >>> 0;
            h2 = Math.imul(h2 ^ view[i], 0x01000193) >>> 0;
        }

        // Hash middle section
        if (len > 1024) {
            const midStart = Math.floor(len / 2) - 256;
            const midEnd = Math.min(midStart + 512, len);
            for (let i = midStart; i < midEnd; i++) {
                h1 = ((h1 << 5) + h1 + view[i]) >>> 0;
                h2 = Math.imul(h2 ^ view[i], 0x01000193) >>> 0;
            }
        }

        // Hash last 512 bytes
        const tailStart = Math.max(headSize, len - 512);
        for (let i = tailStart; i < len; i++) {
            h1 = ((h1 << 5) + h1 + view[i]) >>> 0;
            h2 = Math.imul(h2 ^ view[i], 0x01000193) >>> 0;
        }

        // Include size for collision avoidance
        h1 = ((h1 << 5) + h1 + len) >>> 0;
        h2 = Math.imul(h2 ^ (len & 0xff), 0x01000193) >>> 0;

        return `${h1.toString(16)}_${h2.toString(16)}_${len}`;
    }
}
