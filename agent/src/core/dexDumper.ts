import { Deduplicator } from './deduplicator.js';
import { StrategyName } from '../config/constants.js';
import { sendDexFound } from '../utils/messageSender.js';
import { validateDexHeader, readDexBytes } from '../utils/memoryUtils.js';
import { logger } from '../utils/logger.js';

/**
 * Core DEX dumping logic shared across all strategies.
 * Handles validation, deduplication, and sending to host.
 */
export class DexDumper {
    private dedup: Deduplicator;

    constructor(dedup: Deduplicator) {
        this.dedup = dedup;
    }

    /**
     * Attempt to dump a DEX file from the given memory address.
     * Returns true if a new DEX file was found and sent.
     */
    dumpFromAddress(
        address: NativePointer,
        strategy: StrategyName,
        extra?: { loader?: string; path?: string; location?: string }
    ): boolean {
        const fileSize = validateDexHeader(address);
        if (fileSize === 0) return false;

        const dexBytes = readDexBytes(address, fileSize);
        if (!dexBytes) {
            logger.warn('DUMP', `Failed to read ${fileSize} bytes at ${address}`);
            return false;
        }

        if (this.dedup.isDuplicate(dexBytes)) {
            logger.debug('DUMP', `Duplicate DEX at ${address} (${fileSize} bytes)`);
            return false;
        }

        logger.info('DUMP', `New DEX found: ${fileSize} bytes at ${address} [${strategy}]`);
        sendDexFound(strategy, dexBytes, {
            address: address.toString(),
            ...extra,
        });

        return true;
    }

    /**
     * Dump DEX bytes that are already read into memory.
     * Used when we already have the bytes (e.g., from a ByteBuffer).
     */
    dumpBytes(
        dexBytes: ArrayBuffer,
        strategy: StrategyName,
        extra?: { loader?: string; path?: string; location?: string }
    ): boolean {
        if (this.dedup.isDuplicate(dexBytes)) {
            return false;
        }

        logger.info('DUMP', `New DEX found: ${dexBytes.byteLength} bytes [${strategy}]`);
        sendDexFound(strategy, dexBytes, extra);

        return true;
    }

    /** Number of unique DEX files found so far */
    get uniqueCount(): number {
        return this.dedup.count;
    }

    /** Total bytes of unique DEX files */
    get totalBytes(): number {
        return this.dedup.totalBytes;
    }
}
