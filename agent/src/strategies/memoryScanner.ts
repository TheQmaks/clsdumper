import { DexDumper } from '../core/dexDumper.js';
import { STRATEGY_NAMES, DEX_MAGIC_BYTES, CDEX_MAGIC_BYTES, SCAN_BATCH_SIZE, SCAN_DELAY_MS } from '../config/constants.js';
import { validateDexHeader, readDexBytes } from '../utils/memoryUtils.js';
import { sendScanProgress, sendStrategyStatus } from '../utils/messageSender.js';
import { logger } from '../utils/logger.js';

const TAG = STRATEGY_NAMES.MEMORY_SCAN;

// Max region size to scan in one go. Memory.scanSync blocks the entire agent
// thread, so even 20 MB regions can freeze heavy apps like Facebook.
// DEX files found by other strategies cover large ones; memory scan picks up
// small dynamic DEX that others miss.
const MAX_SCAN_REGION_SIZE = 8 * 1024 * 1024;

// File extensions that are already handled by other strategies or cannot contain DEX
const SKIP_EXTENSIONS = ['.so', '.oat', '.vdex', '.art', '.odex', '.apk', '.jar', '.ttf', '.otf', '.png', '.jpg', '.webp'];

function shouldSkipRange(range: RangeDetails): boolean {
    if (range.size < 0x70) return true;

    if (range.file && range.file.path) {
        const path = range.file.path;
        if (path.startsWith('/dev/') || path.startsWith('/sys/')) return true;

        // Skip known non-DEX file mappings
        const lower = path.toLowerCase();
        for (const ext of SKIP_EXTENSIONS) {
            if (lower.endsWith(ext)) return true;
        }
    }

    // Skip very large anonymous regions (heap, mmap'd data)
    if (range.size > MAX_SCAN_REGION_SIZE) {
        logger.debug(TAG, `Skipping large region ${range.base} (${(range.size / 1024 / 1024).toFixed(1)} MB)`);
        return true;
    }

    return false;
}

/**
 * Strategy 3: Memory DEX Scan
 *
 * Scans all readable memory regions for DEX magic bytes ("dex\n").
 * Most universal strategy — works on any Android version.
 */
export function runMemoryScanner(dumper: DexDumper, deepScan: boolean): void {
    logger.strategy(TAG, 'Starting memory scan...');
    sendStrategyStatus(TAG, 'active', 'Scanning memory regions for DEX files');

    try {
        const ranges = Process.enumerateRanges('r--');
        const total = ranges.length;
        let scanned = 0;
        let skipped = 0;
        let found = 0;

        logger.info(TAG, `Scanning ${total} memory regions`);

        for (let i = 0; i < ranges.length; i += SCAN_BATCH_SIZE) {
            const batch = ranges.slice(i, i + SCAN_BATCH_SIZE);

            for (const range of batch) {
                scanned++;

                if (shouldSkipRange(range)) {
                    skipped++;
                    continue;
                }

                try {
                    // Scan for standard DEX magic (use scanSync so found count is accurate)
                    const matches = Memory.scanSync(range.base, range.size, DEX_MAGIC_BYTES);
                    for (const match of matches) {
                        const fileSize = validateDexHeader(match.address);
                        if (fileSize === 0) continue;

                        // Make sure the DEX fits in this range
                        const rangeEnd = range.base.add(range.size);
                        const dexEnd = match.address.add(fileSize);
                        if (dexEnd.compare(rangeEnd) > 0) continue;

                        if (dumper.dumpFromAddress(match.address, TAG, {
                            path: range.file?.path,
                        })) {
                            found++;
                        }
                    }

                    // Deep scan: also look for CDEX ("cdex") magic
                    if (deepScan) {
                        const cdexMatches = Memory.scanSync(range.base, range.size, CDEX_MAGIC_BYTES);
                        for (const match of cdexMatches) {
                            logger.debug(TAG, `Found CDEX at ${match.address}`);
                            try {
                                const cdexSize = match.address.add(0x20).readU32();
                                const remaining = range.base.add(range.size).sub(match.address).toUInt32();
                                if (cdexSize > 0x70 && cdexSize <= remaining) {
                                    const bytes = readDexBytes(match.address, cdexSize);
                                    if (bytes) {
                                        if (dumper.dumpBytes(bytes, TAG, {
                                            path: range.file?.path,
                                        })) {
                                            found++;
                                        }
                                    }
                                }
                            } catch {
                                // Skip
                            }
                        }
                    }
                } catch {
                    // Skip inaccessible range
                }
            }

            // Report progress
            sendScanProgress(scanned, total, found);

            // Yield to avoid ANR
            if (i + SCAN_BATCH_SIZE < ranges.length) {
                Thread.sleep(SCAN_DELAY_MS / 1000);
            }
        }

        logger.strategy(TAG, `Scan complete: ${found} DEX files found (${scanned} regions scanned, ${skipped} skipped)`);
        sendStrategyStatus(TAG, 'complete', `Found ${found} DEX files`);
    } catch (e) {
        logger.strategyError(TAG, `Memory scan failed: ${e}`);
        sendStrategyStatus(TAG, 'error', `${e}`);
    }
}
