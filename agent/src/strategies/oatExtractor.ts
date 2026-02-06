import { DexDumper } from '../core/dexDumper.js';
import { STRATEGY_NAMES, DEX_MAGIC_BYTES } from '../config/constants.js';
import { validateDexHeader } from '../utils/memoryUtils.js';
import { sendStrategyStatus } from '../utils/messageSender.js';
import { logger } from '../utils/logger.js';

const TAG = STRATEGY_NAMES.OAT_EXTRACT;

// VDEX magic: "vdex" bytes = 76 64 65 78, LE uint32 = 0x78656476
const VDEX_MAGIC = 0x78656476;

/**
 * Strategy 7: OAT/VDEX Extraction
 *
 * Extracts DEX files from pre-compiled OAT/VDEX containers.
 * Scans /proc/self/maps for mapped .vdex/.oat files and parses them
 * to extract embedded DEX sections.
 *
 * Works without any hooks — purely memory reading.
 */
export function runOatExtractor(dumper: DexDumper): void {
    logger.strategy(TAG, 'Starting OAT/VDEX extraction...');
    sendStrategyStatus(TAG, 'active', 'Extracting DEX from OAT/VDEX files');

    let found = 0;

    try {
        // Collect all ranges for each mapped file (handles multi-range mappings)
        const fileRegions = collectFileRegions();
        logger.info(TAG, `Found ${fileRegions.size} VDEX/OAT files in memory`);

        for (const [key, region] of fileRegions) {
            const path = key.split('@')[0];
            found += scanRegionForDex(dumper, region.base, region.totalSize, path);
        }

        // Also scan anonymous regions for VDEX magic we might have missed
        // Limit to 32 MB per region to avoid blocking on huge heap segments
        const MAX_ANON_SCAN = 32 * 1024 * 1024;
        const ranges = Process.enumerateRanges('r--');
        for (const range of ranges) {
            if (range.size < 0x100) continue;
            if (range.file?.path) continue; // Already handled above
            if (range.size > MAX_ANON_SCAN) continue; // Skip huge anonymous regions

            try {
                const magic = range.base.readU32();
                if (magic === VDEX_MAGIC) {
                    logger.debug(TAG, `Found anonymous VDEX at ${range.base} (${(range.size / 1024 / 1024).toFixed(1)} MB)`);
                    found += scanRegionForDex(dumper, range.base, range.size);
                }
            } catch {
                continue;
            }
        }

        logger.strategy(TAG, `OAT/VDEX extraction complete: ${found} DEX files`);
        sendStrategyStatus(TAG, 'complete', `Found ${found} DEX files`);
    } catch (e) {
        logger.strategyError(TAG, `OAT/VDEX extraction failed: ${e}`);
        sendStrategyStatus(TAG, 'error', `${e}`);
    }
}

interface FileRegion {
    base: NativePointer;
    totalSize: number;
}

/**
 * Collect memory regions for .vdex/.oat/.odex files,
 * merging contiguous ranges for the same file.
 */
function collectFileRegions(): Map<string, FileRegion> {
    const regions = new Map<string, FileRegion>();
    const ranges = Process.enumerateRanges('r--');

    // Collect individual ranges per file
    const fileRanges = new Map<string, Array<{ base: NativePointer; size: number }>>();
    for (const range of ranges) {
        const path = range.file?.path;
        if (!path) continue;
        if (!path.endsWith('.vdex') && !path.endsWith('.oat') && !path.endsWith('.odex')) continue;

        let arr = fileRanges.get(path);
        if (!arr) {
            arr = [];
            fileRanges.set(path, arr);
        }
        arr.push({ base: range.base, size: range.size });
    }

    // Only merge truly contiguous ranges; keep non-contiguous as separate regions
    for (const [path, rangeList] of fileRanges) {
        // Sort by base address
        rangeList.sort((a, b) => a.base.compare(b.base));

        let currentBase = rangeList[0].base;
        let currentEnd = currentBase.add(rangeList[0].size);

        for (let i = 1; i < rangeList.length; i++) {
            const nextBase = rangeList[i].base;
            const nextEnd = nextBase.add(rangeList[i].size);

            if (nextBase.compare(currentEnd) <= 0) {
                // Contiguous or overlapping — merge
                if (nextEnd.compare(currentEnd) > 0) {
                    currentEnd = nextEnd;
                }
            } else {
                // Gap — save current and start new
                regions.set(`${path}@${currentBase}`, {
                    base: currentBase,
                    totalSize: currentEnd.sub(currentBase).toUInt32(),
                });
                currentBase = nextBase;
                currentEnd = nextEnd;
            }
        }

        // Save last merged region
        regions.set(`${path}@${currentBase}`, {
            base: currentBase,
            totalSize: currentEnd.sub(currentBase).toUInt32(),
        });
    }

    return regions;
}

/**
 * Scan a memory region for DEX magic and extract valid DEX files.
 */
function scanRegionForDex(
    dumper: DexDumper,
    base: NativePointer,
    size: number,
    path?: string
): number {
    let found = 0;

    // Scan in chunks to avoid blocking the agent thread for too long
    const CHUNK = 8 * 1024 * 1024; // 8 MB chunks
    const totalChunks = Math.ceil(size / CHUNK);

    try {
        let allMatches: MemoryScanMatch[] = [];
        for (let c = 0; c < totalChunks; c++) {
            const chunkBase = base.add(c * CHUNK);
            const chunkSize = Math.min(CHUNK, size - c * CHUNK);
            const chunkMatches = Memory.scanSync(chunkBase, chunkSize, DEX_MAGIC_BYTES);
            allMatches = allMatches.concat(chunkMatches);
            if (totalChunks > 1 && c < totalChunks - 1) {
                Thread.sleep(0.001); // Brief yield between chunks
            }
        }
        const matches = allMatches;
        for (const match of matches) {
            const fileSize = validateDexHeader(match.address);
            if (fileSize === 0) continue;

            // Ensure DEX fits within the region
            const regionEnd = base.add(size);
            const dexEnd = match.address.add(fileSize);
            if (dexEnd.compare(regionEnd) > 0) continue;

            if (dumper.dumpFromAddress(match.address, TAG, { path })) {
                found++;
                logger.debug(TAG, `Extracted DEX (${fileSize} bytes) from ${path ?? base.toString()}`);
            }
        }
    } catch (e) {
        logger.debug(TAG, `Scan failed for ${path ?? base.toString()}: ${e}`);
    }

    return found;
}
