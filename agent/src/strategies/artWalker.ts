import { DexDumper } from '../core/dexDumper.js';
import { OffsetResolver } from '../core/offsetResolver.js';
import { ArtOffsets } from '../config/offsets.js';
import { STRATEGY_NAMES, DEX_MAGIC } from '../config/constants.js';
import { sendStrategyStatus } from '../utils/messageSender.js';
import { safeReadPointer, isValidPointer, validateDexHeader } from '../utils/memoryUtils.js';
import { logger } from '../utils/logger.js';

const TAG = STRATEGY_NAMES.ART_WALK;

/**
 * Strategy 1: ART Structure Walk
 *
 * Directly traverses ART Runtime C++ structures via NativePointer:
 * Runtime::instance_ → ClassLinker → dex_caches_ / boot_class_path_ → DexFile → begin_/size_
 *
 * Most comprehensive strategy but requires accurate struct offsets.
 */
export function runArtWalker(
    dumper: DexDumper,
    offsetResolver: OffsetResolver,
    offsets: ArtOffsets
): void {
    logger.strategy(TAG, 'Starting ART structure walk...');
    sendStrategyStatus(TAG, 'active', 'Walking ART Runtime structures');

    let found = 0;

    try {
        // 1. Get Runtime::instance_
        const runtimePtr = offsetResolver.getRuntimeInstance();
        if (!runtimePtr) {
            logger.strategyError(TAG, 'Cannot find Runtime::instance_');
            sendStrategyStatus(TAG, 'error', 'Runtime::instance_ not found');
            return;
        }
        logger.info(TAG, `Runtime instance: ${runtimePtr}`);

        // 2. Read ClassLinker*
        const classLinker = safeReadPointer(runtimePtr.add(offsets.runtimeClassLinkerOffset));
        if (!classLinker || !isValidPointer(classLinker)) {
            logger.strategyError(TAG, 'Cannot read ClassLinker pointer');
            sendStrategyStatus(TAG, 'error', 'ClassLinker not found');
            return;
        }
        logger.info(TAG, `ClassLinker: ${classLinker}`);

        // 3. Try to walk boot_class_path_ (std::vector<const DexFile*>)
        if (offsets.classLinkerBootClassPathOffset > 0) {
            found += walkDexFileVector(
                dumper,
                classLinker.add(offsets.classLinkerBootClassPathOffset),
                offsets,
                'boot_class_path'
            );
        }

        // 4. Try to walk dex_caches_ (more complex: vector of DexCacheData)
        if (offsets.classLinkerDexCachesOffset > 0) {
            found += walkDexCaches(
                dumper,
                classLinker.add(offsets.classLinkerDexCachesOffset),
                offsets
            );
        }

        // 5. Fallback: scan ClassLinker struct for pointers → DEX magic
        if (found === 0) {
            logger.info(TAG, 'No DEX found via known offsets, probing ClassLinker...');
            found += probeClassLinker(dumper, classLinker, offsets);
        }

        logger.strategy(TAG, `ART walk complete: ${found} DEX files`);
        sendStrategyStatus(TAG, 'complete', `Found ${found} DEX files`);
    } catch (e) {
        logger.strategyError(TAG, `ART walk failed: ${e}`);
        sendStrategyStatus(TAG, 'error', `${e}`);
    }
}

/**
 * Walk a std::vector<const DexFile*> to dump each DexFile.
 */
function walkDexFileVector(
    dumper: DexDumper,
    vectorAddr: NativePointer,
    offsets: ArtOffsets,
    label: string
): number {
    let found = 0;

    try {
        const begin = safeReadPointer(vectorAddr);
        const end = safeReadPointer(vectorAddr.add(Process.pointerSize));

        if (!begin || !end || !isValidPointer(begin) || !isValidPointer(end)) {
            logger.debug(TAG, `${label}: invalid vector pointers`);
            return 0;
        }

        const count = end.sub(begin).toInt32() / Process.pointerSize;
        if (count <= 0 || count > 10000) {
            logger.debug(TAG, `${label}: suspicious count ${count}`);
            return 0;
        }

        logger.info(TAG, `${label}: ${count} entries`);

        for (let i = 0; i < count; i++) {
            const dexFilePtr = safeReadPointer(begin.add(i * Process.pointerSize));
            if (!dexFilePtr || !isValidPointer(dexFilePtr)) continue;

            found += dumpFromDexFilePtr(dumper, dexFilePtr, offsets);
        }
    } catch (e) {
        logger.debug(TAG, `${label} walk error: ${e}`);
    }

    return found;
}

/**
 * Walk dex_caches_ (std::vector<DexCacheData>) to find DexFile pointers.
 */
function walkDexCaches(
    dumper: DexDumper,
    vectorAddr: NativePointer,
    offsets: ArtOffsets
): number {
    let found = 0;

    try {
        const begin = safeReadPointer(vectorAddr);
        const end = safeReadPointer(vectorAddr.add(Process.pointerSize));

        if (!begin || !end || !isValidPointer(begin) || !isValidPointer(end)) {
            return 0;
        }

        const totalBytes = end.sub(begin).toInt32();
        const entrySize = offsets.dexCacheDataSize;
        if (entrySize <= 0 || totalBytes <= 0 || totalBytes > 1000000) return 0;

        const count = Math.floor(totalBytes / entrySize);
        logger.info(TAG, `dex_caches: ${count} entries (entry size: ${entrySize})`);

        for (let i = 0; i < count; i++) {
            const entry = begin.add(i * entrySize);
            const dexFilePtr = safeReadPointer(entry.add(offsets.dexCacheDataDexFileOffset));
            if (!dexFilePtr || !isValidPointer(dexFilePtr)) continue;

            found += dumpFromDexFilePtr(dumper, dexFilePtr, offsets);
        }
    } catch (e) {
        logger.debug(TAG, `dex_caches walk error: ${e}`);
    }

    return found;
}

/**
 * Dump DEX from a native art::DexFile* pointer.
 */
function dumpFromDexFilePtr(
    dumper: DexDumper,
    dexFilePtr: NativePointer,
    offsets: ArtOffsets
): number {
    // Try the known begin_ offset
    const beginPtr = safeReadPointer(dexFilePtr.add(offsets.dexFileBeginOffset));
    if (beginPtr && !beginPtr.isNull()) {
        const fileSize = validateDexHeader(beginPtr);
        if (fileSize > 0) {
            // Try to read location
            let location: string | undefined;
            if (offsets.dexFileLocationOffset > 0) {
                try {
                    // libc++ std::string layout:
                    // Short string (SSO): data is inline at offset 1
                    // Long string: first field is pointer to heap data
                    const locBase = dexFilePtr.add(offsets.dexFileLocationOffset);
                    const firstByte = locBase.readU8();
                    if ((firstByte & 1) === 0) {
                        // Short string: length = firstByte >> 1, data at offset 1
                        const ssoLen = firstByte >> 1;
                        if (ssoLen > 0 && ssoLen < 23) {
                            location = locBase.add(1).readUtf8String(ssoLen) ?? undefined;
                        }
                    } else {
                        // Long string: {capacity, size, data_ptr}
                        const dataPtr = locBase.add(2 * Process.pointerSize).readPointer();
                        if (!dataPtr.isNull()) {
                            location = dataPtr.readCString() ?? undefined;
                        }
                    }
                } catch {
                    // Ignore — location is optional
                }
            }

            // Return regardless of duplicate status — the known offset is correct,
            // no need to fall through to the probe loop
            return dumper.dumpFromAddress(beginPtr, STRATEGY_NAMES.ART_WALK, { location }) ? 1 : 0;
        }
    }

    // Fallback: probe for DEX magic in the struct (only if known offset didn't find valid DEX)
    for (let off = 0; off < 128; off += Process.pointerSize) {
        try {
            const candidate = dexFilePtr.add(off).readPointer();
            if (candidate.isNull()) continue;
            if (candidate.readU32() === DEX_MAGIC) {
                if (dumper.dumpFromAddress(candidate, STRATEGY_NAMES.ART_WALK)) {
                    return 1;
                }
            }
        } catch {
            continue;
        }
    }

    return 0;
}

/**
 * Probe ClassLinker struct looking for vectors of pointers to DEX files.
 */
function probeClassLinker(
    dumper: DexDumper,
    classLinker: NativePointer,
    offsets: ArtOffsets
): number {
    let found = 0;
    const probeRange = 2048; // Scan first 2KB of ClassLinker

    for (let off = 0; off < probeRange; off += Process.pointerSize) {
        try {
            // Look for potential std::vector<DexFile*> patterns:
            // Two consecutive pointers where second >= first
            const p1 = classLinker.add(off).readPointer();
            const p2 = classLinker.add(off + Process.pointerSize).readPointer();

            if (!isValidPointer(p1) || !isValidPointer(p2)) continue;
            if (p2.compare(p1) < 0) continue;

            const size = p2.sub(p1).toInt32();
            if (size <= 0 || size > 100000 || size % Process.pointerSize !== 0) continue;

            const count = size / Process.pointerSize;
            if (count > 1000) continue;

            // Check if entries look like DexFile pointers
            let dexCount = 0;
            for (let i = 0; i < Math.min(count, 5); i++) {
                const entryPtr = safeReadPointer(p1.add(i * Process.pointerSize));
                if (!entryPtr || !isValidPointer(entryPtr)) continue;

                // Check if this points to something with a pointer to DEX magic
                for (let fieldOff = 0; fieldOff < 64; fieldOff += Process.pointerSize) {
                    try {
                        const candidateBegin = entryPtr.add(fieldOff).readPointer();
                        if (!candidateBegin.isNull() && candidateBegin.readU32() === DEX_MAGIC) {
                            dexCount++;
                            break;
                        }
                    } catch { continue; }
                }
            }

            // If most entries look like DexFile*, dump them all
            if (dexCount >= Math.min(count, 3)) {
                logger.info(TAG, `Found probable DexFile vector at ClassLinker+0x${off.toString(16)} (${count} entries)`);
                found += walkDexFileVector(dumper, classLinker.add(off), offsets, `probe_0x${off.toString(16)}`);
            }
        } catch {
            continue;
        }
    }

    return found;
}
