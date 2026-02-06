import { DexDumper } from '../core/dexDumper.js';
import { OffsetResolver } from '../core/offsetResolver.js';
import { ArtOffsets } from '../config/offsets.js';
import { STRATEGY_NAMES, DEX_MAGIC } from '../config/constants.js';
import { sendStrategyStatus } from '../utils/messageSender.js';
import { safeReadPointer, isValidPointer } from '../utils/memoryUtils.js';
import { logger } from '../utils/logger.js';

const TAG = STRATEGY_NAMES.FART_DUMP;

/**
 * Strategy 8: FART-style Active Dump
 *
 * Hooks ClassLinker::DefineClass to intercept all class definitions,
 * extracting the DexFile* parameter to dump DEX files that are only
 * visible during class loading (critical for runtime unpackers).
 *
 * Also walks ClassLinker's class_table_ to find loaded classes and their
 * associated DexFile pointers — catches DEX that was loaded before our
 * agent attached.
 */
export function runFartDump(
    dumper: DexDumper,
    offsetResolver: OffsetResolver,
    offsets: ArtOffsets | null
): void {
    logger.strategy(TAG, 'Starting FART-style dump...');
    sendStrategyStatus(TAG, 'active', 'Setting up class definition hooks');

    let found = 0;

    // Part 1: Hook ClassLinker::DefineClass to catch future class loads
    hookDefineClass(dumper);

    // Part 2: Walk class_table_ if we have ClassLinker access
    if (offsets) {
        found += walkClassTable(dumper, offsetResolver, offsets);
    }

    if (found > 0) {
        logger.strategy(TAG, `FART dump found ${found} DEX files from class table`);
    }

    sendStrategyStatus(TAG, 'active',
        `Found ${found} DEX files, hook active for new classes`);
}

/**
 * Hook ClassLinker::DefineClass to intercept all class definitions.
 *
 * ARM64 calling convention (Interceptor.attach maps to registers directly):
 *   args[0] = x0 = this (ClassLinker*)
 *   args[1] = x1 = Thread*
 *   args[2] = x2 = const char* descriptor
 *   args[3] = x3 = size_t hash
 *   args[4] = x4 = Handle<ClassLoader>
 *   args[5] = x5 = const DexFile&
 *   args[6] = x6 = const ClassDef&
 */
function hookDefineClass(dumper: DexDumper): void {
    const libart = Process.findModuleByName('libart.so');
    if (!libart) {
        logger.warn(TAG, 'libart.so not found');
        return;
    }

    let hookAddr: NativePointer | null = null;
    let hookName = '';

    // Find DefineClass symbol
    try {
        const symbols = libart.enumerateSymbols();
        const match = symbols.find((s: ModuleSymbolDetails) =>
            s.name.includes('ClassLinker') &&
            s.name.includes('DefineClass') &&
            s.name.includes('DexFile') &&
            s.type === 'function'
        );
        if (match) {
            hookAddr = match.address;
            hookName = match.name;
        }
    } catch (e) {
        logger.debug(TAG, `Symbol enumeration failed: ${e}`);
    }

    if (!hookAddr) {
        try {
            const exports = libart.enumerateExports();
            const match = exports.find((e: ModuleExportDetails) =>
                e.name.includes('ClassLinker') &&
                e.name.includes('DefineClass') &&
                e.name.includes('DexFile') &&
                e.type === 'function'
            );
            if (match) {
                hookAddr = match.address;
                hookName = match.name;
            }
        } catch {
            // ignore
        }
    }

    if (!hookAddr) {
        logger.warn(TAG, 'ClassLinker::DefineClass not found');
        return;
    }

    logger.info(TAG, `Hooking ${hookName}`);

    try {
        Interceptor.attach(hookAddr, {
            onEnter(args) {
                try {
                    // DexFile& parameter position varies:
                    // Android 8-11: args[5] (descriptor, hash, ClassLoader, DexFile, ClassDef)
                    // Some builds: args[4] or args[3]
                    // Probe multiple positions to find the one pointing to a DexFile struct
                    for (const argIdx of [5, 4, 3, 6]) {
                        try {
                            const dexFilePtr = args[argIdx];
                            if (!dexFilePtr || dexFilePtr.isNull()) continue;

                            // Scan the DexFile struct for begin_ (pointer to DEX magic)
                            for (let off = 0; off < 128; off += Process.pointerSize) {
                                try {
                                    const candidate = dexFilePtr.add(off).readPointer();
                                    if (candidate.isNull()) continue;
                                    if (candidate.readU32() === DEX_MAGIC) {
                                        dumper.dumpFromAddress(candidate, TAG);
                                        return;
                                    }
                                } catch {
                                    continue;
                                }
                            }
                        } catch {
                            continue;
                        }
                    }
                } catch {
                    // Non-critical — just skip this call
                }
            },
        });

        logger.info(TAG, 'ClassLinker::DefineClass hooked');
    } catch (e) {
        logger.warn(TAG, `Failed to hook DefineClass: ${e}`);
    }
}

/**
 * Walk ClassLinker's class_table_ to find all currently loaded classes
 * and their associated DexFile pointers.
 *
 * Instead of deep nested loops through class entries, we look for
 * vectors in the ClassLinker that contain DexFile* → DEX magic chains.
 * This is faster and less version-dependent than walking individual classes.
 */
function walkClassTable(
    dumper: DexDumper,
    offsetResolver: OffsetResolver,
    offsets: ArtOffsets
): number {
    let found = 0;

    const runtimePtr = offsetResolver.getRuntimeInstance();
    if (!runtimePtr) return 0;

    const classLinker = safeReadPointer(runtimePtr.add(offsets.runtimeClassLinkerOffset));
    if (!classLinker || !isValidPointer(classLinker)) return 0;

    logger.info(TAG, 'Scanning ClassLinker for additional DexFile vectors...');

    const libart = Process.findModuleByName('libart.so');
    if (!libart) return 0;

    const libBase = libart.base;
    const libEnd = libBase.add(libart.size);
    const dexPtrs = new Set<string>();

    // Scan ClassLinker struct for vectors containing DexFile* pointers
    // that lead to DEX magic. This catches any vector field (dex_caches_,
    // boot_class_path_, class_table_ hash table buckets, etc.)
    // Phase 1: Collect all unique DEX addresses (fast — no send() calls)
    const dexAddresses: NativePointer[] = [];

    for (let clOff = 0; clOff < 0x600; clOff += Process.pointerSize) {
        try {
            const p1 = classLinker.add(clOff).readPointer();
            const p2 = classLinker.add(clOff + Process.pointerSize).readPointer();

            if (!isValidPointer(p1) || !isValidPointer(p2)) continue;
            if (p2.compare(p1) <= 0) continue;

            // Skip known libart vtables
            if (p1.compare(libBase) >= 0 && p1.compare(libEnd) < 0) continue;

            const size = p2.sub(p1).toUInt32();
            if (size === 0 || size > 10 * 1024 * 1024 || size % Process.pointerSize !== 0) continue;

            const count = size / Process.pointerSize;
            if (count > 10000) continue;

            // Sample first few entries for DexFile* → DEX magic chains
            let dexCount = 0;
            const sampleSize = Math.min(count, 10);

            for (let i = 0; i < sampleSize; i++) {
                const entryPtr = safeReadPointer(p1.add(i * Process.pointerSize));
                if (!entryPtr || !isValidPointer(entryPtr)) continue;

                for (let dOff = 0; dOff < 64; dOff += Process.pointerSize) {
                    try {
                        const dexBegin = entryPtr.add(dOff).readPointer();
                        if (dexBegin.isNull()) continue;
                        if (dexBegin.readU32() === DEX_MAGIC) {
                            dexCount++;
                            break;
                        }
                    } catch { break; }
                }
            }

            // If at least half the sampled entries look like DexFile*, collect all
            if (dexCount >= Math.max(1, Math.floor(sampleSize / 2))) {
                logger.debug(TAG, `DexFile vector at CL+0x${clOff.toString(16)} (${count} entries)`);

                for (let i = 0; i < count; i++) {
                    const entryPtr = safeReadPointer(p1.add(i * Process.pointerSize));
                    if (!entryPtr || !isValidPointer(entryPtr)) continue;

                    for (let dOff = 0; dOff < 64; dOff += Process.pointerSize) {
                        try {
                            const dexBegin = entryPtr.add(dOff).readPointer();
                            if (dexBegin.isNull()) continue;
                            if (dexBegin.readU32() === DEX_MAGIC) {
                                const key = dexBegin.toString();
                                if (!dexPtrs.has(key)) {
                                    dexPtrs.add(key);
                                    dexAddresses.push(dexBegin);
                                }
                                break;
                            }
                        } catch { break; }
                    }
                }
            }
        } catch {
            continue;
        }
    }

    logger.info(TAG, `Found ${dexAddresses.length} unique DEX addresses in class table`);

    // Phase 2: Dump collected addresses (send() heavy — yield between dumps)
    for (let i = 0; i < dexAddresses.length; i++) {
        if (dumper.dumpFromAddress(dexAddresses[i], TAG)) {
            found++;
            // Yield after each successful dump to let Frida transport drain
            // (prevents send() backpressure blocking on large payloads)
            Thread.sleep(0.001);
        }
    }

    return found;
}
