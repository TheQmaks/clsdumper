import { DexDumper } from '../core/dexDumper.js';
import { STRATEGY_NAMES, DEX_MAGIC } from '../config/constants.js';
import { validateDexHeader } from '../utils/memoryUtils.js';
import { sendStrategyStatus } from '../utils/messageSender.js';
import { logger } from '../utils/logger.js';

const TAG = STRATEGY_NAMES.DEXFILE_CONSTRUCTOR;

/**
 * Strategy 9: DexFile Constructor Hook
 *
 * Hooks the art::DexFile C++ constructor(s) in libart.so to intercept
 * DEX files at the moment they are created. This catches DEX files
 * earlier than OpenCommon — before any processing is applied.
 *
 * Constructor mangled names contain:
 * - _ZN3art7DexFileC1E  (complete object constructor)
 * - _ZN3art7DexFileC2E  (base object constructor)
 *
 * ARM64 calling convention (Interceptor.attach maps to registers):
 *   args[0] = x0 = this (DexFile*)
 *   args[1] = x1 = first param (typically const uint8_t* base)
 *   args[2] = x2 = second param (typically size_t size)
 *   args[3+] = remaining params
 */
export function runDexFileConstructorHook(dumper: DexDumper): void {
    logger.strategy(TAG, 'Setting up DexFile constructor hooks...');
    sendStrategyStatus(TAG, 'active', 'Hooking DexFile constructors');

    const libart = Process.findModuleByName('libart.so');
    if (!libart) {
        logger.strategyError(TAG, 'libart.so not found');
        sendStrategyStatus(TAG, 'error', 'libart.so not found');
        return;
    }

    // Find all DexFile constructor symbols
    const constructors = findDexFileConstructors(libart);

    if (constructors.length === 0) {
        // Fallback: also check libdexfile.so (Android 10+)
        const libdexfile = Process.findModuleByName('libdexfile.so');
        if (libdexfile) {
            constructors.push(...findDexFileConstructors(libdexfile));
        }
    }

    if (constructors.length === 0) {
        logger.warn(TAG, 'No DexFile constructors found');
        sendStrategyStatus(TAG, 'skipped', 'No DexFile constructors found');
        return;
    }

    let hooked = 0;

    for (const ctor of constructors) {
        try {
            Interceptor.attach(ctor.address, {
                onEnter(args) {
                    // DexFile constructors on ARM64:
                    //   args[0] = this (DexFile being constructed)
                    //   args[1] = base (const uint8_t* — raw DEX bytes)
                    //   args[2] = size (size_t)
                    //   args[3+] = location, checksum, etc.
                    //
                    // Try args[1] first (base), then args[2], then args[3]
                    // (position may shift if there's an extra param before base)
                    for (const argIdx of [1, 2, 3]) {
                        try {
                            const candidate = args[argIdx];
                            if (!candidate || candidate.isNull()) continue;

                            const magic = candidate.readU32();
                            if (magic !== DEX_MAGIC) continue;

                            const fileSize = validateDexHeader(candidate);
                            if (fileSize > 0) {
                                dumper.dumpFromAddress(candidate, TAG, {
                                    location: ctor.name,
                                });
                                return;
                            }
                        } catch {
                            continue;
                        }
                    }
                },
            });

            hooked++;
            logger.info(TAG, `Hooked constructor: ${ctor.name}`);
        } catch (e) {
            logger.debug(TAG, `Failed to hook ${ctor.name}: ${e}`);
        }
    }

    if (hooked > 0) {
        sendStrategyStatus(TAG, 'active', `Hooked ${hooked} DexFile constructors`);
    } else {
        sendStrategyStatus(TAG, 'error', 'Failed to hook any constructor');
    }
}

/**
 * Find DexFile constructor symbols in a module.
 * Filters out copy/move constructors (which have DexFile ref/rvalue-ref params).
 */
function findDexFileConstructors(mod: Module): Array<{ address: NativePointer; name: string }> {
    const results: Array<{ address: NativePointer; name: string }> = [];
    const seen = new Set<string>();

    const processSymbol = (name: string, address: NativePointer) => {
        // Match DexFile constructors: C1 (complete) and C2 (base)
        if (!name.includes('DexFileC1E') && !name.includes('DexFileC2E')) return;

        // Skip copy constructor: DexFileC1ERKS_ or DexFileC2ERKS_ (const DexFile&)
        // Skip move constructor: DexFileC1EOS_ or DexFileC2EOS_ (DexFile&&)
        if (/DexFileC[12]E(RKS|OS)/.test(name)) return;

        const key = address.toString();
        if (seen.has(key)) return;
        seen.add(key);

        results.push({ address, name });
    };

    // Search symbols (includes non-exported)
    try {
        const symbols = mod.enumerateSymbols();
        for (const sym of symbols) {
            if (sym.type !== 'function') continue;
            processSymbol(sym.name, sym.address);
        }
    } catch (e) {
        logger.debug(TAG, `Symbol enumeration failed for ${mod.name}: ${e}`);
    }

    // Also check exports
    try {
        const exports = mod.enumerateExports();
        for (const exp of exports) {
            if (exp.type !== 'function') continue;
            processSymbol(exp.name, exp.address);
        }
    } catch {
        // ignore
    }

    return results;
}
