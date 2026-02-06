import { DexDumper } from '../core/dexDumper.js';
import { STRATEGY_NAMES } from '../config/constants.js';
import { validateDexHeader } from '../utils/memoryUtils.js';
import { sendStrategyStatus } from '../utils/messageSender.js';
import { logger } from '../utils/logger.js';
const TAG = STRATEGY_NAMES.OPEN_COMMON_HOOK;

/**
 * Strategy 2: Hook DexFile::OpenCommon / OpenMemory
 *
 * Intercepts DEX file loading at the native level.
 * - Android < 8: DexFile::OpenMemory in libart.so
 * - Android 8-9: DexFile::OpenCommon in libart.so
 * - Android 10+: DexFile::OpenCommon in libdexfile.so (APEX)
 */
export function runOpenCommonHook(dumper: DexDumper): void {
    logger.strategy(TAG, 'Setting up OpenCommon/OpenMemory hooks...');

    let hookAddress: NativePointer | null = null;
    let hookLibrary = 'libart.so';
    let hookName = '';

    // Try both libraries — libdexfile.so first (Android 10+), then libart.so
    const searchLibraries = ['libdexfile.so', 'libart.so'];

    for (const lib of searchLibraries) {
        try {
            const mod = Process.findModuleByName(lib);
            if (!mod) continue;

            const symbols = mod.enumerateSymbols();
            const match = symbols.find((s: ModuleSymbolDetails) =>
                s.name.includes('DexFile') &&
                (s.name.includes('OpenCommon') || s.name.includes('OpenMemory')) &&
                s.type === 'function'
            );

            if (match) {
                hookAddress = match.address;
                hookLibrary = lib;
                hookName = match.name;
                break;
            }
        } catch {
            continue;
        }
    }

    // Fallback: try enumerateExports
    if (!hookAddress) {
        for (const lib of searchLibraries) {
            try {
                const mod = Process.findModuleByName(lib);
                if (!mod) continue;

                const exports = mod.enumerateExports();
                const match = exports.find((e: ModuleExportDetails) =>
                    e.name.includes('DexFile') &&
                    (e.name.includes('OpenCommon') || e.name.includes('OpenMemory')) &&
                    e.type === 'function'
                );
                if (match) {
                    hookAddress = match.address;
                    hookLibrary = lib;
                    hookName = match.name;
                    break;
                }
            } catch {
                continue;
            }
        }
    }

    if (!hookAddress) {
        logger.strategyError(TAG, 'Could not find OpenCommon/OpenMemory symbol');
        sendStrategyStatus(TAG, 'skipped', 'Symbol not found');
        return;
    }

    logger.info(TAG, `Hooking ${hookName} in ${hookLibrary}`);

    try {
        Interceptor.attach(hookAddress, {
            onEnter(args) {
                // The first argument is typically const uint8_t* base (the raw DEX bytes)
                // Argument positions may vary by Android version, but arg[0] or arg[1] is usually base
                // We try both
                for (let argIdx = 0; argIdx < 3; argIdx++) {
                    try {
                        const candidate = args[argIdx];
                        if (candidate.isNull()) continue;

                        const fileSize = validateDexHeader(candidate);
                        if (fileSize > 0) {
                            dumper.dumpFromAddress(candidate, TAG, {
                                location: hookName,
                            });
                            return;
                        }
                    } catch {
                        continue;
                    }
                }
            },
        });

        sendStrategyStatus(TAG, 'active', `Hooked ${hookLibrary}`);
    } catch (e) {
        logger.strategyError(TAG, `Failed to hook: ${e}`);
        sendStrategyStatus(TAG, 'error', `${e}`);
    }
}
