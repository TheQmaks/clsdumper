import Java from 'frida-java-bridge';
import { Deduplicator } from './core/deduplicator.js';
import { DexDumper } from './core/dexDumper.js';
import { OffsetResolver } from './core/offsetResolver.js';
import { getAndroidInfo, getAndroidInfoNative } from './core/androidVersion.js';
import { installAntiFridaBypass } from './core/antiFrida.js';
import { runMemoryScanner } from './strategies/memoryScanner.js';
import { runCookieExtractor } from './strategies/cookieExtractor.js';
import { runOpenCommonHook } from './strategies/openCommonHook.js';
import { runClassLoaderHooks } from './strategies/classLoaderHook.js';
import { runArtWalker } from './strategies/artWalker.js';
import { runMmapHook } from './strategies/mmapHook.js';
import { runOatExtractor } from './strategies/oatExtractor.js';
import { runFartDump } from './strategies/fartDump.js';
import { runDexFileConstructorHook } from './strategies/dexFileConstructorHook.js';
import { sendInfo, sendStrategyStatus, sendError } from './utils/messageSender.js';
import { logger, setDebug } from './utils/logger.js';
import { STRATEGY_NAMES, StrategyName } from './config/constants.js';

let enabledStrategies: Set<StrategyName> = new Set([
    STRATEGY_NAMES.ART_WALK,
    STRATEGY_NAMES.OPEN_COMMON_HOOK,
    STRATEGY_NAMES.MEMORY_SCAN,
    STRATEGY_NAMES.COOKIE,
    STRATEGY_NAMES.CLASSLOADER_HOOK,
    STRATEGY_NAMES.OAT_EXTRACT,
    STRATEGY_NAMES.FART_DUMP,
    STRATEGY_NAMES.DEXFILE_CONSTRUCTOR,
    // mmap_hook excluded by default: adds massive overhead on hot mmap() syscall,
    // causing crashes when combined with other hooks. Redundant with
    // dexfile_constructor + open_common_hook which catch all DEX loading.
]);
let deepScan = false;
let antiFrida = true;

// ── Shared state (initialized at load, used by run()) ──
const dedup = new Deduplicator();
const dumper = new DexDumper(dedup);
const offsetResolver = new OffsetResolver();

rpc.exports = {
    configure(strategies: StrategyName[] | null, deep: boolean, debug: boolean, noAntiFrida?: boolean) {
        if (debug) setDebug(true);
        if (strategies) enabledStrategies = new Set(strategies);
        deepScan = deep;
        if (noAntiFrida) antiFrida = false;
        logger.debug('AGENT', `Config: strategies=${Array.from(enabledStrategies)}, deep=${deep}, antiFrida=${antiFrida}`);
    },
};

// Start execution when host sends 'run' message (non-blocking)
recv('run', () => {
    executeStrategies();
});

function executeStrategies(): void {
    // ── Phase 0: Anti-frida bypass (before any hooks) ──

    logger.info('AGENT', 'CLSDumper agent starting...');

    if (antiFrida) {
        try {
            installAntiFridaBypass();
        } catch (e) {
            logger.warn('AGENT', `Anti-frida bypass error (non-fatal): ${e}`);
        }
    }

    // ── Phase 1: Native strategies (no Java required) ──

    const info = getAndroidInfoNative();
    let apiLevel = info.apiLevel;
    sendInfo(`Android ${info.release} (API ${info.apiLevel}), arch: ${info.arch}`);

    // Resolve ART offsets once for strategies that need them
    let artOffsets = null as ReturnType<OffsetResolver['resolve']>;
    try {
        artOffsets = offsetResolver.resolve(apiLevel);
    } catch (e) {
        logger.warn('AGENT', `Offset resolution error: ${e}`);
    }

    // Strategy 6: mmap Hook (install early to catch all future mmaps)
    if (enabledStrategies.has(STRATEGY_NAMES.MMAP_HOOK)) {
        try { runMmapHook(dumper); }
        catch (e) { sendError(STRATEGY_NAMES.MMAP_HOOK, `${e}`); }
    } else {
        sendStrategyStatus(STRATEGY_NAMES.MMAP_HOOK, 'skipped', 'Disabled');
    }

    // Strategy 9: DexFile Constructor Hook (install early to catch all DEX creation)
    if (enabledStrategies.has(STRATEGY_NAMES.DEXFILE_CONSTRUCTOR)) {
        try { runDexFileConstructorHook(dumper); }
        catch (e) { sendError(STRATEGY_NAMES.DEXFILE_CONSTRUCTOR, `${e}`); }
    } else {
        sendStrategyStatus(STRATEGY_NAMES.DEXFILE_CONSTRUCTOR, 'skipped', 'Disabled');
    }

    // Strategy 2: OpenCommon/OpenMemory Hook (native)
    if (enabledStrategies.has(STRATEGY_NAMES.OPEN_COMMON_HOOK)) {
        try { runOpenCommonHook(dumper); }
        catch (e) { sendError(STRATEGY_NAMES.OPEN_COMMON_HOOK, `${e}`); }
    } else {
        sendStrategyStatus(STRATEGY_NAMES.OPEN_COMMON_HOOK, 'skipped', 'Disabled');
    }

    // Strategy 8: FART-style Active Dump (hook + class table walk)
    if (enabledStrategies.has(STRATEGY_NAMES.FART_DUMP)) {
        try { runFartDump(dumper, offsetResolver, artOffsets); }
        catch (e) { sendError(STRATEGY_NAMES.FART_DUMP, `${e}`); }
    } else {
        sendStrategyStatus(STRATEGY_NAMES.FART_DUMP, 'skipped', 'Disabled');
    }

    // Strategy 1: ART Structure Walk (native — uses NativePointer only)
    if (enabledStrategies.has(STRATEGY_NAMES.ART_WALK)) {
        if (artOffsets) {
            try { runArtWalker(dumper, offsetResolver, artOffsets); }
            catch (e) { sendError(STRATEGY_NAMES.ART_WALK, `${e}`); }
        } else {
            sendStrategyStatus(STRATEGY_NAMES.ART_WALK, 'skipped', 'Could not resolve ART offsets');
        }
    } else {
        sendStrategyStatus(STRATEGY_NAMES.ART_WALK, 'skipped', 'Disabled');
    }

    // Strategy 7: OAT/VDEX Extraction (reads mapped files, no hooks)
    if (enabledStrategies.has(STRATEGY_NAMES.OAT_EXTRACT)) {
        try { runOatExtractor(dumper); }
        catch (e) { sendError(STRATEGY_NAMES.OAT_EXTRACT, `${e}`); }
    } else {
        sendStrategyStatus(STRATEGY_NAMES.OAT_EXTRACT, 'skipped', 'Disabled');
    }

    // Strategy 3: Memory Scan (native — last among static strategies, slowest)
    if (enabledStrategies.has(STRATEGY_NAMES.MEMORY_SCAN)) {
        try { runMemoryScanner(dumper, deepScan); }
        catch (e) { sendError(STRATEGY_NAMES.MEMORY_SCAN, `${e}`); }
    } else {
        sendStrategyStatus(STRATEGY_NAMES.MEMORY_SCAN, 'skipped', 'Disabled');
    }

    sendInfo(`Native strategies complete: ${dumper.uniqueCount} unique DEX files (${formatBytes(dumper.totalBytes)})`);

    // ── Phase 2: Java strategies (require Java bridge) ──

    const needsJava = enabledStrategies.has(STRATEGY_NAMES.COOKIE) ||
        enabledStrategies.has(STRATEGY_NAMES.CLASSLOADER_HOOK);

    if (needsJava) {
        try {
            Java.perform(() => {
                logger.info('AGENT', 'Java bridge active');

                // Update API level from Java if available (more accurate)
                try {
                    const javaInfo = getAndroidInfo();
                    apiLevel = javaInfo.apiLevel;
                } catch {
                    // Keep native-detected info
                }

                // Strategy 4: Cookie Extraction
                if (enabledStrategies.has(STRATEGY_NAMES.COOKIE)) {
                    try { runCookieExtractor(dumper, offsetResolver); }
                    catch (e) { sendError(STRATEGY_NAMES.COOKIE, `${e}`); }
                } else {
                    sendStrategyStatus(STRATEGY_NAMES.COOKIE, 'skipped', 'Disabled');
                }

                // Strategy 5: ClassLoader Hooks
                if (enabledStrategies.has(STRATEGY_NAMES.CLASSLOADER_HOOK)) {
                    try { runClassLoaderHooks(dumper); }
                    catch (e) { sendError(STRATEGY_NAMES.CLASSLOADER_HOOK, `${e}`); }
                } else {
                    sendStrategyStatus(STRATEGY_NAMES.CLASSLOADER_HOOK, 'skipped', 'Disabled');
                }

                sendInfo(`All strategies complete: ${dumper.uniqueCount} unique DEX files (${formatBytes(dumper.totalBytes)})`);
                sendInfo('Hooks active — watching for dynamic loads.');
            });
        } catch (e) {
            logger.warn('AGENT', `Java bridge failed (anti-debug?): ${e}`);
            sendInfo(`Java strategies skipped (anti-debug). Native results: ${dumper.uniqueCount} unique DEX files (${formatBytes(dumper.totalBytes)})`);
        }
    } else {
        sendInfo(`All strategies complete: ${dumper.uniqueCount} unique DEX files (${formatBytes(dumper.totalBytes)})`);
    }
}

// ── Control messages ──

recv('stop', () => {
    logger.info('AGENT', 'Received stop signal');
    Interceptor.detachAll();
    sendInfo('Agent stopped');
});

function formatBytes(bytes: number): string {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}
