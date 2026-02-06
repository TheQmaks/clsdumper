import Java from 'frida-java-bridge';
import { logger } from '../utils/logger.js';

export interface AndroidInfo {
    apiLevel: number;
    release: string;
    arch: string;
    pointerSize: number;
}

let cachedInfo: AndroidInfo | null = null;
let cachedNativeInfo: AndroidInfo | null = null;

/**
 * Get Android info via native __system_property_get (no Java required).
 */
export function getAndroidInfoNative(): AndroidInfo {
    if (cachedNativeInfo) return cachedNativeInfo;

    let apiLevel = 0;
    let release = 'unknown';

    try {
        const getProp = new NativeFunction(
            Process.findModuleByName('libc.so')!.getExportByName('__system_property_get'),
            'int',
            ['pointer', 'pointer']
        );
        const nameBuf = Memory.allocUtf8String('ro.build.version.sdk');
        const valBuf = Memory.alloc(92); // PROP_VALUE_MAX = 92
        getProp(nameBuf, valBuf);
        const sdkStr = valBuf.readCString();
        if (sdkStr) apiLevel = parseInt(sdkStr, 10) || 0;

        const nameRelease = Memory.allocUtf8String('ro.build.version.release');
        getProp(nameRelease, valBuf);
        release = valBuf.readCString() || 'unknown';
    } catch (e) {
        logger.warn('VERSION', `Native property read failed: ${e}`);
    }

    cachedNativeInfo = {
        apiLevel,
        release,
        arch: Process.arch,
        pointerSize: Process.pointerSize,
    };

    logger.info('VERSION', `Android ${release} (API ${apiLevel}), arch: ${Process.arch}`);
    return cachedNativeInfo;
}

/**
 * Get Android info via Java (more accurate, requires Java.perform).
 */
export function getAndroidInfo(): AndroidInfo {
    if (cachedInfo) return cachedInfo;

    let apiLevel = 0;
    let release = 'unknown';

    try {
        const Build = Java.use('android.os.Build$VERSION');
        apiLevel = Build.SDK_INT.value;
        release = Build.RELEASE.value;
    } catch (e) {
        logger.warn('VERSION', `Failed to read Build.VERSION: ${e}`);
        // Fallback to native
        return getAndroidInfoNative();
    }

    cachedInfo = {
        apiLevel,
        release,
        arch: Process.arch,
        pointerSize: Process.pointerSize,
    };

    logger.info('VERSION', `Android ${release} (API ${apiLevel}), arch: ${Process.arch}`);
    return cachedInfo;
}

export function isAtLeast(level: number): boolean {
    return getAndroidInfoNative().apiLevel >= level;
}
