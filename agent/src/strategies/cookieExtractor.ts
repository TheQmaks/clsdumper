import Java from 'frida-java-bridge';
import { DexDumper } from '../core/dexDumper.js';
import { OffsetResolver } from '../core/offsetResolver.js';
import { STRATEGY_NAMES, DEX_MAGIC } from '../config/constants.js';
import { sendStrategyStatus, sendClassLoaderFound } from '../utils/messageSender.js';
import { safeReadPointer } from '../utils/memoryUtils.js';
import { logger } from '../utils/logger.js';

const TAG = STRATEGY_NAMES.COOKIE;

/**
 * Read a Java long[] via reflection, returning values as strings (to preserve 64-bit precision).
 */
function readLongArray(arr: any): string[] {
    const result: string[] = [];
    try {
        const ArrayReflect = Java.use('java.lang.reflect.Array');
        const len = ArrayReflect.getLength(arr);
        for (let i = 0; i < len; i++) {
            const val = ArrayReflect.getLong(arr, i);
            result.push(val.toString());
        }
    } catch (e) {
        logger.debug(TAG, `readLongArray reflection failed: ${e}`);
        // Fallback: try treating as JS-iterable
        try {
            if (Array.isArray(arr)) {
                for (let i = 0; i < arr.length; i++) {
                    result.push(String(arr[i]));
                }
            } else if (arr && typeof arr.length === 'number') {
                for (let i = 0; i < arr.length; i++) {
                    result.push(String(arr[i]));
                }
            }
        } catch (e2) {
            logger.debug(TAG, `readLongArray fallback failed: ${e2}`);
        }
    }
    return result;
}

/**
 * Strategy 4: Cookie Extraction (Java-level)
 *
 * Enumerates all ClassLoaders, accesses DexFile.mCookie to get
 * native DexFile* pointers, then reads begin_/size_ to dump DEX bytes.
 */
export function runCookieExtractor(dumper: DexDumper, offsetResolver: OffsetResolver): void {
    logger.strategy(TAG, 'Starting cookie extraction...');
    sendStrategyStatus(TAG, 'active', 'Extracting DEX via ClassLoader cookies');

    let found = 0;
    let dexFileBeginOffset: number | null = null;

    try {
        Java.enumerateClassLoaders({
                onMatch(loader) {
                    try {
                        const BaseDexClassLoader = Java.use('dalvik.system.BaseDexClassLoader');
                        const cast = Java.cast(loader, BaseDexClassLoader);

                        const loaderStr = loader.toString();
                        const loaderType = loader.$className || 'unknown';

                        try {
                            sendClassLoaderFound(loaderStr, loaderType, 'unknown');
                        } catch {
                            // Non-fatal — just metadata reporting
                        }

                        const pathList = cast.pathList.value;
                        if (!pathList) return;

                        const dexElements = pathList.dexElements.value;
                        if (!dexElements) return;

                        logger.debug(TAG, `${loaderType}: ${dexElements.length} dexElements`);

                        for (let i = 0; i < dexElements.length; i++) {
                            try {
                                const element = dexElements[i];
                                const dexFile = element.dexFile.value;
                                if (!dexFile) continue;

                                // Try mCookie first, fallback to mInternalCookie
                                let cookieObj: any = null;
                                try { cookieObj = dexFile.mCookie.value; } catch {}
                                if (!cookieObj) {
                                    try { cookieObj = dexFile.mInternalCookie.value; } catch {}
                                }
                                if (!cookieObj) {
                                    logger.debug(TAG, `No cookie for ${loaderStr} element ${i}`);
                                    continue;
                                }

                                // Read cookie as long[] via reflection
                                const cookieValues = readLongArray(cookieObj);
                                logger.debug(TAG, `Cookie for ${loaderType}[${i}]: ${cookieValues.length} entries`);

                                if (cookieValues.length < 2) continue;

                                // cookie[0] = oat_file_ptr (or 0)
                                // cookie[1+] = native DexFile* pointers
                                for (let j = 1; j < cookieValues.length; j++) {
                                    try {
                                        const nativeDexFilePtr = ptr(cookieValues[j]);
                                        if (nativeDexFilePtr.isNull()) continue;

                                        // Probe for begin_ offset if unknown
                                        if (dexFileBeginOffset === null) {
                                            const probed = offsetResolver.probeDexFileOffsets(nativeDexFilePtr);
                                            if (probed?.dexFileBeginOffset !== undefined) {
                                                dexFileBeginOffset = probed.dexFileBeginOffset;
                                                logger.info(TAG, `Probed DexFile::begin_ offset: 0x${dexFileBeginOffset.toString(16)}`);
                                            }
                                        }

                                        // Try known offset first
                                        if (dexFileBeginOffset !== null) {
                                            const beginPtr = safeReadPointer(nativeDexFilePtr.add(dexFileBeginOffset));
                                            if (beginPtr && !beginPtr.isNull()) {
                                                if (dumper.dumpFromAddress(beginPtr, TAG, {
                                                    loader: loaderStr,
                                                })) {
                                                    found++;
                                                    continue;
                                                }
                                            }
                                        }

                                        // Fallback: scan for begin_ in the struct
                                        for (let offset = 0; offset < 128; offset += Process.pointerSize) {
                                            const candidate = safeReadPointer(nativeDexFilePtr.add(offset));
                                            if (!candidate || candidate.isNull()) continue;
                                            try {
                                                if (candidate.readU32() === DEX_MAGIC) {
                                                    if (dexFileBeginOffset === null) {
                                                        dexFileBeginOffset = offset;
                                                        logger.info(TAG, `Found DexFile::begin_ at offset 0x${offset.toString(16)}`);
                                                    }
                                                    if (dumper.dumpFromAddress(candidate, TAG, {
                                                        loader: loaderStr,
                                                    })) {
                                                        found++;
                                                    }
                                                    break;
                                                }
                                            } catch {
                                                continue;
                                            }
                                        }
                                    } catch (e) {
                                        logger.debug(TAG, `Cookie entry error: ${e}`);
                                    }
                                }
                            } catch (e) {
                                logger.debug(TAG, `DexElement error: ${e}`);
                            }
                        }
                    } catch {
                        // Not a BaseDexClassLoader — skip
                    }
                },
                onComplete() {
                    logger.strategy(TAG, `Cookie extraction complete: ${found} DEX files`);
                    sendStrategyStatus(TAG, 'complete', `Found ${found} DEX files`);
                },
            });
    } catch (e) {
        logger.strategyError(TAG, `Cookie extraction failed: ${e}`);
        sendStrategyStatus(TAG, 'error', `${e}`);
    }
}
