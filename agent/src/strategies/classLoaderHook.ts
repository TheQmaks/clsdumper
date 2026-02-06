import Java from 'frida-java-bridge';
import { DexDumper } from '../core/dexDumper.js';
import { STRATEGY_NAMES, DEX_MAGIC } from '../config/constants.js';
import { sendStrategyStatus, sendClassLoaded } from '../utils/messageSender.js';
import { logger } from '../utils/logger.js';

const TAG = STRATEGY_NAMES.CLASSLOADER_HOOK;

/**
 * Strategy 5: ClassLoader Hooks (real-time monitoring)
 *
 * Hooks Java-level class loading to detect:
 * - New classes being loaded dynamically
 * - New DexClassLoader / InMemoryDexClassLoader creation
 * - Dynamic DEX file loading
 */
export function runClassLoaderHooks(dumper: DexDumper): void {
    logger.strategy(TAG, 'Setting up ClassLoader hooks...');
    sendStrategyStatus(TAG, 'active', 'Monitoring class loading');

    // Already inside Java.perform from main.ts
    {
        // Hook ClassLoader.loadClass to monitor class loads
        try {
            const ClassLoader = Java.use('java.lang.ClassLoader');
            ClassLoader.loadClass.overload('java.lang.String', 'boolean').implementation = function (
                name: string,
                resolve: boolean
            ) {
                const result = this.loadClass(name, resolve);
                sendClassLoaded(name, this.toString(), TAG);
                return result;
            };
            logger.info(TAG, 'Hooked ClassLoader.loadClass');
        } catch (e) {
            logger.warn(TAG, `Failed to hook ClassLoader.loadClass: ${e}`);
        }

        // Hook DexClassLoader constructor
        try {
            const DexClassLoader = Java.use('dalvik.system.DexClassLoader');
            DexClassLoader.$init.implementation = function (
                dexPath: string,
                optimizedDirectory: string,
                librarySearchPath: string,
                parent: any
            ) {
                logger.info(TAG, `DexClassLoader created: ${dexPath}`);
                sendClassLoaded(`[DexClassLoader] ${dexPath}`, this.toString(), TAG);

                // Call original
                this.$init(dexPath, optimizedDirectory, librarySearchPath, parent);

                // After construction, try to dump the loaded DEX via cookie
                try {
                    const BaseDexClassLoader = Java.use('dalvik.system.BaseDexClassLoader');
                    const cast = Java.cast(this, BaseDexClassLoader);
                    const pathList = cast.pathList.value;
                    if (pathList) {
                        const dexElements = pathList.dexElements.value;
                        if (dexElements) {
                            for (let i = 0; i < dexElements.length; i++) {
                                const elem = dexElements[i];
                                const dexFile = elem.dexFile.value;
                                if (!dexFile) continue;
                                const cookie = dexFile.mCookie.value;
                                if (!cookie) continue;
                                const ReflectArray = Java.use('java.lang.reflect.Array');
                                const arrLen = ReflectArray.getLength(cookie);
                                if (arrLen < 2) continue;

                                for (let j = 1; j < arrLen; j++) {
                                    const longVal = ReflectArray.getLong(cookie, j);
                                    const nativePtr = ptr(longVal.toString());
                                    if (nativePtr.isNull()) continue;
                                    // Scan for begin_ in DexFile struct
                                    for (let off = 0; off < 128; off += Process.pointerSize) {
                                        try {
                                            const begin = nativePtr.add(off).readPointer();
                                            if (!begin.isNull() && begin.readU32() === DEX_MAGIC) {
                                                dumper.dumpFromAddress(begin, TAG, {
                                                    loader: `DexClassLoader:${dexPath}`,
                                                    path: dexPath,
                                                });
                                                break;
                                            }
                                        } catch { continue; }
                                    }
                                }
                            }
                        }
                    }
                } catch (e) {
                    logger.debug(TAG, `Failed to dump after DexClassLoader creation: ${e}`);
                }
            };
            logger.info(TAG, 'Hooked DexClassLoader.$init');
        } catch (e) {
            logger.warn(TAG, `Failed to hook DexClassLoader: ${e}`);
        }

        // Hook InMemoryDexClassLoader (Android 8+)
        try {
            const InMemoryDexClassLoader = Java.use('dalvik.system.InMemoryDexClassLoader');

            // Hook the ByteBuffer[] constructor
            InMemoryDexClassLoader.$init.overload(
                '[Ljava.nio.ByteBuffer;', 'java.lang.String', 'java.lang.ClassLoader'
            ).implementation = function (buffers: any, librarySearchPath: string, parent: any) {
                logger.info(TAG, `InMemoryDexClassLoader created with ${buffers.length} buffers`);

                // Dump ByteBuffer contents before they're consumed
                for (let i = 0; i < buffers.length; i++) {
                    try {
                        const buf = buffers[i];
                        if (buf === null) continue;

                        const ByteBuffer = Java.use('java.nio.ByteBuffer');
                        const castBuf = Java.cast(buf, ByteBuffer);

                        // Get the buffer's content
                        const pos = castBuf.position();
                        const lim = castBuf.limit();
                        const size = lim - pos;

                        if (size > 0) {
                            // Try to get direct buffer address
                            if (castBuf.isDirect()) {
                                try {
                                    const address = (castBuf as any).address.value;
                                    if (address) {
                                        const baseAddr = ptr(address).add(pos);
                                        dumper.dumpFromAddress(baseAddr, TAG, {
                                            loader: 'InMemoryDexClassLoader',
                                        });
                                    }
                                } catch {
                                    // Fall through to byte-array path
                                }
                            }

                            // Fallback: read via byte array using bulk get
                            try {
                                const tmpBuf = castBuf.duplicate();
                                tmpBuf.position(pos);
                                const javaBytes = Java.array('byte', new Array(size).fill(0));
                                tmpBuf.get(javaBytes);

                                // Bulk-convert Java byte[] to native buffer
                                const nativeBuf = Memory.alloc(size);
                                const env = Java.vm.getEnv();
                                const javaArr = (javaBytes as any).$handle;
                                if (javaArr) {
                                    // Fast path: use JNI GetByteArrayRegion
                                    const getByteArrayRegion = (env as any).getByteArrayRegion;
                                    if (getByteArrayRegion) {
                                        getByteArrayRegion.call(env, javaArr, 0, size, nativeBuf);
                                    } else {
                                        // Slow path fallback
                                        for (let k = 0; k < size; k++) {
                                            nativeBuf.add(k).writeS8(javaBytes[k]);
                                        }
                                    }
                                } else {
                                    for (let k = 0; k < size; k++) {
                                        nativeBuf.add(k).writeS8(javaBytes[k]);
                                    }
                                }
                                const bytes = nativeBuf.readByteArray(size);
                                if (bytes) {
                                    dumper.dumpBytes(bytes, TAG, {
                                        loader: 'InMemoryDexClassLoader',
                                    });
                                }
                            } catch (e) {
                                logger.debug(TAG, `Failed to read ByteBuffer: ${e}`);
                            }
                        }
                    } catch (e) {
                        logger.debug(TAG, `ByteBuffer extraction error: ${e}`);
                    }
                }

                return this.$init(buffers, librarySearchPath, parent);
            };
            logger.info(TAG, 'Hooked InMemoryDexClassLoader.$init (ByteBuffer[])');
        } catch (e) {
            logger.debug(TAG, `InMemoryDexClassLoader (ByteBuffer[]) not available: ${e}`);
        }

        // Hook the single ByteBuffer constructor (most common overload)
        try {
            const InMemoryDexClassLoader = Java.use('dalvik.system.InMemoryDexClassLoader');
            InMemoryDexClassLoader.$init.overload(
                'java.nio.ByteBuffer', 'java.lang.ClassLoader'
            ).implementation = function (buffer: any, parent: any) {
                logger.info(TAG, 'InMemoryDexClassLoader created with single buffer');

                try {
                    if (buffer !== null) {
                        const ByteBuffer = Java.use('java.nio.ByteBuffer');
                        const castBuf = Java.cast(buffer, ByteBuffer);
                        const pos = castBuf.position();
                        const lim = castBuf.limit();
                        const size = lim - pos;

                        if (size > 0 && castBuf.isDirect()) {
                            try {
                                const address = (castBuf as any).address.value;
                                if (address) {
                                    dumper.dumpFromAddress(ptr(address).add(pos), TAG, {
                                        loader: 'InMemoryDexClassLoader',
                                    });
                                }
                            } catch {
                                // Fall through
                            }
                        }
                    }
                } catch (e) {
                    logger.debug(TAG, `ByteBuffer extraction error: ${e}`);
                }

                return this.$init(buffer, parent);
            };
            logger.info(TAG, 'Hooked InMemoryDexClassLoader.$init (ByteBuffer)');
        } catch (e) {
            logger.debug(TAG, `InMemoryDexClassLoader (ByteBuffer) not available: ${e}`);
        }

        // Hook DexFile.loadDex (deprecated but still used)
        try {
            const DexFile = Java.use('dalvik.system.DexFile');
            if (DexFile.loadDex) {
                DexFile.loadDex.implementation = function (
                    sourcePathName: string,
                    outputPathName: string,
                    flags: number
                ) {
                    logger.info(TAG, `DexFile.loadDex: ${sourcePathName}`);
                    sendClassLoaded(`[DexFile.loadDex] ${sourcePathName}`, 'DexFile', TAG);
                    return this.loadDex(sourcePathName, outputPathName, flags);
                };
                logger.info(TAG, 'Hooked DexFile.loadDex');
            }
        } catch (e) {
            logger.debug(TAG, `DexFile.loadDex not available: ${e}`);
        }

        sendStrategyStatus(TAG, 'active', 'ClassLoader hooks installed');
    }
}
