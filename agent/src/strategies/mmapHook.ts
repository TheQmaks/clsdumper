import { DexDumper } from '../core/dexDumper.js';
import { STRATEGY_NAMES, DEX_MAGIC } from '../config/constants.js';
import { validateDexHeader } from '../utils/memoryUtils.js';
import { sendStrategyStatus } from '../utils/messageSender.js';
import { logger } from '../utils/logger.js';

const TAG = STRATEGY_NAMES.MMAP_HOOK;

/**
 * Strategy 6: mmap/mmap64 Hook
 *
 * Intercepts memory-mapping syscalls to catch DEX files being mapped into memory.
 * Useful for packers that decrypt DEX to a temp file and mmap it.
 *
 * mmap signature: void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
 */
export function runMmapHook(dumper: DexDumper): void {
    logger.strategy(TAG, 'Setting up mmap/mmap64 hooks...');
    sendStrategyStatus(TAG, 'active', 'Hooking mmap/mmap64');

    const libc = Process.findModuleByName('libc.so');
    if (!libc) {
        logger.strategyError(TAG, 'libc.so not found');
        sendStrategyStatus(TAG, 'error', 'libc.so not found');
        return;
    }

    // Cache readlink NativeFunction (avoid creating in hot path)
    let readlinkFunc: NativeFunction<number, [NativePointer, NativePointer, number]> | null = null;
    const readlinkAddr = libc.findExportByName('readlink');
    if (readlinkAddr) {
        readlinkFunc = new NativeFunction(readlinkAddr, 'int', ['pointer', 'pointer', 'int']);
    }

    let hooked = 0;

    // Hook both mmap and mmap64
    for (const funcName of ['mmap', 'mmap64']) {
        const addr = libc.findExportByName(funcName);
        if (!addr) {
            logger.debug(TAG, `${funcName} not found in libc.so`);
            continue;
        }

        try {
            Interceptor.attach(addr, {
                onEnter(args) {
                    // Fast filter in onEnter to minimize onLeave overhead.
                    // Skip anonymous mappings (fd == -1) — vast majority of mmap calls.
                    // Skip tiny mappings that can't be DEX files.
                    const fd = args[4].toInt32();
                    const length = args[1].toUInt32();
                    if (fd < 0 || length < 0x70) {
                        this.skip = true;
                        return;
                    }
                    this.skip = false;
                    this.length = length;
                    this.fd = fd;
                },
                onLeave(retval) {
                    if (this.skip) return;

                    // MAP_FAILED = (void*)-1
                    if (retval.equals(ptr(-1)) || retval.isNull()) return;

                    const length = this.length as number;

                    try {
                        const magic = retval.readU32();
                        if (magic !== DEX_MAGIC) return;

                        const fileSize = validateDexHeader(retval);
                        if (fileSize === 0) return;
                        if (fileSize > length) return;

                        // Try to resolve fd to path for metadata
                        let path: string | undefined;
                        const fd = this.fd as number;
                        if (fd >= 0 && readlinkFunc) {
                            try {
                                const linkBuf = Memory.alloc(512);
                                const linkPath = Memory.allocUtf8String(`/proc/self/fd/${fd}`);
                                const len = readlinkFunc(linkPath, linkBuf, 511) as number;
                                if (len > 0) {
                                    path = linkBuf.readUtf8String(len) ?? undefined;
                                }
                            } catch {
                                // Ignore — path is optional
                            }
                        }

                        dumper.dumpFromAddress(retval, TAG, { path });
                    } catch {
                        // Not readable or not DEX — ignore
                    }
                },
            });
            hooked++;
            logger.info(TAG, `Hooked ${funcName}`);
        } catch (e) {
            logger.warn(TAG, `Failed to hook ${funcName}: ${e}`);
        }
    }

    if (hooked > 0) {
        sendStrategyStatus(TAG, 'active', `Hooked ${hooked} mmap variants`);
    } else {
        sendStrategyStatus(TAG, 'error', 'Failed to hook any mmap variant');
    }
}
