import { logger } from '../utils/logger.js';

/**
 * Anti-Frida bypass module.
 *
 * Patches common anti-tampering techniques:
 * 1. SIGILL/SIGTRAP handler hijacking — prevents signal handler registration
 * 2. /proc/self/maps filtering — replaces fd with filtered memfd (zero hot-path overhead)
 * 3. pthread_create monitoring — neutralizes watchdog threads from known libraries
 *
 * Key design: maps filtering does NOT hook read()/close()/fgets()/fclose().
 * Instead, it replaces the returned fd in open()/openat()/fopen() with a memfd
 * containing pre-filtered content. This eliminates all hot-path overhead that
 * caused crashes on apps like Facebook.
 *
 * Must be called BEFORE any strategy hooks are installed.
 */

const TAG = 'ANTI-FRIDA';

// Signal constants
const SIGILL = 4;
const SIGTRAP = 5;
const SIG_DFL = ptr(0);
// Block SIGILL and SIGTRAP handler registration. SIGILL handlers from app code
// (dalvik-internals, sigmux, etc.) detect Frida's inline hooks.
// Note: blocking SIGILL means Java bridge calls that trigger SIGILL will
// terminate the process (SIG_DFL). This is acceptable — native strategies
// complete before Java phase, and the crash is handled gracefully.
const PROTECTED_SIGNALS = [SIGILL, SIGTRAP];

export function installAntiFridaBypass(): void {
    logger.info(TAG, 'Installing anti-frida bypass...');

    let bypassed = 0;

    bypassed += patchSignalHandlers();
    bypassed += patchProcMaps();
    bypassed += patchPthreadCreate();

    logger.info(TAG, `Anti-frida bypass installed (${bypassed} patches)`);
}

/**
 * Patch 1: Prevent apps from registering custom SIGILL/SIGTRAP handlers.
 *
 * Apps register a SIGILL handler that detects Frida's inline hooks
 * (which can cause illegal instruction when tamper-checked).
 * We intercept sigaction() and block handler registration for these signals.
 */
function patchSignalHandlers(): number {
    const libc = Process.findModuleByName('libc.so');
    if (!libc) return 0;

    let patched = 0;

    const sigactionAddr = libc.findExportByName('sigaction');
    if (sigactionAddr) {
        try {
            Interceptor.attach(sigactionAddr, {
                onEnter(args) {
                    const signum = args[0].toInt32();
                    if (PROTECTED_SIGNALS.includes(signum)) {
                        logger.debug(TAG, `Blocked sigaction for signal ${signum}`);
                        const actPtr = args[1];
                        if (!actPtr.isNull()) {
                            try {
                                actPtr.writePointer(SIG_DFL);
                                const flagsOffset = Process.arch === 'arm64' ? (8 + 128) : 4;
                                try {
                                    const flags = actPtr.add(flagsOffset).readU32();
                                    actPtr.add(flagsOffset).writeU32(flags & ~0x4);
                                } catch {
                                    // Flags write failed — handler replacement alone is sufficient
                                }
                            } catch {
                                // If we can't write, skip
                            }
                        }
                    }
                },
            });
            patched++;
            logger.debug(TAG, 'Hooked sigaction');
        } catch (e) {
            logger.debug(TAG, `Failed to hook sigaction: ${e}`);
        }
    }

    const signalAddr = libc.findExportByName('signal');
    if (signalAddr) {
        try {
            Interceptor.attach(signalAddr, {
                onEnter(args) {
                    const signum = args[0].toInt32();
                    if (PROTECTED_SIGNALS.includes(signum)) {
                        logger.debug(TAG, `Blocked signal() for signal ${signum}`);
                        args[1] = SIG_DFL;
                    }
                },
            });
            patched++;
            logger.debug(TAG, 'Hooked signal()');
        } catch (e) {
            logger.debug(TAG, `Failed to hook signal: ${e}`);
        }
    }

    return patched;
}

/**
 * Patch 2: Filter /proc/self/maps to hide Frida traces.
 *
 * APPROACH: memfd replacement (zero hot-path overhead).
 *
 * Instead of hooking read()/fgets() (called millions of times per second),
 * we intercept open()/openat()/fopen() and replace the returned fd/FILE*
 * with a memfd containing pre-filtered content.
 *
 * Flow:
 *   1. App calls open("/proc/self/maps") → returns real fd
 *   2. In onLeave, we read all content from real fd via NativeFunction
 *   3. Filter out frida-related lines
 *   4. Create memfd via memfd_create (or syscall fallback)
 *   5. Write filtered content to memfd, lseek to 0
 *   6. Close real fd, replace retval with memfd
 *   7. App reads from memfd — sees filtered content, no frida traces
 *
 * This approach hooks ONLY open/openat/fopen (rare calls) and avoids
 * hooking read/close/fgets/fclose (extremely hot paths).
 */
function patchProcMaps(): number {
    const libc = Process.findModuleByName('libc.so');
    if (!libc) return 0;

    let patched = 0;

    const fridaPatterns = ['frida', 'gmain', 'gdbus', 'gum-js-loop', 'linjector'];

    const isMapsPath = (path: string): boolean => {
        return /\/proc\/(self|\d+)\/(maps|smaps)/.test(path);
    };

    // ── Resolve native functions (cached at init, NOT in hot path) ──

    const readAddr = libc.findExportByName('read');
    const writeAddr = libc.findExportByName('write');
    const closeAddr = libc.findExportByName('close');
    const lseekAddr = libc.findExportByName('lseek');

    if (!readAddr || !writeAddr || !closeAddr || !lseekAddr) {
        logger.warn(TAG, 'Missing libc functions for maps filtering');
        return 0;
    }

    const readNative = new NativeFunction(readAddr, 'int', ['int', 'pointer', 'int']);
    const writeNative = new NativeFunction(writeAddr, 'int', ['int', 'pointer', 'int']);
    const closeNative = new NativeFunction(closeAddr, 'int', ['int']);
    const lseekNative = new NativeFunction(lseekAddr, 'int', ['int', 'int', 'int']);

    // For fopen() → fdopen() replacement
    const filenoAddr = libc.findExportByName('fileno');
    const fdopenAddr = libc.findExportByName('fdopen');
    const fcloseAddr = libc.findExportByName('fclose');

    const filenoNative = filenoAddr
        ? new NativeFunction(filenoAddr, 'int', ['pointer'])
        : null;
    const fdopenNative = fdopenAddr
        ? new NativeFunction(fdopenAddr, 'pointer', ['int', 'pointer'])
        : null;
    const fcloseNative = fcloseAddr
        ? new NativeFunction(fcloseAddr, 'int', ['pointer'])
        : null;

    // ── Resolve memfd_create ──

    let memfdCreateFn: (() => number) | null = null;
    const memfdName = Memory.allocUtf8String('m');

    // Try libc wrapper first (Android 11+ / API 30+)
    const memfdLibcAddr = libc.findExportByName('memfd_create');
    if (memfdLibcAddr) {
        const nf = new NativeFunction(memfdLibcAddr, 'int', ['pointer', 'uint']);
        memfdCreateFn = () => nf(memfdName, 0) as number;
        logger.debug(TAG, 'Using memfd_create libc wrapper');
    } else {
        // Fallback: raw syscall (Linux 3.17+, available on all supported Android versions)
        const syscallAddr = libc.findExportByName('syscall');
        if (syscallAddr) {
            const SYS_memfd_create = Process.arch === 'arm64' ? 279 : 385;
            const nf = new NativeFunction(syscallAddr, 'int', ['int', 'pointer', 'uint']);
            memfdCreateFn = () => nf(SYS_memfd_create, memfdName, 0) as number;
            logger.debug(TAG, 'Using memfd_create via syscall');
        }
    }

    if (!memfdCreateFn) {
        logger.warn(TAG, 'memfd_create unavailable, maps filtering disabled');
        return 0;
    }

    // Pre-allocated constants
    const rMode = Memory.allocUtf8String('r');

    // ── Helper: read entire fd contents into string ──

    function readAllFromFd(fd: number): string {
        const BUF_SIZE = 256 * 1024;
        const buf = Memory.alloc(BUF_SIZE);
        let content = '';
        while (true) {
            const n = readNative(fd, buf, BUF_SIZE) as number;
            if (n <= 0) break;
            content += buf.readUtf8String(n);
        }
        return content;
    }

    // ── Helper: create memfd with filtered maps content ──

    function createFilteredMemfd(content: string): number {
        const filtered = content.split('\n')
            .filter(line => {
                if (line.length === 0) return true;
                const lower = line.toLowerCase();
                return !fridaPatterns.some(p => lower.includes(p));
            })
            .join('\n');

        const memfd = memfdCreateFn!();
        if (memfd < 0) return -1;

        if (filtered.length > 0) {
            const filteredBuf = Memory.allocUtf8String(filtered);
            // Find actual UTF-8 byte length by scanning for null terminator
            // (maps content is ASCII so length == byteLen, but be safe)
            let byteLen = 0;
            while (byteLen < filtered.length * 4) {
                if (filteredBuf.add(byteLen).readU8() === 0) break;
                byteLen++;
            }
            let written = 0;
            while (written < byteLen) {
                const w = writeNative(memfd, filteredBuf.add(written),
                    byteLen - written) as number;
                if (w <= 0) break;
                written += w;
            }
        }

        lseekNative(memfd, 0, 0); // SEEK_SET
        return memfd;
    }

    // ── Helper: replace fd retval with filtered memfd ──

    function replaceFdRetval(retval: InvocationReturnValue): void {
        const realFd = retval.toInt32();
        if (realFd < 0) return;

        try {
            const content = readAllFromFd(realFd);
            const memfd = createFilteredMemfd(content);
            if (memfd >= 0) {
                closeNative(realFd);
                retval.replace(ptr(memfd));
            } else {
                // memfd failed — rewind real fd so caller can still read (unfiltered)
                lseekNative(realFd, 0, 0);
            }
        } catch {
            // On error, rewind real fd so caller can still read
            try { lseekNative(realFd, 0, 0); } catch { /* ignore */ }
        }
    }

    // ── Hook open() ──

    const openHookAddr = libc.findExportByName('open');
    if (openHookAddr) {
        try {
            Interceptor.attach(openHookAddr, {
                onEnter(args) {
                    try {
                        const path = args[0].readCString();
                        if (path && isMapsPath(path)) this.isMaps = true;
                    } catch { /* ignore */ }
                },
                onLeave(retval) {
                    if (this.isMaps) replaceFdRetval(retval);
                },
            });
            patched++;
        } catch (e) {
            logger.debug(TAG, `Failed to hook open: ${e}`);
        }
    }

    // ── Hook openat() (preferred on newer Android) ──

    const openatHookAddr = libc.findExportByName('openat');
    if (openatHookAddr) {
        try {
            Interceptor.attach(openatHookAddr, {
                onEnter(args) {
                    try {
                        const path = args[1].readCString(); // openat: path is args[1]
                        if (path && isMapsPath(path)) this.isMaps = true;
                    } catch { /* ignore */ }
                },
                onLeave(retval) {
                    if (this.isMaps) replaceFdRetval(retval);
                },
            });
            patched++;
        } catch (e) {
            logger.debug(TAG, `Failed to hook openat: ${e}`);
        }
    }

    // ── Hook fopen() ──

    if (filenoNative && fdopenNative && fcloseNative) {
        const fopenHookAddr = libc.findExportByName('fopen');
        if (fopenHookAddr) {
            try {
                Interceptor.attach(fopenHookAddr, {
                    onEnter(args) {
                        try {
                            const path = args[0].readCString();
                            if (path && isMapsPath(path)) this.isMaps = true;
                        } catch { /* ignore */ }
                    },
                    onLeave(retval) {
                        if (!this.isMaps || retval.isNull()) return;

                        try {
                            // Get underlying fd from FILE* (buffer is empty, just opened)
                            const realFd = filenoNative!(retval) as number;
                            if (realFd < 0) return;

                            // Read content via raw fd
                            const content = readAllFromFd(realFd);

                            // Create filtered memfd
                            const memfd = createFilteredMemfd(content);
                            if (memfd < 0) {
                                lseekNative(realFd, 0, 0);
                                return;
                            }

                            // Wrap memfd as FILE*
                            const newFile = fdopenNative!(memfd, rMode) as NativePointer;
                            if (newFile.isNull()) {
                                closeNative(memfd);
                                lseekNative(realFd, 0, 0);
                                return;
                            }

                            // Success: close original FILE* and replace retval
                            fcloseNative!(retval);
                            retval.replace(newFile);
                        } catch {
                            // On error, try to rewind so caller can still read
                            try {
                                const fd = filenoNative!(retval) as number;
                                if (fd >= 0) lseekNative(fd, 0, 0);
                            } catch { /* ignore */ }
                        }
                    },
                });
                patched++;
            } catch (e) {
                logger.debug(TAG, `Failed to hook fopen: ${e}`);
            }
        }
    }

    if (patched > 0) {
        logger.debug(TAG, `Maps filtering active (${patched} hooks, memfd-based)`);
    }

    return patched;
}

/**
 * Patch 3: Monitor pthread_create for suspicious watchdog threads.
 *
 * Some apps create dedicated threads that continuously scan for Frida.
 * We detect these by looking at start routines from known anti-frida libraries.
 */
function patchPthreadCreate(): number {
    const libc = Process.findModuleByName('libc.so');
    if (!libc) return 0;

    const suspiciousModules = ['libcoldstart.so', 'libliger.so', 'libsec.so', 'libprotect.so'];

    const pthreadCreateAddr = libc.findExportByName('pthread_create');
    if (!pthreadCreateAddr) return 0;

    // Pre-allocate noop function (avoid hot-path allocation)
    let noopFunc: NativePointer | null = null;
    try {
        const noop = Memory.alloc(Process.pageSize);
        if (Process.arch === 'arm64') {
            noop.writeU32(0xd65f03c0); // ret
        } else if (Process.arch === 'arm') {
            noop.writeU32(0xe12fff1e); // bx lr
        }
        Memory.protect(noop, Process.pageSize, 'r-x');

        // Flush instruction cache for ARM (critical for correctness)
        const cacheflushAddr = libc.findExportByName('cacheflush');
        if (cacheflushAddr) {
            const cacheflush = new NativeFunction(cacheflushAddr, 'int', ['pointer', 'pointer', 'int']);
            cacheflush(noop, noop.add(4), 0);
        }

        noopFunc = noop;
    } catch (e) {
        logger.debug(TAG, `Failed to create noop function: ${e}`);
        return 0;
    }

    try {
        Interceptor.attach(pthreadCreateAddr, {
            onEnter(args) {
                const startRoutine = args[2];
                if (startRoutine.isNull()) return;

                try {
                    const mod = Process.findModuleByAddress(startRoutine);
                    if (mod && suspiciousModules.some(s => mod.name.includes(s))) {
                        logger.info(TAG, `Neutralized watchdog thread from ${mod.name}`);
                        if (noopFunc) {
                            args[2] = noopFunc;
                        }
                    }
                } catch {
                    // Can't determine module — let it through
                }
            },
        });

        logger.debug(TAG, 'Hooked pthread_create');
        return 1;
    } catch (e) {
        logger.debug(TAG, `Failed to hook pthread_create: ${e}`);
        return 0;
    }
}
