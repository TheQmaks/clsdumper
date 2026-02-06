import { ArtOffsets, ART_ACCESSOR_SYMBOLS, STATIC_OFFSETS_ARM64, STATIC_OFFSETS_ARM32 } from '../config/offsets.js';
import { logger } from '../utils/logger.js';
import { safeReadPointer, isValidPointer } from '../utils/memoryUtils.js';
import { DEX_MAGIC } from '../config/constants.js';

/**
 * Multi-level ART offset resolver.
 *
 * Priority:
 * 1. Disassemble accessor functions in libart.so
 * 2. Heuristic: scan Runtime struct for ClassLinker*
 * 3. DEX magic probing for DexFile offsets
 * 4. Static offset table (fallback)
 * 5. Graceful skip (return null)
 */
export class OffsetResolver {
    private arch: string;
    private pointerSize: number;
    private libart: Module | null = null;

    constructor() {
        this.arch = Process.arch;
        this.pointerSize = Process.pointerSize;
        this.libart = Process.findModuleByName('libart.so');
    }

    /**
     * Main entry point: resolve ART offsets for the given API level.
     * Returns null if offsets cannot be determined (Strategy 1 should be skipped).
     */
    resolve(apiLevel: number): ArtOffsets | null {
        logger.info('OFFSETS', 'Resolving ART structure offsets...');

        // Level 1: Disassemble accessor functions
        let fromAccessors = this.resolveFromAccessors();

        // Level 1b: If accessor symbols are stripped, try heuristic ClassLinker scan
        if (!fromAccessors || fromAccessors.runtimeClassLinkerOffset === undefined) {
            const runtimePtr = this.getRuntimeInstance();
            if (runtimePtr) {
                const heuristic = this.findClassLinkerHeuristic(runtimePtr);
                if (heuristic) {
                    logger.info('OFFSETS', `Found ClassLinker via heuristic at Runtime+0x${heuristic.classLinkerOffset.toString(16)}, begin_ at DexFile+0x${heuristic.dexFileBeginOffset.toString(16)}`);
                    if (!fromAccessors) fromAccessors = {};
                    fromAccessors.runtimeClassLinkerOffset = heuristic.classLinkerOffset;
                    fromAccessors.dexFileBeginOffset = heuristic.dexFileBeginOffset;
                }
            }
        }

        // Level 2: JNI verification
        if (fromAccessors?.runtimeClassLinkerOffset !== undefined) {
            const runtimePtr = this.getRuntimeInstance();
            if (runtimePtr) {
                const verified = this.verifyViaJNI(runtimePtr);
                if (verified) {
                    logger.info('OFFSETS', 'Offsets verified via JNI anchoring');
                }
            }
        }

        // Level 3: DEX magic probing for DexFile field offsets
        const fromProbing = this.resolveFromDexMagic();

        // Combine accessor + probing results
        const combined = this.combineOffsets(fromAccessors, fromProbing);
        if (combined) {
            logger.info('OFFSETS', 'Offsets resolved via dynamic analysis');
            return combined;
        }

        // Level 4: Static table
        const staticTable = this.arch === 'arm64' ? STATIC_OFFSETS_ARM64 : STATIC_OFFSETS_ARM32;
        const staticOffsets = staticTable[apiLevel];
        if (staticOffsets) {
            logger.info('OFFSETS', `Using static offset table for API ${apiLevel}`);
            const merged = this.combineOffsets(fromAccessors, staticOffsets as Partial<ArtOffsets>);
            if (merged) return merged;
        }

        // Level 5: Skip
        logger.warn('OFFSETS', 'Could not resolve ART offsets — ART Walk strategy will be skipped');
        return null;
    }

    /**
     * Level 1: Disassemble accessor functions to extract field offsets.
     */
    private resolveFromAccessors(): Partial<ArtOffsets> | null {
        const result: Partial<ArtOffsets> = {};
        let found = false;

        const classLinkerOffset = this.resolveOffsetFromAccessor(ART_ACCESSOR_SYMBOLS.getClassLinker);
        if (classLinkerOffset !== null) {
            result.runtimeClassLinkerOffset = classLinkerOffset;
            logger.debug('OFFSETS', `GetClassLinker offset: 0x${classLinkerOffset.toString(16)}`);
            found = true;
        }

        const heapOffset = this.resolveOffsetFromAccessor(ART_ACCESSOR_SYMBOLS.getHeap);
        if (heapOffset !== null) {
            logger.debug('OFFSETS', `GetHeap offset: 0x${heapOffset.toString(16)}`);
        }

        return found ? result : null;
    }

    /**
     * Disassemble a single accessor function to extract the field offset.
     * Handles BTI (Branch Target Identification) on Android 14+.
     */
    private resolveOffsetFromAccessor(funcName: string): number | null {
        if (!this.libart) return null;

        // Try export first, then full symbol table
        let func = this.libart.findExportByName(funcName);
        if (!func) {
            const symbols = this.libart.enumerateSymbols();
            const match = symbols.find(s => s.name === funcName);
            if (match) func = match.address;
        }
        if (!func) {
            logger.debug('OFFSETS', `Symbol not found: ${funcName}`);
            return null;
        }

        try {
            if (this.arch === 'arm64') {
                // Read up to 4 instructions to skip BTI/PAC preamble
                for (let i = 0; i < 4; i++) {
                    const insn = func.add(i * 4).readU32();

                    // Skip BTI instructions: BTI c = 0xd503245f, BTI j = 0xd503249f, BTI jc = 0xd50324df
                    if ((insn & 0xffffff1f) === 0xd503241f) continue;
                    // Skip PAC instructions (PACIASP, PACIBSP, etc.)
                    if ((insn & 0xfffff000) === 0xd503233f) continue;

                    // LDR Xt, [Xn, #imm] — unsigned offset load (F940???? pattern)
                    if ((insn & 0xffc00000) === 0xf9400000) {
                        return ((insn >> 10) & 0xfff) * 8;
                    }
                    // If we hit a non-preamble instruction that's not LDR, stop
                    break;
                }
            } else if (this.arch === 'arm') {
                // ARM32: LDR Rd, [Rn, #imm]
                // Encoding A1: cond 01 I P U 0 W 1 Rn Rd imm12
                // U=1 (add), P=1 (pre-indexed), W=0: mask=0x0f700000, val=0x05900000
                const insn = func.readU32();
                if ((insn & 0x0f700000) === 0x05900000) {
                    return insn & 0xfff;
                }
                // Also handle U=0 (subtract) variant, less common
                if ((insn & 0x0f700000) === 0x05100000) {
                    return -(insn & 0xfff);
                }
            }
        } catch (e) {
            logger.debug('OFFSETS', `Failed to disassemble ${funcName}: ${e}`);
        }

        return null;
    }

    /**
     * Heuristic: scan Runtime struct for ClassLinker*.
     * ClassLinker is heap-allocated, has a vtable in libart.so,
     * and contains a boot_class_path_ vector with DexFile* entries
     * that point to DEX magic.
     */
    private findClassLinkerHeuristic(runtimePtr: NativePointer): { classLinkerOffset: number; dexFileBeginOffset: number } | null {
        if (!this.libart) return null;

        const libBase = this.libart.base;
        const libEnd = libBase.add(this.libart.size);

        // Scan Runtime struct for pointers whose target has a vtable in libart.so
        const candidates: Array<{ offset: number; ptr: NativePointer }> = [];

        for (let offset = 0; offset < 0x800; offset += this.pointerSize) {
            try {
                const val = runtimePtr.add(offset).readPointer();
                if (val.isNull() || val.compare(ptr(0x1000)) <= 0) continue;

                // Check if val's first field (vtable) points into libart.so
                const vtable = val.readPointer();
                if (vtable.compare(libBase) >= 0 && vtable.compare(libEnd) < 0) {
                    candidates.push({ offset, ptr: val });
                }
            } catch {
                continue;
            }
        }

        logger.debug('OFFSETS', `Found ${candidates.length} ClassLinker candidates in Runtime struct`);

        // Verify: ClassLinker contains DexFile pointers somewhere in its struct.
        for (const { offset, ptr: clPtr } of candidates) {
            const beginOffset = this.verifyClassLinkerAndFindBeginOffset(clPtr);
            if (beginOffset !== null) {
                return { classLinkerOffset: offset, dexFileBeginOffset: beginOffset };
            }
        }

        return null;
    }

    /**
     * Verify that a pointer likely points to a ClassLinker object.
     * ClassLinker contains boot_class_path_ (std::vector<const DexFile*>)
     * which has pointers to DexFile structs that contain begin_ → DEX magic.
     * Returns the dexFileBeginOffset if found, null otherwise.
     */
    private verifyClassLinkerAndFindBeginOffset(clPtr: NativePointer): number | null {
        // Scan the ClassLinker struct for a std::vector<DexFile*>
        // A vector has {begin, end, capacity} — three consecutive pointers
        // where begin < end, and dereferencing elements gives valid DexFile*
        for (let off = 0; off < 0x400; off += this.pointerSize) {
            try {
                const begin = clPtr.add(off).readPointer();
                const end = clPtr.add(off + this.pointerSize).readPointer();

                if (begin.isNull() || end.isNull()) continue;
                if (begin.compare(end) >= 0) continue;

                // Calculate element count
                const size = end.sub(begin).toInt32();
                const elemCount = size / this.pointerSize;
                if (elemCount < 1 || elemCount > 500) continue;

                // Check if the first element looks like a DexFile* → begin_ → DEX magic
                const firstElem = begin.readPointer();
                if (firstElem.isNull()) continue;

                // Scan first few fields of the potential DexFile for a pointer to DEX magic
                for (let dOff = 0; dOff < 64; dOff += this.pointerSize) {
                    try {
                        const candidate = firstElem.add(dOff).readPointer();
                        if (candidate.isNull()) continue;
                        if (candidate.readU32() === DEX_MAGIC) {
                            logger.debug('OFFSETS', `ClassLinker verified: boot_class_path_ at CL+0x${off.toString(16)}, DexFile::begin_ at +0x${dOff.toString(16)}`);
                            return dOff; // This is the dexFileBeginOffset
                        }
                    } catch {
                        continue;
                    }
                }
            } catch {
                continue;
            }
        }
        return null;
    }

    /**
     * Get the art::Runtime::instance_ pointer.
     */
    getRuntimeInstance(): NativePointer | null {
        if (!this.libart) {
            logger.debug('OFFSETS', 'libart.so not found');
            return null;
        }
        const sym = this.libart.findExportByName(ART_ACCESSOR_SYMBOLS.runtimeInstance);
        if (!sym) {
            logger.debug('OFFSETS', 'Runtime::instance_ not found');
            return null;
        }

        try {
            const runtimePtr = sym.readPointer();
            if (isValidPointer(runtimePtr)) {
                return runtimePtr;
            }
        } catch (e) {
            logger.debug('OFFSETS', `Failed to read Runtime::instance_: ${e}`);
        }
        return null;
    }

    /**
     * Level 2: Verify offsets by finding JavaVM* in Runtime struct.
     */
    private verifyViaJNI(runtimePtr: NativePointer): boolean {
        try {
            // Use the GetJavaVM accessor to cross-validate offsets
            const javaVmOffset = this.resolveOffsetFromAccessor(ART_ACCESSOR_SYMBOLS.getJavaVM);
            if (javaVmOffset !== null) {
                const javaVm = safeReadPointer(runtimePtr.add(javaVmOffset));
                if (javaVm && isValidPointer(javaVm)) {
                    // Verify it looks like a JavaVM (first field is JNI function table pointer)
                    try {
                        const fnTable = javaVm.readPointer();
                        if (isValidPointer(fnTable)) {
                            logger.debug('OFFSETS', `Verified java_vm_ at Runtime+0x${javaVmOffset.toString(16)}`);
                            return true;
                        }
                    } catch {
                        // Not a valid pointer — verification failed
                    }
                }
            }
        } catch (e) {
            logger.debug('OFFSETS', `JNI verification failed: ${e}`);
        }
        return false;
    }

    /**
     * Level 3: Find DexFile::begin_ offset by probing for DEX magic.
     */
    resolveFromDexMagic(): Partial<ArtOffsets> | null {
        return null;
    }

    /**
     * Probe a native DexFile pointer to find begin_ offset.
     * Called by cookie strategy when it has a real DexFile*.
     */
    probeDexFileOffsets(nativeDexFilePtr: NativePointer): Partial<ArtOffsets> | null {
        const result: Partial<ArtOffsets> = {};

        for (let offset = 0; offset < 256; offset += this.pointerSize) {
            try {
                const candidate = nativeDexFilePtr.add(offset).readPointer();
                if (candidate.isNull()) continue;
                const magic = candidate.readU32();
                if (magic === DEX_MAGIC) {
                    result.dexFileBeginOffset = offset;
                    logger.debug('OFFSETS', `Found DexFile::begin_ at offset 0x${offset.toString(16)}`);
                    return result;
                }
            } catch {
                continue;
            }
        }
        return null;
    }

    /**
     * Combine two partial offset objects into a full ArtOffsets if possible.
     */
    private combineOffsets(a: Partial<ArtOffsets> | null, b: Partial<ArtOffsets> | null): ArtOffsets | null {
        if (!a && !b) return null;

        const merged: Partial<ArtOffsets> = { ...b, ...a };

        // Minimum required fields for ART walk
        if (
            merged.runtimeClassLinkerOffset !== undefined &&
            merged.dexFileBeginOffset !== undefined
        ) {
            return {
                runtimeClassLinkerOffset: merged.runtimeClassLinkerOffset,
                classLinkerDexCachesOffset: merged.classLinkerDexCachesOffset ?? 0,
                classLinkerBootClassPathOffset: merged.classLinkerBootClassPathOffset ?? 0,
                dexCacheDataDexFileOffset: merged.dexCacheDataDexFileOffset ?? 0,
                dexCacheDataSize: merged.dexCacheDataSize ?? (this.pointerSize * 4),
                dexFileBeginOffset: merged.dexFileBeginOffset,
                dexFileSizeOffset: merged.dexFileSizeOffset ?? (merged.dexFileBeginOffset + this.pointerSize),
                dexFileLocationOffset: merged.dexFileLocationOffset ?? 0,
                cookieFirstDexOffset: merged.cookieFirstDexOffset ?? 1,
            };
        }

        return null;
    }
}
