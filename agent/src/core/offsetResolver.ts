import { ArtOffsets, ART_ACCESSOR_SYMBOLS, STATIC_OFFSETS_ARM64, STATIC_OFFSETS_ARM32 } from '../config/offsets.js';
import { logger } from '../utils/logger.js';
import { safeReadPointer, isValidPointer, validateDexHeader } from '../utils/memoryUtils.js';
import { DEX_MAGIC, DEX_MAGIC_BYTES } from '../config/constants.js';

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
     * Level 3: Find DexFile::begin_ offset by scanning memory for DEX magic.
     *
     * Bottom-up approach (unlike Level 1b which goes top-down from Runtime):
     * 1. Find a standard DEX file in mapped regions (APK/VDEX/OAT) or anonymous memory
     * 2. Scan process memory for pointers to that DEX address (these are begin_ fields)
     * 3. Verify each candidate by checking that the adjacent field matches file size
     * 4. Determine offset within the DexFile struct via probeDexFileOffsets()
     */
    resolveFromDexMagic(): Partial<ArtOffsets> | null {
        logger.debug('OFFSETS', 'Level 3: Probing for DexFile::begin_ via memory scan...');

        // Step 1: Find a standard DEX file in memory
        const dexInfo = this.findDexInMemory();
        if (!dexInfo) {
            logger.debug('OFFSETS', 'Level 3: No standard DEX files found in memory');
            return null;
        }

        logger.debug('OFFSETS', `Level 3: Found DEX at ${dexInfo.address} (${dexInfo.fileSize} bytes)`);

        // Step 2: Build a scan pattern for the pointer value (little-endian bytes)
        const ptrPattern = this.pointerToScanPattern(dexInfo.address);

        // Step 3: Scan readable memory for this pointer value.
        // DexFile structs are heap-allocated or in libart.so .data/.bss sections.
        const ranges = Process.enumerateRanges('r--');
        for (const range of ranges) {
            if (range.size < this.pointerSize * 4 || range.size > 64 * 1024 * 1024) continue;

            let matches: MemoryScanMatch[];
            try {
                matches = Memory.scanSync(range.base, range.size, ptrPattern);
            } catch {
                continue;
            }

            for (const m of matches) {
                // m.address holds a pointer to our DEX bytes.
                // Verify: the next pointer-sized field should be size_t matching file size.
                try {
                    const sizeVal = this.pointerSize === 8
                        ? m.address.add(this.pointerSize).readU64().toNumber()
                        : m.address.add(this.pointerSize).readU32();
                    if (sizeVal !== dexInfo.fileSize) continue;
                } catch {
                    continue;
                }

                // Confirmed begin_/size_ pair. Find struct base by probing backwards.
                // Start from pointerSize: offset 0 is always the vtable pointer
                // (DexFile has virtual ~DexFile()), and off=0 would tautologically
                // match the pointer we already found.
                for (let off = this.pointerSize; off <= 64; off += this.pointerSize) {
                    try {
                        const candidateBase = m.address.sub(off);
                        const probed = this.probeDexFileOffsets(candidateBase);
                        if (probed && probed.dexFileBeginOffset === off) {
                            logger.info('OFFSETS', `Level 3: DexFile::begin_ at +0x${off.toString(16)}`);
                            return probed;
                        }
                    } catch {
                        continue;
                    }
                }
            }
        }

        logger.debug('OFFSETS', 'Level 3: Could not determine DexFile::begin_ offset');
        return null;
    }

    /**
     * Find a standard DEX file in process memory.
     * Scans mapped files first (.apk, .jar, .vdex, .oat), then anonymous regions.
     */
    private findDexInMemory(): { address: NativePointer; fileSize: number } | null {
        const ranges = Process.enumerateRanges('r--');
        const fileExts = ['.apk', '.jar', '.vdex', '.oat'];

        // Phase 1: Scan file-backed regions (fast — boot classpath is always present)
        for (const range of ranges) {
            if (range.size < 0x70 || range.size > 64 * 1024 * 1024) continue;
            const path = range.file?.path;
            if (!path || !fileExts.some(ext => path.endsWith(ext))) continue;

            try {
                const matches = Memory.scanSync(range.base, range.size, DEX_MAGIC_BYTES);
                for (const match of matches) {
                    const fileSize = validateDexHeader(match.address);
                    if (fileSize > 0) return { address: match.address, fileSize };
                }
            } catch {
                continue;
            }
        }

        // Phase 2: Scan anonymous regions (catches packed/decrypted DEX in memory)
        for (const range of ranges) {
            if (range.size < 0x70 || range.size > 8 * 1024 * 1024) continue;
            if (range.file?.path) continue;

            try {
                const matches = Memory.scanSync(range.base, range.size, DEX_MAGIC_BYTES);
                for (const match of matches) {
                    const fileSize = validateDexHeader(match.address);
                    if (fileSize > 0) return { address: match.address, fileSize };
                }
            } catch {
                continue;
            }
        }

        return null;
    }

    /**
     * Convert a NativePointer value to a hex pattern for Memory.scanSync.
     * Writes the pointer in native byte order (little-endian on ARM).
     */
    private pointerToScanPattern(p: NativePointer): string {
        const buf = Memory.alloc(this.pointerSize);
        buf.writePointer(p);
        const parts: string[] = [];
        for (let i = 0; i < this.pointerSize; i++) {
            parts.push(buf.add(i).readU8().toString(16).padStart(2, '0'));
        }
        return parts.join(' ');
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
