/**
 * Static ART structure offsets per Android API level.
 * These are fallback values derived from AOSP source code.
 * The OffsetResolver will try dynamic resolution first.
 *
 * NOTE: dexFileBeginOffset is resolved dynamically via three methods:
 * - Level 1b: ClassLinker heuristic (Runtime → ClassLinker → DexFile → begin_)
 * - Level 3: Memory probing (finds DEX in memory, searches for DexFile structs)
 * - Cookie strategy: probes DexFile* from mCookie at runtime
 * Hardcoding it here is unsafe as it varies across OEM builds.
 */

export interface ArtOffsets {
    /** Offset of ClassLinker* in art::Runtime */
    runtimeClassLinkerOffset: number;
    /** Offset of dex_caches_ in art::ClassLinker */
    classLinkerDexCachesOffset: number;
    /** Offset of boot_class_path_ in art::ClassLinker (std::vector<const DexFile*>) */
    classLinkerBootClassPathOffset: number;
    /** Offset of dex_file in DexCacheData struct */
    dexCacheDataDexFileOffset: number;
    /** Size of one DexCacheData element */
    dexCacheDataSize: number;
    /** Offset of begin_ in art::DexFile (pointer to raw DEX bytes) */
    dexFileBeginOffset: number;
    /** Offset of size_ in art::DexFile */
    dexFileSizeOffset: number;
    /** Offset of location_ (std::string) in art::DexFile */
    dexFileLocationOffset: number;
    /** Index of first DexFile* in mCookie long[] (usually 1, index 0 is oat_file) */
    cookieFirstDexOffset: number;
}

/**
 * Static offset table. Keys are Android API levels.
 * Only includes offsets we are confident about from AOSP.
 * dexFileBeginOffset is intentionally omitted — resolved dynamically.
 */
export const STATIC_OFFSETS_ARM64: Record<number, Partial<ArtOffsets>> = {
    26: { cookieFirstDexOffset: 1 },
    27: { cookieFirstDexOffset: 1 },
    28: { cookieFirstDexOffset: 1 },
    29: { cookieFirstDexOffset: 1 },
    30: { cookieFirstDexOffset: 1 },
    31: { cookieFirstDexOffset: 1 },
    32: { cookieFirstDexOffset: 1 },
    33: { cookieFirstDexOffset: 1 },
    34: { cookieFirstDexOffset: 1 },
    35: { cookieFirstDexOffset: 1 },
};

export const STATIC_OFFSETS_ARM32: Record<number, Partial<ArtOffsets>> = {
    26: { cookieFirstDexOffset: 1 },
    27: { cookieFirstDexOffset: 1 },
    28: { cookieFirstDexOffset: 1 },
    29: { cookieFirstDexOffset: 1 },
    30: { cookieFirstDexOffset: 1 },
    31: { cookieFirstDexOffset: 1 },
    32: { cookieFirstDexOffset: 1 },
    33: { cookieFirstDexOffset: 1 },
    34: { cookieFirstDexOffset: 1 },
    35: { cookieFirstDexOffset: 1 },
};

/** Accessor function names in libart.so for offset extraction */
export const ART_ACCESSOR_SYMBOLS = {
    getClassLinker: '_ZNK3art7Runtime14GetClassLinkerEv',
    getJavaVM: '_ZNK3art7Runtime10GetJavaVMEv',
    getHeap: '_ZNK3art7Runtime7GetHeapEv',
    runtimeInstance: '_ZN3art7Runtime9instance_E',
} as const;
