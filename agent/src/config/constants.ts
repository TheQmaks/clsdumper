export const DEX_MAGIC = 0x0a786564; // "dex\n" little-endian
export const CDEX_MAGIC = 0x78656463; // "cdex" little-endian (63 64 65 78)
export const CDEX_MAGIC_BYTES = '63 64 65 78'; // "cdex"
export const DEX_MAGIC_BYTES = '64 65 78 0a'; // "dex\n"

export const DEX_HEADER_SIZE = 0x70;
export const DEX_ENDIAN_CONSTANT = 0x12345678;
export const DEX_REVERSE_ENDIAN = 0x78563412;

export const DEX_FILE_SIZE_OFFSET = 0x20;
export const DEX_HEADER_SIZE_OFFSET = 0x24;
export const DEX_ENDIAN_TAG_OFFSET = 0x28;

export const MAX_DEX_SIZE = 100 * 1024 * 1024; // 100 MB max DEX size
export const MIN_DEX_SIZE = 0x70; // At least header size

export const CHUNK_SIZE = 4 * 1024 * 1024; // 4 MB chunks for large DEX transfer
export const SCAN_BATCH_SIZE = 50; // Memory ranges to scan per batch
export const SCAN_DELAY_MS = 10; // Delay between scan batches to avoid ANR

export const OFFSET_SEARCH_MAX = 1024; // Max bytes to search for offsets
export const OFFSET_SEARCH_STEP = 4; // Step size for pointer-aligned search (overridden by pointerSize)

export const STRATEGY_NAMES = {
    ART_WALK: 'art_walk',
    OPEN_COMMON_HOOK: 'open_common_hook',
    MEMORY_SCAN: 'memory_scan',
    COOKIE: 'cookie',
    CLASSLOADER_HOOK: 'classloader_hook',
    MMAP_HOOK: 'mmap_hook',
    OAT_EXTRACT: 'oat_extract',
    FART_DUMP: 'fart_dump',
    DEXFILE_CONSTRUCTOR: 'dexfile_constructor',
} as const;

export type StrategyName = typeof STRATEGY_NAMES[keyof typeof STRATEGY_NAMES];
