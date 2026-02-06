import {
    DEX_MAGIC,
    DEX_FILE_SIZE_OFFSET,
    DEX_HEADER_SIZE_OFFSET,
    DEX_ENDIAN_TAG_OFFSET,
    DEX_HEADER_SIZE,
    DEX_ENDIAN_CONSTANT,
    MAX_DEX_SIZE,
    MIN_DEX_SIZE,
} from '../config/constants.js';

/**
 * Validate that a memory address points to a valid DEX file.
 * Returns the file size if valid, or 0 if invalid.
 */
export function validateDexHeader(address: NativePointer): number {
    try {
        const magic = address.readU32();
        if (magic !== DEX_MAGIC) return 0;

        const fileSize = address.add(DEX_FILE_SIZE_OFFSET).readU32();
        const headerSize = address.add(DEX_HEADER_SIZE_OFFSET).readU32();
        const endianTag = address.add(DEX_ENDIAN_TAG_OFFSET).readU32();

        if (headerSize !== DEX_HEADER_SIZE) return 0;
        if (endianTag !== DEX_ENDIAN_CONSTANT) return 0;
        if (fileSize < MIN_DEX_SIZE || fileSize > MAX_DEX_SIZE) return 0;

        return fileSize;
    } catch {
        return 0;
    }
}

/**
 * Safely read DEX bytes from memory.
 * Returns null if read fails.
 */
export function readDexBytes(address: NativePointer, size: number): ArrayBuffer | null {
    try {
        return address.readByteArray(size);
    } catch {
        return null;
    }
}

/**
 * Read a pointer safely, returning null on failure.
 */
export function safeReadPointer(address: NativePointer): NativePointer | null {
    try {
        return address.readPointer();
    } catch {
        return null;
    }
}

/**
 * Read a U32 safely, returning null on failure.
 */
export function safeReadU32(address: NativePointer): number | null {
    try {
        return address.readU32();
    } catch {
        return null;
    }
}

/**
 * Read a U64 safely (as a number — may lose precision for very large values).
 */
export function safeReadU64(address: NativePointer): UInt64 | null {
    try {
        return address.readU64();
    } catch {
        return null;
    }
}

/**
 * Check if a pointer is likely valid (non-null, not sentinel, aligned).
 */
export function isValidPointer(p: NativePointer): boolean {
    if (p.isNull()) return false;
    // Check for common sentinel values on both arm32 and arm64
    if (p.compare(ptr('0xffffffffffffffff')) === 0) return false;
    if (p.compare(ptr('0xffffffff')) === 0) return false;
    // Check pointer alignment
    if (!p.and(Process.pointerSize - 1).isNull()) return false;
    return true;
}

/**
 * Get the size of a DEX file from its begin_ pointer (reads file_size from header).
 */
export function getDexSizeFromBegin(beginPtr: NativePointer): number {
    return validateDexHeader(beginPtr);
}
