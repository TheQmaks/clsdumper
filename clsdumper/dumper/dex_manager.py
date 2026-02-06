"""Manages DEX file storage and metadata."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

from clsdumper.utils.logging import Logger


@dataclass
class DexFileInfo:
    """Metadata for a dumped DEX file."""

    filename: str
    sha256: str
    size: int
    strategy: str
    address: str = ""
    loader: str = ""
    path: str = ""
    location: str = ""
    class_count: int = 0


class DexDumpManager:
    """Manages saving DEX files to disk with deduplication."""

    def __init__(self, output_dir: Path, logger: Logger) -> None:
        self.output_dir = output_dir
        self.dex_dir = output_dir / "dex"
        self.logger = logger
        self._files: list[DexFileInfo] = []
        self._hashes: set[str] = set()
        self._name_counter = 0

        # Ensure output directories exist
        self.dex_dir.mkdir(parents=True, exist_ok=True)

    @property
    def files(self) -> list[DexFileInfo]:
        return list(self._files)

    @property
    def count(self) -> int:
        return len(self._files)

    @property
    def total_bytes(self) -> int:
        return sum(f.size for f in self._files)

    def save_dex(self, payload: dict, data: bytes) -> DexFileInfo | None:
        """Save a DEX file to disk. Returns info or None if duplicate."""
        sha256 = payload.get("sha256") or hashlib.sha256(data).hexdigest()
        if sha256 in self._hashes:
            return None
        self._hashes.add(sha256)

        filename = self._generate_filename(payload, sha256)
        filepath = self.dex_dir / filename

        filepath.write_bytes(data)

        info = DexFileInfo(
            filename=filename,
            sha256=sha256,
            size=len(data),
            strategy=payload.get("strategy", "unknown"),
            address=payload.get("address", ""),
            loader=payload.get("loader", ""),
            path=payload.get("path", ""),
            location=payload.get("location", ""),
        )
        self._files.append(info)

        self.logger.debug("DUMP", f"Saved {filename} ({len(data)} bytes)")
        return info

    def save_metadata(self) -> None:
        """Write metadata.json to the output directory."""
        metadata = {
            "version": "0.1.0",
            "dex_files": [
                {
                    "filename": f.filename,
                    "sha256": f.sha256,
                    "size": f.size,
                    "strategy": f.strategy,
                    "address": f.address,
                    "loader": f.loader,
                    "path": f.path,
                    "location": f.location,
                    "class_count": f.class_count,
                }
                for f in self._files
            ],
            "total_dex_files": len(self._files),
            "total_bytes": self.total_bytes,
        }
        meta_path = self.output_dir / "metadata.json"
        meta_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
        self.logger.debug("DUMP", f"Metadata saved to {meta_path}")

    @staticmethod
    def _safe_filename(name: str) -> str:
        """Sanitize a string for use as a filename."""
        import re
        # Remove or replace characters that are unsafe in filenames
        name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', name)
        # Collapse multiple underscores
        name = re.sub(r'_+', '_', name).strip('_')
        return name[:100] if name else 'unknown'

    def _generate_filename(self, payload: dict, sha256: str) -> str:
        """Generate a descriptive filename for a DEX file."""
        strategy = payload.get("strategy", "")
        location = payload.get("location", "")
        loader = payload.get("loader", "")
        short_hash = sha256[:8]

        # Try to derive a meaningful name
        if location:
            # Extract base name from location (e.g., /data/app/.../base.apk!classes.dex)
            name = location.split("/")[-1].split("!")[-1]
            if name.endswith(".dex"):
                name = name[:-4]
            name = self._safe_filename(name)
            return f"{name}_{short_hash}.dex"

        if "InMemory" in loader or strategy == "classloader_hook":
            return f"inmemory_{short_hash}.dex"

        if "DexClassLoader" in loader:
            return f"dynamic_{short_hash}.dex"

        # Default: sequential naming
        self._name_counter += 1
        if self._name_counter <= 1:
            return f"classes_{short_hash}.dex"
        return f"classes{self._name_counter}_{short_hash}.dex"
