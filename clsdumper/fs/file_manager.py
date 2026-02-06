"""High-level file operations facade."""

from __future__ import annotations

from pathlib import Path

from clsdumper.fs.path_generator import generate_output_dir


class FileManager:
    """Facade for file system operations."""

    def __init__(self, output_dir: Path | None = None, target: str | int = "") -> None:
        if output_dir:
            self.output_dir = output_dir
        else:
            self.output_dir = generate_output_dir(target)

    def ensure_dirs(self) -> None:
        """Create all necessary output directories."""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        (self.output_dir / "dex").mkdir(exist_ok=True)

    @property
    def dex_dir(self) -> Path:
        return self.output_dir / "dex"

    @property
    def classes_dir(self) -> Path:
        return self.output_dir / "classes"

    @property
    def metadata_path(self) -> Path:
        return self.output_dir / "metadata.json"
