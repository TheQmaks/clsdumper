"""Safe filename and path generation."""

from __future__ import annotations

import re
from pathlib import Path


def safe_filename(name: str, max_length: int = 200) -> str:
    """
    Sanitize a string for use as a filename.
    Removes or replaces unsafe characters.
    """
    # Replace path separators and other unsafe chars
    safe = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", name)
    # Collapse multiple underscores
    safe = re.sub(r"_+", "_", safe)
    # Strip leading/trailing dots and spaces
    safe = safe.strip(". ")
    # Truncate
    if len(safe) > max_length:
        safe = safe[:max_length]
    return safe or "unnamed"


def generate_output_dir(target: str | int, base: Path | None = None) -> Path:
    """Generate an output directory path for a dump session."""
    if base is None:
        base = Path.cwd()

    if isinstance(target, int):
        dir_name = f"dump_pid_{target}"
    else:
        dir_name = f"dump_{safe_filename(target)}"

    return base / dir_name
