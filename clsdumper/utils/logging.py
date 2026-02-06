"""Colored logging with progress display for clsdumper."""

from __future__ import annotations

import sys
from datetime import datetime

# ANSI color codes
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"

RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"
WHITE = "\033[37m"

LEVEL_COLORS = {
    "DEBUG": DIM,
    "INFO": GREEN,
    "WARN": YELLOW,
    "ERROR": RED,
}

TAG_COLORS = {
    "DEVICE": CYAN,
    "CORE": BLUE,
    "AGENT": MAGENTA,
    "STRATEGY": YELLOW,
    "DUMP": GREEN,
    "EXTRACT": CYAN,
    "HOOK": MAGENTA,
    "CLASSLOADERS": BLUE,
}

BANNER = r"""
       _         _
   ___| |___  __| |_   _ _ __ ___  _ __   ___ _ __
  / __| / __|/ _` | | | | '_ ` _ \| '_ \ / _ \ '__|
 | (__| \__ \ (_| | |_| | | | | | | |_) |  __/ |
  \___|_|___/\__,_|\__,_|_| |_| |_| .__/ \___|_|
                                   |_|
"""


class Logger:
    """Colored console logger with progress bar support."""

    def __init__(self, verbose: bool = False) -> None:
        self.verbose = verbose
        self._progress_active = False

    def banner(self) -> None:
        print(f"{BOLD}{CYAN}{BANNER}{RESET}")

    def debug(self, tag: str, message: str) -> None:
        if self.verbose:
            self._log("DEBUG", tag, message)

    def info(self, tag: str, message: str) -> None:
        self._log("INFO", tag, message)

    def warn(self, tag: str, message: str) -> None:
        self._log("WARN", tag, message)

    def error(self, tag: str, message: str) -> None:
        self._log("ERROR", tag, message)

    def progress(self, current: int, total: int, label: str = "") -> None:
        """Display a progress bar."""
        if total <= 0:
            return
        pct = min(current / total, 1.0)
        filled = int(32 * pct)
        bar = "\u2588" * filled + "\u2591" * (32 - filled)
        line = f"\r{DIM}[{bar}]{RESET} {pct:.0%} ({current}/{total})"
        if label:
            line += f" {label}"
        # Clear any leftover characters from a longer previous line
        line += "\033[K"
        sys.stderr.write(line)
        sys.stderr.flush()
        self._progress_active = True
        if current >= total:
            sys.stderr.write("\n")
            self._progress_active = False

    def tree(self, lines: list[str], indent: str = "                     ") -> None:
        """Print tree-formatted output."""
        for line in lines:
            sys.stderr.write(f"{indent}{line}\n")
        sys.stderr.flush()

    def _log(self, level: str, tag: str, message: str) -> None:
        if self._progress_active:
            sys.stderr.write("\n")
            self._progress_active = False

        now = datetime.now()
        time_str = now.strftime("%H:%M:%S")

        level_color = LEVEL_COLORS.get(level, "")
        tag_color = TAG_COLORS.get(tag, WHITE)

        line = (
            f"{DIM}[{time_str}]{RESET} "
            f"{level_color}[{level}]{RESET} "
            f"{tag_color}[{tag}]{RESET} "
            f"{message}"
        )
        sys.stderr.write(line + "\n")
        sys.stderr.flush()
