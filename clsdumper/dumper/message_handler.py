"""Handles messages from the Frida agent."""

from __future__ import annotations

import hashlib
from typing import Any, Callable

from clsdumper.utils.logging import Logger


class MessageHandler:
    """Parses and dispatches messages from the Frida agent."""

    def __init__(self, logger: Logger) -> None:
        self.logger = logger
        self._dex_callbacks: list[Callable[[dict, bytes], None]] = []
        self._class_callbacks: list[Callable[[dict], None]] = []
        self._classloader_callbacks: list[Callable[[dict], None]] = []
        self._progress_callbacks: list[Callable[[int, int, int], None]] = []
        self._status_callbacks: list[Callable[[dict], None]] = []

        # Stats
        self.dex_count = 0
        self.class_count = 0
        self.total_dex_bytes = 0
        self._seen_hashes: set[str] = set()

    def on_dex(self, callback: Callable[[dict, bytes], None]) -> None:
        self._dex_callbacks.append(callback)

    def on_class(self, callback: Callable[[dict], None]) -> None:
        self._class_callbacks.append(callback)

    def on_classloader(self, callback: Callable[[dict], None]) -> None:
        self._classloader_callbacks.append(callback)

    def on_progress(self, callback: Callable[[int, int, int], None]) -> None:
        self._progress_callbacks.append(callback)

    def on_status(self, callback: Callable[[dict], None]) -> None:
        self._status_callbacks.append(callback)

    def handle(self, message: dict, data: Any) -> None:
        """Handle a message from the Frida agent. Called by Frida's on_message."""
        if message.get("type") == "error":
            self.logger.error("AGENT", f"Script error: {message.get('description', message)}")
            stack = message.get("stack")
            if stack:
                self.logger.debug("AGENT", f"Stack: {stack}")
            return

        if message.get("type") == "log":
            # Agent console.log() messages
            log_msg = message.get("payload", "")
            if isinstance(log_msg, str) and log_msg:
                self.logger.debug("AGENT-LOG", log_msg)
            return

        if message.get("type") != "send":
            return

        payload = message.get("payload")
        if not isinstance(payload, dict):
            return

        msg_type = payload.get("type")

        if msg_type == "dex_found":
            self._handle_dex_found(payload, data)
        elif msg_type == "class_loaded":
            self._handle_class_loaded(payload)
        elif msg_type == "classloader_found":
            self._handle_classloader_found(payload)
        elif msg_type == "scan_progress":
            self._handle_scan_progress(payload)
        elif msg_type == "strategy_status":
            self._handle_strategy_status(payload)
        elif msg_type == "error":
            strategy = payload.get("strategy", "unknown")
            self.logger.error("AGENT", f"[{strategy}] {payload.get('message', '')}")
        elif msg_type == "info":
            self.logger.info("AGENT", payload.get("message", ""))

    def _handle_dex_found(self, payload: dict, data: bytes | None) -> None:
        if data is None:
            return

        # Deduplicate by SHA-256 on host side
        sha256 = hashlib.sha256(data).hexdigest()
        if sha256 in self._seen_hashes:
            self.logger.debug("DUMP", f"Duplicate DEX (host dedup): {sha256[:12]}")
            return
        self._seen_hashes.add(sha256)

        self.dex_count += 1
        self.total_dex_bytes += len(data)

        strategy = payload.get("strategy", "unknown")
        size = len(data)
        self.logger.info(
            "DUMP",
            f"DEX #{self.dex_count}: {_format_bytes(size)} [{strategy}]"
        )

        # Pass sha256 to callbacks to avoid recomputation
        payload['sha256'] = sha256

        for cb in self._dex_callbacks:
            try:
                cb(payload, data)
            except Exception as e:
                self.logger.error("DUMP", f"DEX callback error: {e}")

    def _handle_class_loaded(self, payload: dict) -> None:
        self.class_count += 1
        name = payload.get("name", "?")
        self.logger.debug("HOOK", f"Class loaded: {name}")
        for cb in self._class_callbacks:
            try:
                cb(payload)
            except Exception as e:
                self.logger.error("HOOK", f"Class callback error: {e}")

    def _handle_classloader_found(self, payload: dict) -> None:
        loader_type = payload.get("loaderType", "?")
        self.logger.debug("CLASSLOADERS", f"Found: {loader_type}")
        for cb in self._classloader_callbacks:
            try:
                cb(payload)
            except Exception as e:
                self.logger.error("CLASSLOADERS", f"ClassLoader callback error: {e}")

    def _handle_scan_progress(self, payload: dict) -> None:
        scanned = payload.get("scanned", 0)
        total = payload.get("total", 0)
        found = payload.get("found", 0)
        for cb in self._progress_callbacks:
            try:
                cb(scanned, total, found)
            except Exception as e:
                self.logger.error("DUMP", f"Progress callback error: {e}")

    def _handle_strategy_status(self, payload: dict) -> None:
        strategy = payload.get("strategy", "?")
        status = payload.get("status", "?")
        msg = payload.get("message", "")
        self.logger.info("STRATEGY", f"{strategy}: {status} — {msg}")
        for cb in self._status_callbacks:
            try:
                cb(payload)
            except Exception as e:
                self.logger.error("STRATEGY", f"Status callback error: {e}")


def _format_bytes(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n / (1024 * 1024):.1f} MB"
