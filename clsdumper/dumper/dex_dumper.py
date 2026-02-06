"""Main orchestrator for the DEX dump process."""

from __future__ import annotations

import signal
import sys
import time
from pathlib import Path

from clsdumper.device.connector import DeviceConnector
from clsdumper.dumper.dex_manager import DexDumpManager
from clsdumper.dumper.message_handler import MessageHandler
from clsdumper.extractor.class_extractor import ClassExtractor
from clsdumper.frida.script_manager import ScriptManager
from clsdumper.utils.exceptions import CLSDumperError
from clsdumper.utils.logging import Logger


class DexDumper:
    """Orchestrates the full dump pipeline: connect → attach → dump → extract."""

    def __init__(
        self,
        target: str | int,
        output_dir: Path,
        logger: Logger,
        *,
        spawn: bool = False,
        host: str | None = None,
        strategies: list[str] | None = None,
        deep_scan: bool = False,
        extract_classes: bool = False,
        debug: bool = False,
        no_anti_frida: bool = False,
    ) -> None:
        self.target = target
        self.output_dir = output_dir
        self.logger = logger
        self.spawn = spawn
        self.strategies = strategies
        self.deep_scan = deep_scan
        self.extract_classes = extract_classes
        self.debug = debug
        self.no_anti_frida = no_anti_frida

        self.connector = DeviceConnector(logger, host=host)
        self.script_manager = ScriptManager(logger)
        self.message_handler = MessageHandler(logger)
        self.dex_manager = DexDumpManager(output_dir, logger)
        self.extractor = ClassExtractor(logger)

        self._running = False
        self._agent_loaded = False

    def run(self) -> None:
        """Execute the full dump pipeline."""
        self._running = True
        self._setup_signal_handler()

        try:
            # 1. Connect to device
            self.connector.connect()

            # 2. Attach or spawn
            if self.spawn:
                if isinstance(self.target, int):
                    raise CLSDumperError(
                        "--spawn cannot be used with a PID. "
                        "Provide a package name instead."
                    )
                session = self.connector.spawn_and_attach(self.target)
            else:
                session = self.connector.attach(self.target)

            # 3. Register session detach handler (process death detection)
            session.on("detached", self._on_detached)

            # 4. Register message callbacks
            self.message_handler.on_dex(self._on_dex_found)
            self.message_handler.on_progress(self._on_progress)

            # 5. Load agent
            self.script_manager.load(session, self.message_handler.handle)
            self._agent_loaded = True

            # 6. Send config to agent (does not start execution yet)
            self.script_manager.send_config(
                strategies=self.strategies,
                deep_scan=self.deep_scan,
                debug=self.debug,
                no_anti_frida=self.no_anti_frida,
            )

            # 7. Trigger strategy execution BEFORE resume — agent runs on
            #    a quiet process with no anti-frida competition
            self.script_manager.trigger_run()

            # 8. Resume spawned process (hooks are already installed)
            if self.spawn:
                self.connector.resume()

            # 9. Wait for dump to complete, then watch for dynamic loads
            self.logger.info("HOOK", "Watching for new class loads... (Ctrl+C to stop)")
            while self._running:
                time.sleep(0.5)

        except KeyboardInterrupt:
            self.logger.info("CORE", "Interrupted by user")
        except CLSDumperError:
            raise
        except Exception as e:
            raise CLSDumperError(f"Unexpected error: {e}") from e
        finally:
            self._finish()

    def _on_detached(self, reason: str, crash: object = None) -> None:
        """Called when the Frida session is detached (process died, etc.)."""
        if reason == "process-terminated":
            self.logger.warn(
                "CORE",
                "Target process terminated (anti-debug crash). "
                f"Collected {self.dex_manager.count} DEX files before crash."
            )
        elif reason == "application-requested":
            self.logger.info("CORE", "Session detached by application")
        else:
            self.logger.warn("CORE", f"Session detached: {reason}")
        self._agent_loaded = False
        self._running = False

    def _on_dex_found(self, payload: dict, data: bytes) -> None:
        """Called when a new DEX file is received from the agent."""
        self.dex_manager.save_dex(payload, data)

    def _on_progress(self, scanned: int, total: int, found: int) -> None:
        """Called on scan progress updates."""
        self.logger.progress(scanned, total, f"({found} DEX found)")

    def _finish(self) -> None:
        """Cleanup and final reporting."""
        if self._agent_loaded:
            self.script_manager.stop()
            self.script_manager.unload()
        self.connector.detach()

        if self.dex_manager.count == 0:
            return

        # Extract classes if requested
        if self.extract_classes and self.dex_manager.count > 0:
            self.logger.info("EXTRACT", "Extracting classes from DEX files...")
            classes_dir = self.output_dir / "classes"
            total_classes = 0
            for dex_info in self.dex_manager.files:
                dex_path = self.dex_manager.dex_dir / dex_info.filename
                count = self.extractor.extract(dex_path, classes_dir)
                dex_info.class_count = count
                total_classes += count
            self.logger.info("EXTRACT", f"Extracted {total_classes} classes")

        # Save metadata
        self.dex_manager.save_metadata()

        # Print summary
        self._print_summary()

    def _print_summary(self) -> None:
        """Print final dump summary."""
        self.logger.info("CORE", "Dump complete!")
        total_classes = sum(f.class_count for f in self.dex_manager.files)
        lines = [
            f"DEX files dumped:   {self.dex_manager.count}",
            f"Classes extracted:  {total_classes}",
            f"Total size:         {_format_bytes(self.dex_manager.total_bytes)}",
            f"Output:             {self.output_dir}",
        ]
        self.logger.tree(lines)

        if self.dex_manager.count > 0:
            self.logger.info("DUMP", "DEX files:")
            tree_lines = []
            files = self.dex_manager.files
            for i, f in enumerate(files):
                prefix = "\u2514\u2500\u2500" if i == len(files) - 1 else "\u251c\u2500\u2500"
                size_str = _format_bytes(f.size)
                cls_str = f", {f.class_count} classes" if f.class_count > 0 else ""
                tree_lines.append(f"{prefix} {f.filename} ({size_str}{cls_str}) [{f.strategy}]")
            self.logger.tree(tree_lines)

    def _setup_signal_handler(self) -> None:
        """Handle Ctrl+C gracefully."""
        def handler(sig: int, frame: object) -> None:
            self._running = False

        signal.signal(signal.SIGINT, handler)
        if sys.platform != "win32":
            signal.signal(signal.SIGTERM, handler)


def _format_bytes(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n / (1024 * 1024):.1f} MB"
