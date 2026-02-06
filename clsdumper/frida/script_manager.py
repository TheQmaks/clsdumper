"""Manages loading and lifecycle of the Frida agent script."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

import frida

from clsdumper.utils.exceptions import AgentLoadError
from clsdumper.utils.logging import Logger

AGENT_PATH = Path(__file__).parent / "scripts" / "agent.js"


class ScriptManager:
    """Loads the compiled TypeScript agent into a Frida session."""

    def __init__(self, logger: Logger) -> None:
        self.logger = logger
        self._script: frida.core.Script | None = None

    @property
    def script(self) -> frida.core.Script:
        if self._script is None:
            raise AgentLoadError("Script not loaded")
        return self._script

    def load(
        self,
        session: frida.core.Session,
        on_message: Callable[[dict, Any], None],
    ) -> frida.core.Script:
        """Load the agent script into the session."""
        agent_source = self._read_agent()
        self.logger.debug("AGENT", f"Agent source: {len(agent_source)} bytes")

        try:
            self._script = session.create_script(agent_source, runtime="v8")
            self._script.on("message", on_message)
            self._script.load()
            self.logger.info("AGENT", "Agent loaded successfully")
            return self._script
        except Exception as e:
            raise AgentLoadError(f"Failed to load agent: {e}")

    def send_config(
        self,
        strategies: list[str] | None = None,
        deep_scan: bool = False,
        debug: bool = False,
        no_anti_frida: bool = False,
    ) -> None:
        """Configure the agent via RPC (does NOT start execution)."""
        try:
            self.script.exports_sync.configure(strategies, deep_scan, debug, no_anti_frida)
        except Exception as e:
            self.logger.warn("AGENT", f"RPC configure failed: {e}")

    def trigger_run(self) -> None:
        """Trigger strategy execution. Call AFTER resume() in spawn mode."""
        self._script.post({"type": "run"})

    def stop(self) -> None:
        """Send stop signal to the agent."""
        if self._script:
            try:
                self._script.post({"type": "stop"})
            except Exception:
                pass

    def unload(self) -> None:
        """Unload the script."""
        if self._script:
            try:
                self._script.unload()
            except Exception:
                pass
            self._script = None

    def _read_agent(self) -> str:
        """Read the compiled agent.js file."""
        if not AGENT_PATH.exists():
            raise AgentLoadError(
                f"Agent script not found at {AGENT_PATH}. "
                "Build it first: cd agent && npm run build"
            )
        return AGENT_PATH.read_text(encoding="utf-8")
