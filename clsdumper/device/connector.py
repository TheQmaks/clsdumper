"""Device connection management via Frida USB/TCP."""

from __future__ import annotations

import frida

from clsdumper.utils.exceptions import DeviceError, DeviceNotFoundError, ProcessNotFoundError
from clsdumper.utils.logging import Logger


class DeviceConnector:
    """Manages connection to Android device and target process."""

    def __init__(self, logger: Logger, host: str | None = None) -> None:
        self.logger = logger
        self.host = host
        self._device: frida.core.Device | None = None
        self._session: frida.core.Session | None = None

    @property
    def device(self) -> frida.core.Device:
        if self._device is None:
            raise DeviceError("Not connected to a device")
        return self._device

    @property
    def session(self) -> frida.core.Session:
        if self._session is None:
            raise DeviceError("No active session")
        return self._session

    def connect(self) -> frida.core.Device:
        """Connect to an Android device via USB or TCP."""
        try:
            if self.host:
                self.logger.info("DEVICE", f"Connecting to {self.host}...")
                manager = frida.get_device_manager()
                self._device = manager.add_remote_device(self.host)
            else:
                self.logger.info("DEVICE", "Connecting via USB...")
                self._device = frida.get_usb_device(timeout=10)

            device_name = self._device.name
            # Try to get Android version info
            android_info = ""
            try:
                params = self._device.query_system_parameters()
                os_version = params.get("os", {}).get("version", "")
                api_level = params.get("os", {}).get("id", "")
                if os_version:
                    android_info = f" (Android {os_version}, API {api_level})"
            except Exception:
                pass

            self.logger.info("DEVICE", f"Connected to {device_name}{android_info}")
            return self._device

        except frida.ServerNotRunningError:
            raise DeviceError(
                "Frida server is not running on the device. "
                "Start frida-server on the device and try again."
            )
        except frida.TimedOutError:
            raise DeviceNotFoundError(
                "No device found. Check USB connection or specify --host for TCP."
            )
        except Exception as e:
            raise DeviceError(f"Failed to connect: {e}")

    def list_processes(self) -> list[dict]:
        """List all running processes on the device."""
        processes = self.device.enumerate_processes()
        result = []
        for proc in processes:
            result.append({
                "pid": proc.pid,
                "name": proc.name,
            })
        return sorted(result, key=lambda p: p["name"])

    def list_apps(self) -> list[dict]:
        """List installed applications."""
        apps = self.device.enumerate_applications()
        result = []
        for app in apps:
            result.append({
                "identifier": app.identifier,
                "name": app.name,
                "pid": app.pid,
            })
        return sorted(result, key=lambda a: a["identifier"])

    def attach(self, target: str | int) -> frida.core.Session:
        """Attach to a process by PID or package name."""
        try:
            if isinstance(target, int):
                self.logger.info("CORE", f"Attaching to PID {target}...")
                self._session = self.device.attach(target)
            else:
                self.logger.info("CORE", f"Attaching to {target}...")
                self._session = self.device.attach(target)
            return self._session
        except frida.ProcessNotFoundError:
            raise ProcessNotFoundError(
                f"Process '{target}' not found. "
                "Make sure the app is running or use --spawn to start it."
            )
        except Exception as e:
            raise DeviceError(f"Failed to attach: {e}")

    def spawn_and_attach(self, package: str) -> frida.core.Session:
        """Spawn the app and attach to it.

        Kills any existing instance first, then spawns via Frida.
        If Frida spawn times out (heavy apps), falls back to
        am start + attach.
        """
        # Kill existing process to avoid conflicts
        try:
            self.device.kill(package)
            import time
            time.sleep(0.5)
        except Exception:
            pass  # Process might not be running

        self.logger.info("CORE", f"Spawning {package}...")
        try:
            pid = self.device.spawn([package])
            self._spawn_pid = pid
            self._session = self.device.attach(pid)
            return self._session
        except frida.TimedOutError:
            self.logger.warn("CORE", "Frida spawn timed out, trying am start fallback...")
            return self._spawn_via_am_start(package)
        except Exception as e:
            if "timed out" in str(e).lower():
                self.logger.warn("CORE", "Frida spawn timed out, trying am start fallback...")
                return self._spawn_via_am_start(package)
            raise DeviceError(f"Failed to spawn {package}: {e}")

    def _spawn_via_am_start(self, package: str) -> frida.core.Session:
        """Fallback spawn: launch app via adb shell am start, then attach."""
        import subprocess
        import time

        # Get the launch activity
        try:
            # Use Frida device to run shell command
            # First try: spawn with am start via adb
            subprocess.run(
                ["adb", "shell", "am", "start", "-n",
                 f"{package}/.MainActivity",
                 "--activity-clear-task"],
                capture_output=True, timeout=5,
            )
        except Exception:
            pass

        # Also try monkey (works without knowing activity name)
        try:
            subprocess.run(
                ["adb", "shell", "monkey", "-p", package,
                 "-c", "android.intent.category.LAUNCHER", "1"],
                capture_output=True, timeout=5,
            )
        except Exception:
            pass

        # Wait for the app to start
        self.logger.info("CORE", f"Waiting for {package} to start...")
        for attempt in range(30):
            time.sleep(1)
            try:
                processes = self.device.enumerate_processes()
                for proc in processes:
                    if proc.name == package or package in (proc.name or ""):
                        self.logger.info("CORE", f"Found {package} (PID {proc.pid}), attaching...")
                        self._spawn_pid = proc.pid
                        self._session = self.device.attach(proc.pid)
                        return self._session
            except Exception:
                continue

        raise DeviceError(
            f"Failed to spawn {package}: app did not start within 30 seconds"
        )

    def resume(self) -> None:
        """Resume a spawned process."""
        pid = getattr(self, '_spawn_pid', None)
        if pid is None:
            self.logger.warn("CORE", "No spawned process to resume")
            return
        try:
            self.device.resume(pid)
        except Exception as e:
            self.logger.warn("CORE", f"Failed to resume PID {pid}: {e}")

    def detach(self) -> None:
        """Detach from the current session."""
        if self._session:
            try:
                self._session.detach()
            except Exception:
                pass
            self._session = None
