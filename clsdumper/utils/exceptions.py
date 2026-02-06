"""Exception hierarchy for clsdumper."""


class CLSDumperError(Exception):
    """Base exception for all clsdumper errors."""


class DeviceError(CLSDumperError):
    """Error connecting to or communicating with the device."""


class DeviceNotFoundError(DeviceError):
    """No device found."""


class ProcessNotFoundError(DeviceError):
    """Target process not found on device."""


class AgentError(CLSDumperError):
    """Error loading or running the Frida agent."""


class AgentLoadError(AgentError):
    """Failed to load the agent script."""


class DumpError(CLSDumperError):
    """Error during DEX dump."""


class ExtractionError(CLSDumperError):
    """Error extracting classes from DEX files."""
