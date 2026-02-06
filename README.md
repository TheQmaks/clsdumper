# clsdumper

```
       _         _
   ___| |___  __| |_   _ _ __ ___  _ __   ___ _ __
  / __| / __|/ _` | | | | '_ ` _ \| '_ \ / _ \ '__|
 | (__| \__ \ (_| | |_| | | | | | | |_) |  __/ |
  \___|_|___/\__,_|\__,_|_| |_| |_| .__/ \___|_|
                                   |_|
```

[![PyPI](https://img.shields.io/pypi/v/clsdumper.svg)](https://pypi.org/project/clsdumper/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Android Dynamic Class Dumper — dump all DEX files from running Android apps using Frida.

clsdumper hooks into a running (or freshly spawned) Android application and extracts every DEX file it can find using 9 different strategies. It works against apps with anti-Frida protections, packed/encrypted DEX files, and dynamically loaded code.

## Features

- **9 extraction strategies** — ART runtime walk, function hooking, memory scanning, OAT/VDEX parsing, and more
- **Anti-Frida bypass** — blocks signal-handler registration, filters `/proc/self/maps`, neutralizes watchdog threads
- **Spawn & attach** — start the app fresh or hook into an already running process
- **Automatic deduplication** — agent-side fast hash + host-side SHA-256
- **Class extraction** — optionally decompile DEX files into individual `.smali` classes via androguard
- **Works without Java bridge** — native strategies run outside `Java.perform()`, so they work even when the Java bridge crashes

## Quick Start

```bash
# Install from PyPI
pip install clsdumper

# Dump DEX from a running app (USB-connected device)
clsdumper com.example.app

# Spawn the app and dump
clsdumper com.example.app --spawn

# Attach by PID
clsdumper 12345
```

## Requirements

- Python 3.10+
- Rooted Android device with [frida-server](https://github.com/frida/frida/releases) running
- USB debugging enabled (or use `--host` for TCP)

## Usage

```
clsdumper [target] [options]
```

| Option | Description |
|---|---|
| `target` | Package name or PID of the target app |
| `-o, --output DIR` | Output directory (default: `./dump_<target>`) |
| `--spawn` | Spawn the app instead of attaching |
| `--host HOST` | Frida server host for TCP connection (default: USB) |
| `--strategies LIST` | Comma-separated list of strategies to use |
| `--no-scan` | Disable memory scan strategy |
| `--deep-scan` | Enable deep scan (CDEX files, slower) |
| `--extract-classes` | Extract individual classes from dumped DEX files |
| `--no-anti-frida` | Disable anti-Frida bypass |
| `-d, --debug` | Enable debug output |
| `--list` | List running processes on the device |
| `--list-apps` | List installed applications |
| `-v, --version` | Show version |

### Examples

```bash
# Use specific strategies only
clsdumper com.example.app --strategies fart_dump,oat_extract

# Spawn with class extraction
clsdumper com.example.app --spawn --extract-classes

# Connect to remote frida-server
clsdumper com.example.app --host 192.168.1.100

# List all installed apps
clsdumper --list-apps
```

## Strategies

| # | Strategy | Phase | Description |
|---|---|---|---|
| 1 | `art_walk` | Native | Walks Runtime -> ClassLinker -> DexFile structs in ART |
| 2 | `open_common_hook` | Native | Hooks `DexFile::OpenCommon` in libdexfile.so |
| 3 | `memory_scan` | Native | Scans readable memory regions for DEX magic bytes |
| 4 | `cookie` | Java | Reads `mCookie` field from ClassLoaders via reflection |
| 5 | `classloader_hook` | Java | Monitors `loadClass` / `DexClassLoader` / `InMemoryDexClassLoader` |
| 6 | `mmap_hook` | Native | Intercepts `mmap`/`mmap64` calls (not in default set) |
| 7 | `oat_extract` | Native | Parses mapped `.vdex` / `.oat` files for embedded DEX |
| 8 | `fart_dump` | Native | Hooks `DefineClass` + walks `class_table_` (best coverage) |
| 9 | `dexfile_constructor` | Native | Hooks `OatDexFile` C++ constructors |

**Default set**: all except `mmap_hook` (causes performance issues when combined with other hooks).

## Building from Source

The Frida agent is pre-built and included as `clsdumper/frida/scripts/agent.js`. To modify the agent:

```bash
# Install agent dependencies
cd agent && npm install

# Build the TypeScript agent
npm run build

# Install the Python package
cd .. && pip install -e .
```

## How It Works

clsdumper runs in three phases:

1. **Phase 0 — Anti-Frida bypass**: Hooks `sigaction`/`signal` to block anti-debugging signal handlers, replaces `/proc/self/maps` reads via `memfd_create`, and monitors `pthread_create` to neutralize watchdog threads.

2. **Phase 1 — Native strategies**: Runs outside `Java.perform()` using direct memory access and native function hooks. This works even when the Java bridge fails (common with heavily protected apps).

3. **Phase 2 — Java strategies**: Uses the Java bridge to inspect ClassLoaders and hook class loading. Falls back gracefully if the bridge is unavailable.

All found DEX files are deduplicated (fast djb2 hash on the agent, SHA-256 on the host) and saved with metadata including the strategy that found them.

## Output

```
dump_com.example.app/
  dex/
    classes_001.dex    # Dumped DEX files
    classes_002.dex
    ...
  classes/             # Only with --extract-classes
    com/example/...
  metadata.json        # Dump metadata and per-file info
```

## License

[MIT](LICENSE)
