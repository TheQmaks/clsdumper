"""Command-line interface for clsdumper."""

from __future__ import annotations

import argparse
import io
import sys
from pathlib import Path

# Fix Windows console encoding for Unicode output
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

from clsdumper import __version__
from clsdumper.dumper.dex_dumper import DexDumper
from clsdumper.device.connector import DeviceConnector
from clsdumper.fs.path_generator import generate_output_dir
from clsdumper.utils.exceptions import CLSDumperError
from clsdumper.utils.logging import Logger

VALID_STRATEGIES = [
    "art_walk", "open_common_hook", "memory_scan", "cookie", "classloader_hook",
    "mmap_hook", "oat_extract", "fart_dump", "dexfile_constructor",
]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="clsdumper",
        description="Android Dynamic Class Dumper — dump all DEX files and classes from running apps",
    )
    parser.add_argument(
        "target",
        nargs="?",
        help="Package name or PID of the target app",
    )
    parser.add_argument(
        "-o", "--output",
        type=Path,
        help="Output directory (default: ./dump_<target>)",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List running processes on the device",
    )
    parser.add_argument(
        "--list-apps",
        action="store_true",
        help="List installed applications on the device",
    )
    parser.add_argument(
        "--spawn",
        action="store_true",
        help="Spawn the app instead of attaching to a running process",
    )
    parser.add_argument(
        "--host",
        help="Frida server host (default: USB)",
    )
    parser.add_argument(
        "--strategies",
        help=f"Comma-separated list of strategies: {', '.join(VALID_STRATEGIES)}",
    )
    parser.add_argument(
        "--no-scan",
        action="store_true",
        help="Disable memory scan strategy",
    )
    parser.add_argument(
        "--deep-scan",
        action="store_true",
        help="Enable deep scan (CDEX files, slower)",
    )
    parser.add_argument(
        "--extract-classes",
        action="store_true",
        help="Extract individual classes from dumped DEX files",
    )
    parser.add_argument(
        "--no-anti-frida",
        action="store_true",
        help="Disable anti-frida bypass (sigaction/maps patching)",
    )
    parser.add_argument(
        "-d", "--debug",
        action="store_true",
        help="Enable debug output",
    )
    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"clsdumper {__version__}",
    )
    return parser


def parse_target(target_str: str) -> str | int:
    """Parse target as PID (int) or package name (str)."""
    try:
        return int(target_str)
    except ValueError:
        return target_str


def run_cli(args: argparse.Namespace) -> int:
    """Execute the CLI command."""
    logger = Logger(verbose=args.debug)
    logger.banner()

    # List mode
    if args.list or args.list_apps:
        return _run_list(args, logger)

    # Dump mode — target is required
    if not args.target:
        logger.error("CORE", "Target is required. Use --list to see running processes.")
        return 1

    target = parse_target(args.target)
    output_dir = args.output or generate_output_dir(target)

    # Parse strategies
    strategies = None
    if args.strategies:
        strategies = [s.strip() for s in args.strategies.split(",")]
        invalid = [s for s in strategies if s not in VALID_STRATEGIES]
        if invalid:
            logger.error("CORE", f"Invalid strategies: {', '.join(invalid)}")
            logger.error("CORE", f"Valid strategies: {', '.join(VALID_STRATEGIES)}")
            return 1

    if args.no_scan:
        if strategies is None:
            strategies = [s for s in VALID_STRATEGIES if s != "memory_scan"]
        elif "memory_scan" in strategies:
            strategies.remove("memory_scan")

    try:
        dumper = DexDumper(
            target=target,
            output_dir=output_dir,
            logger=logger,
            spawn=args.spawn,
            host=args.host,
            strategies=strategies,
            deep_scan=args.deep_scan,
            extract_classes=args.extract_classes,
            debug=args.debug,
            no_anti_frida=args.no_anti_frida,
        )
        dumper.run()
        return 0
    except CLSDumperError as e:
        logger.error("CORE", str(e))
        return 1
    except Exception as e:
        logger.error("CORE", f"Unexpected error: {e}")
        if args.debug:
            import traceback
            traceback.print_exc()
        return 1


def _run_list(args: argparse.Namespace, logger: Logger) -> int:
    """List processes or apps on the device."""
    connector = DeviceConnector(logger, host=args.host)
    try:
        connector.connect()

        if args.list_apps:
            apps = connector.list_apps()
            logger.info("DEVICE", f"Found {len(apps)} applications:")
            print(f"\n{'PID':>6}  {'Identifier':<45} {'Name'}")
            print("-" * 80)
            for app in apps:
                pid_str = str(app["pid"]) if app["pid"] else "-"
                print(f"{pid_str:>6}  {app['identifier']:<45} {app['name']}")
        else:
            processes = connector.list_processes()
            logger.info("DEVICE", f"Found {len(processes)} processes:")
            print(f"\n{'PID':>6}  {'Name'}")
            print("-" * 40)
            for proc in processes:
                print(f"{proc['pid']:>6}  {proc['name']}")

        return 0
    except CLSDumperError as e:
        logger.error("CORE", str(e))
        return 1
