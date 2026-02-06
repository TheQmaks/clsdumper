"""Entry point for clsdumper: python -m clsdumper or clsdumper CLI."""

from __future__ import annotations

import sys

from clsdumper.cli import build_parser, run_cli


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    sys.exit(run_cli(args))


if __name__ == "__main__":
    main()
