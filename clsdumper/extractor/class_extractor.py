"""Extract individual classes from DEX files using androguard."""

from __future__ import annotations

from pathlib import Path

from clsdumper.utils.logging import Logger


class ClassExtractor:
    """Extracts class definitions from DEX files to individual files."""

    def __init__(self, logger: Logger) -> None:
        self.logger = logger

    def extract(self, dex_path: Path, output_dir: Path) -> int:
        """
        Extract all classes from a DEX file.

        Creates a directory structure mirroring the package hierarchy.
        Each class gets a .smali file (DEX-native format).

        Returns the number of classes extracted.
        """
        try:
            from androguard.core.dex import DEX
        except ImportError:
            self.logger.warn(
                "EXTRACT",
                "androguard not installed — skipping class extraction. "
                "Install with: pip install androguard"
            )
            return 0

        try:
            dex_data = dex_path.read_bytes()
            dex = DEX(dex_data)
        except Exception as e:
            self.logger.warn("EXTRACT", f"Failed to parse {dex_path.name}: {e}")
            return 0

        count = 0
        for cls in dex.get_classes():
            try:
                class_name = cls.get_name()
                if not class_name:
                    continue

                # Convert Lcom/example/Foo; → com/example/Foo
                clean_name = class_name
                if clean_name.startswith("L") and clean_name.endswith(";"):
                    clean_name = clean_name[1:-1]

                # Create the class file
                class_path = output_dir / (clean_name + ".smali")
                class_path.parent.mkdir(parents=True, exist_ok=True)

                # Write class info (smali-like representation)
                source = self._class_to_smali(cls)
                class_path.write_text(source, encoding="utf-8")
                count += 1
            except Exception as e:
                self.logger.debug("EXTRACT", f"Failed to extract class: {e}")

        self.logger.debug("EXTRACT", f"Extracted {count} classes from {dex_path.name}")
        return count

    def _class_to_smali(self, cls: object) -> str:
        """Generate a smali-like text representation of a class."""
        lines: list[str] = []

        try:
            lines.append(f".class {cls.get_access_flags_string()} {cls.get_name()}")
            super_name = cls.get_superclassname()
            if super_name:
                lines.append(f".super {super_name}")
            source = cls.get_source()
            if source:
                lines.append(f".source \"{source}\"")
            lines.append("")

            # Interfaces
            for iface in cls.get_interfaces() or []:
                lines.append(f".implements {iface}")
            if cls.get_interfaces():
                lines.append("")

            # Fields
            for field in cls.get_fields() or []:
                try:
                    flags = field.get_access_flags_string()
                    name = field.get_name()
                    ftype = field.get_descriptor()
                    lines.append(f".field {flags} {name}:{ftype}")
                except Exception:
                    pass
            if cls.get_fields():
                lines.append("")

            # Methods (signatures only)
            for method in cls.get_methods() or []:
                try:
                    flags = method.get_access_flags_string()
                    name = method.get_name()
                    descriptor = method.get_descriptor()
                    lines.append(f".method {flags} {name}{descriptor}")
                    lines.append(".end method")
                    lines.append("")
                except Exception:
                    pass
        except Exception:
            lines.append(f"# Failed to fully decompile class")

        return "\n".join(lines)
