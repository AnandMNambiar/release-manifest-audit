from pathlib import Path

from .models import EntryType, ManifestEntry


class ManifestParser:
    """Parses a release manifest into structured entries."""

    def parse_file(self, manifest_path: Path) -> list[ManifestEntry]:
        content = manifest_path.read_text(encoding="utf-8")
        return self.parse_content(content)

    def parse_content(self, content: str) -> list[ManifestEntry]:
        entries = []

        for line_number, line in enumerate(content.splitlines(), start=1):
            line = line.strip()

            # Ignore blank lines and comments.
            if not line or line.startswith("#"):
                continue

            try:
                entry_type_text, value = line.split(":", 1)
                file_path, expected_hash = value.rsplit(":", 1)
            except ValueError:
                raise ValueError(
                    f"Invalid manifest entry on line {line_number}: {line}"
                )

            try:
                entry_type = EntryType(entry_type_text.strip())
            except ValueError:
                raise ValueError(
                    f"Unknown entry type on line {line_number}: "
                    f"{entry_type_text.strip()}"
                )

            file_path = file_path.strip()
            expected_hash = expected_hash.strip()

            if not file_path:
                raise ValueError(
                    f"Missing file path on line {line_number}"
                )

            if not expected_hash:
                raise ValueError(
                    f"Missing hash on line {line_number}"
                )

            entries.append(
                ManifestEntry(
                    entry_type=entry_type,
                    file_path=file_path,
                    expected_hash=expected_hash,
                )
            )

        return entries