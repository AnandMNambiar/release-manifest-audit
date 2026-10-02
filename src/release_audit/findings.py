from dataclasses import dataclass
from pathlib import Path

from .models import Scope


@dataclass
class Finding:
    file_path: str
    scope: Scope
    message: str
    severity: str


def parse_findings_file(findings_path: Path) -> list[Finding]:
    """Read synthetic findings from a text file."""

    findings = []

    content = findings_path.read_text(encoding="utf-8")

    for line in content.splitlines():
        line = line.strip()

        if not line or line.startswith("#"):
            continue

        file_path, severity, message = line.split("|", 2)

        if file_path.startswith("canonical/"):
            scope = Scope.CANONICAL
        elif file_path.startswith("noncanonical/"):
            scope = Scope.NONCANONICAL
        else:
            raise ValueError(
                f"Unable to determine scope for finding: {file_path}"
            )

        findings.append(
            Finding(
                file_path=file_path,
                scope=scope,
                message=message,
                severity=severity,
            )
        )

    return findings