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
    """Read synthetic findings from a text file.

    Expected format:

        file_path|scope|severity|message

    Example:

        canonical/app.py|canonical|MEDIUM|Example canonical finding
        noncanonical/experiment.py|noncanonical|LOW|Example noncanonical finding
    """

    findings = []

    content = findings_path.read_text(encoding="utf-8")

    for line_number, line in enumerate(content.splitlines(), start=1):
        line = line.strip()

        if not line or line.startswith("#"):
            continue

        parts = line.split("|", 3)

        if len(parts) != 4:
            raise ValueError(
                f"Invalid finding on line {line_number}: {line}"
            )

        file_path, scope_text, severity, message = (
            part.strip() for part in parts
        )

        if not file_path:
            raise ValueError(
                f"Missing file path on line {line_number}"
            )

        if not scope_text:
            raise ValueError(
                f"Missing scope on line {line_number}"
            )

        if not severity:
            raise ValueError(
                f"Missing severity on line {line_number}"
            )

        if not message:
            raise ValueError(
                f"Missing finding message on line {line_number}"
            )

        try:
            scope = Scope(scope_text.lower())
        except ValueError:
            raise ValueError(
                f"Unknown scope on line {line_number}: {scope_text}"
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