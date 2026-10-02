from dataclasses import dataclass
from pathlib import Path

from .findings import Finding
from .hash_utils import calculate_sha3_512
from .models import ManifestEntry, Scope


@dataclass
class AuditResult:
    file_path: str
    scope: Scope
    entry_type: str
    status: str
    message: str


@dataclass
class AuditReport:
    results: list[AuditResult]
    canonical_findings: list[Finding]
    noncanonical_findings: list[Finding]


class ReleaseAuditor:
    """Verifies manifest entries and separates findings by audit scope."""

    def __init__(self, base_directory: Path):
        self.base_directory = base_directory

    def audit(
        self,
        entries: list[ManifestEntry],
        findings: list[Finding] | None = None,
    ) -> AuditReport:
        results = []

        for entry in entries:
            results.append(self._audit_entry(entry))

        findings = findings or []

        canonical_findings = [
            finding
            for finding in findings
            if finding.scope == Scope.CANONICAL
        ]

        noncanonical_findings = [
            finding
            for finding in findings
            if finding.scope == Scope.NONCANONICAL
        ]

        return AuditReport(
            results=results,
            canonical_findings=canonical_findings,
            noncanonical_findings=noncanonical_findings,
        )

    def _audit_entry(self, entry: ManifestEntry) -> AuditResult:
        file_path = self.base_directory / entry.file_path

        if not file_path.exists():
            return AuditResult(
                file_path=entry.file_path,
                scope=entry.scope,
                entry_type=entry.entry_type.value,
                status="FAIL",
                message="File is missing",
            )

        actual_hash = calculate_sha3_512(file_path)

        if actual_hash.lower() != entry.expected_hash.lower():
            return AuditResult(
                file_path=entry.file_path,
                scope=entry.scope,
                entry_type=entry.entry_type.value,
                status="FAIL",
                message="SHA3-512 hash mismatch",
            )

        return AuditResult(
            file_path=entry.file_path,
            scope=entry.scope,
            entry_type=entry.entry_type.value,
            status="PASS",
            message="File exists and SHA3-512 hash matches",
        )