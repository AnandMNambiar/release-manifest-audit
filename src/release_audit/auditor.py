from dataclasses import dataclass
from pathlib import Path, PurePosixPath

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
    finding_scope_errors: list[Finding]
    unmanifested_findings: list[Finding]


class ReleaseAuditor:
    """Verifies manifest entries and separates findings by audit scope."""

    def __init__(self, base_directory: Path):
        self.base_directory = base_directory.resolve()

    def audit(
        self,
        entries: list[ManifestEntry],
        findings: list[Finding] | None = None,
    ) -> AuditReport:
        results = []

        if not entries:
            results.append(
                AuditResult(
                    file_path="",
                    scope=Scope.CANONICAL,
                    entry_type="MANIFEST",
                    status="FAIL",
                    message="Manifest contains no entries",
                )
            )
        else:
            duplicate_errors = self._validate_duplicates(entries)

            if duplicate_errors:
                results.extend(duplicate_errors)
            else:
                for entry in entries:
                    results.append(self._audit_entry(entry))

        findings = findings or []

        manifest_scopes = {
            self._normalize_path(entry.file_path): entry.scope
            for entry in entries
        }

        canonical_findings = []
        noncanonical_findings = []
        finding_scope_errors = []
        unmanifested_findings = []

        for finding in findings:
            normalized_path = self._normalize_path(finding.file_path)
            manifest_scope = manifest_scopes.get(normalized_path)

            if manifest_scope is None:
                unmanifested_findings.append(finding)
                continue

            if manifest_scope != finding.scope:
                finding_scope_errors.append(finding)
                continue

            if finding.scope == Scope.CANONICAL:
                canonical_findings.append(finding)
            else:
                noncanonical_findings.append(finding)

        return AuditReport(
            results=results,
            canonical_findings=canonical_findings,
            noncanonical_findings=noncanonical_findings,
            finding_scope_errors=finding_scope_errors,
            unmanifested_findings=unmanifested_findings,
        )

    def _validate_duplicates(
        self,
        entries: list[ManifestEntry],
    ) -> list[AuditResult]:
        """Reject conflicting duplicate manifest entries."""

        seen: dict[str, ManifestEntry] = {}
        results = []

        for entry in entries:
            normalized_path = self._normalize_path(entry.file_path)

            if normalized_path in seen:
                previous = seen[normalized_path]

                if (
                    previous.entry_type != entry.entry_type
                    or previous.expected_hash.lower()
                    != entry.expected_hash.lower()
                ):
                    results.append(
                        AuditResult(
                            file_path=entry.file_path,
                            scope=entry.scope,
                            entry_type=entry.entry_type.value,
                            status="FAIL",
                            message="Conflicting duplicate manifest entry",
                        )
                    )
            else:
                seen[normalized_path] = entry

        return results

    def _audit_entry(self, entry: ManifestEntry) -> AuditResult:
        file_path = self._resolve_safe_path(entry.file_path)

        if file_path is None:
            return AuditResult(
                file_path=entry.file_path,
                scope=entry.scope,
                entry_type=entry.entry_type.value,
                status="FAIL",
                message="File path escapes the base directory",
            )

        if not file_path.exists():
            return AuditResult(
                file_path=entry.file_path,
                scope=entry.scope,
                entry_type=entry.entry_type.value,
                status="FAIL",
                message="File is missing",
            )

        if not file_path.is_file():
            return AuditResult(
                file_path=entry.file_path,
                scope=entry.scope,
                entry_type=entry.entry_type.value,
                status="FAIL",
                message="Path is not a file",
            )

        try:
            actual_hash = calculate_sha3_512(file_path)
        except OSError as error:
            return AuditResult(
                file_path=entry.file_path,
                scope=entry.scope,
                entry_type=entry.entry_type.value,
                status="FAIL",
                message=f"Unable to read file: {error}",
            )

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

    def _resolve_safe_path(self, relative_path: str) -> Path | None:
        """Resolve a manifest path and reject paths outside the base directory."""

        candidate = (self.base_directory / relative_path).resolve()

        try:
            candidate.relative_to(self.base_directory)
        except ValueError:
            return None

        return candidate

    @staticmethod
    def _normalize_path(file_path: str) -> str:
        """Normalize path separators and equivalent relative path forms."""

        normalized = file_path.replace("\\", "/").strip()

        return PurePosixPath(normalized).as_posix()