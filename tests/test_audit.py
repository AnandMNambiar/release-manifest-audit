from pathlib import Path

from release_audit.auditor import ReleaseAuditor
from release_audit.findings import Finding, parse_findings_file
from release_audit.models import ManifestEntry, Scope
from release_audit.parser import ManifestParser


BASE_DIR = Path("data")
MANIFEST_PATH = BASE_DIR / "manifest.txt"


def load_entries():
    return ManifestParser().parse_file(MANIFEST_PATH)


def test_manifest_classification():
    entries = load_entries()

    assert entries[0].scope == Scope.CANONICAL
    assert entries[1].scope == Scope.CANONICAL
    assert entries[2].scope == Scope.CANONICAL

    assert entries[3].scope == Scope.NONCANONICAL
    assert entries[4].scope == Scope.NONCANONICAL


def test_all_manifest_files_pass():
    entries = load_entries()

    report = ReleaseAuditor(BASE_DIR).audit(entries)

    assert all(result.status == "PASS" for result in report.results)


def test_missing_canonical_file_is_failure(tmp_path):
    original_entry = load_entries()[0]

    entry = ManifestEntry(
        entry_type=original_entry.entry_type,
        file_path="missing.py",
        expected_hash=original_entry.expected_hash,
    )

    report = ReleaseAuditor(tmp_path).audit([entry])

    assert report.results[0].status == "FAIL"
    assert report.results[0].message == "File is missing"


def test_hash_mismatch_is_failure(tmp_path):
    test_file = tmp_path / "app.py"
    test_file.write_text("modified content", encoding="utf-8")

    original_entry = load_entries()[0]

    entry = ManifestEntry(
        entry_type=original_entry.entry_type,
        file_path="app.py",
        expected_hash=original_entry.expected_hash,
    )

    report = ReleaseAuditor(tmp_path).audit([entry])

    assert report.results[0].status == "FAIL"
    assert report.results[0].message == "SHA3-512 hash mismatch"


def test_findings_are_separated_by_scope():
    entries = load_entries()

    findings = [
        Finding(
            file_path="canonical/app.py",
            scope=Scope.CANONICAL,
            message="Example canonical finding",
            severity="MEDIUM",
        ),
        Finding(
            file_path="noncanonical/experiment.py",
            scope=Scope.NONCANONICAL,
            message="Example noncanonical finding",
            severity="LOW",
        ),
    ]

    report = ReleaseAuditor(BASE_DIR).audit(entries, findings)

    assert len(report.canonical_findings) == 1
    assert len(report.noncanonical_findings) == 1

    assert report.canonical_findings[0].file_path == "canonical/app.py"

    assert (
        report.noncanonical_findings[0].file_path
        == "noncanonical/experiment.py"
    )


def test_findings_file_is_parsed():
    findings_path = Path("data/findings.txt")

    findings = parse_findings_file(findings_path)

    assert len(findings) == 2

    assert findings[0].file_path == "canonical/app.py"
    assert findings[0].scope == Scope.CANONICAL
    assert findings[0].severity == "MEDIUM"

    assert findings[1].file_path == "noncanonical/experiment.py"
    assert findings[1].scope == Scope.NONCANONICAL
    assert findings[1].severity == "LOW"