from pathlib import Path
import subprocess
import sys

from release_audit.auditor import ReleaseAuditor
from release_audit.findings import Finding, parse_findings_file
from release_audit.models import EntryType, ManifestEntry, Scope
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


def test_empty_manifest_fails(tmp_path):
    manifest = tmp_path / "manifest.txt"
    manifest.write_text("", encoding="utf-8")

    entries = ManifestParser().parse_file(manifest)

    report = ReleaseAuditor(tmp_path).audit(entries)

    assert report.results[0].status == "FAIL"
    assert report.results[0].message == "Manifest contains no entries"


def test_path_traversal_is_rejected(tmp_path):
    outside_file = tmp_path.parent / "outside.py"
    outside_file.write_text("outside", encoding="utf-8")

    original_entry = load_entries()[0]

    entry = ManifestEntry(
        entry_type=original_entry.entry_type,
        file_path="../outside.py",
        expected_hash=original_entry.expected_hash,
    )

    report = ReleaseAuditor(tmp_path).audit([entry])

    assert report.results[0].status == "FAIL"
    assert (
        report.results[0].message
        == "File path escapes the base directory"
    )


def test_conflicting_duplicate_entries_fail(tmp_path):
    original_entry = load_entries()[0]

    first_entry = ManifestEntry(
        entry_type=original_entry.entry_type,
        file_path="app.py",
        expected_hash="hash-one",
    )

    second_entry = ManifestEntry(
        entry_type=original_entry.entry_type,
        file_path="app.py",
        expected_hash="hash-two",
    )

    report = ReleaseAuditor(tmp_path).audit(
        [first_entry, second_entry]
    )

    assert any(
        result.status == "FAIL"
        and result.message == "Conflicting duplicate manifest entry"
        for result in report.results
    )


def test_equivalent_duplicate_paths_fail(tmp_path):
    original_entry = load_entries()[0]

    first_entry = ManifestEntry(
        entry_type=original_entry.entry_type,
        file_path="canonical/app.py",
        expected_hash=original_entry.expected_hash,
    )

    second_entry = ManifestEntry(
        entry_type=original_entry.entry_type,
        file_path="canonical/./app.py",
        expected_hash="different-hash",
    )

    report = ReleaseAuditor(tmp_path).audit(
        [first_entry, second_entry]
    )

    assert any(
        result.status == "FAIL"
        and result.message == "Conflicting duplicate manifest entry"
        for result in report.results
    )


def test_directory_used_as_file_fails(tmp_path):
    directory = tmp_path / "app.py"
    directory.mkdir()

    original_entry = load_entries()[0]

    entry = ManifestEntry(
        entry_type=original_entry.entry_type,
        file_path="app.py",
        expected_hash=original_entry.expected_hash,
    )

    report = ReleaseAuditor(tmp_path).audit([entry])

    assert report.results[0].status == "FAIL"
    assert report.results[0].message == "Path is not a file"


def test_finding_scope_mismatch_is_detected():
    entries = load_entries()

    findings = [
        Finding(
            file_path="canonical/app.py",
            scope=Scope.NONCANONICAL,
            message="Incorrectly scoped finding",
            severity="HIGH",
        )
    ]

    report = ReleaseAuditor(BASE_DIR).audit(entries, findings)

    assert len(report.finding_scope_errors) == 1
    assert report.finding_scope_errors[0].file_path == "canonical/app.py"


def test_cli_reports_scope_mismatch_and_fails(tmp_path):
    findings_path = tmp_path / "findings_scope_mismatch.txt"

    findings_path.write_text(
        "canonical/app.py|noncanonical|HIGH|Incorrectly scoped finding\n",
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "release_audit.cli",
            "--manifest",
            str(MANIFEST_PATH),
            "--base-dir",
            str(BASE_DIR),
            "--findings",
            str(findings_path),
        ],
        capture_output=True,
        text=True,
        env={**__import__("os").environ, "PYTHONPATH": "src"},
    )

    assert result.returncode == 1
    assert "Finding scope errors:" in result.stdout
    assert "AUDIT STATUS: FAILED" in result.stdout
def test_unmanifested_finding_is_rejected():
    entries = load_entries()

    findings = [
        Finding(
            file_path="canonical/not_in_manifest.py",
            scope=Scope.CANONICAL,
            message="Finding for an unmanifested file",
            severity="HIGH",
        )
    ]

    report = ReleaseAuditor(BASE_DIR).audit(entries, findings)

    assert len(report.unmanifested_findings) == 1
    assert (
        report.unmanifested_findings[0].file_path
        == "canonical/not_in_manifest.py"
    )

    assert len(report.canonical_findings) == 0
    assert len(report.noncanonical_findings) == 0
def test_cli_reports_unmanifested_finding_and_fails(tmp_path):
    findings_path = tmp_path / "findings_unmanifested.txt"

    findings_path.write_text(
        "canonical/not_in_manifest.py|canonical|HIGH|Finding for an unmanifested file\n",
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "release_audit.cli",
            "--manifest",
            str(MANIFEST_PATH),
            "--base-dir",
            str(BASE_DIR),
            "--findings",
            str(findings_path),
        ],
        capture_output=True,
        text=True,
        env={**__import__("os").environ, "PYTHONPATH": "src"},
    )

    assert result.returncode == 1
    assert "Unmanifested findings:" in result.stdout
    assert "Finding refers to a file that is not present in the manifest" in result.stdout
    assert "AUDIT STATUS: FAILED" in result.stdout
def test_dot_dot_duplicate_paths_fail(tmp_path):
    original_entry = load_entries()[0]

    first_entry = ManifestEntry(
        entry_type=original_entry.entry_type,
        file_path="canonical/app.py",
        expected_hash=original_entry.expected_hash,
    )

    second_entry = ManifestEntry(
        entry_type=EntryType.EVIDENCE,
        file_path="canonical/sub/../app.py",
        expected_hash=original_entry.expected_hash,
    )

    report = ReleaseAuditor(tmp_path).audit(
        [first_entry, second_entry]
    )

    assert any(
        result.status == "FAIL"
        and result.message == "Conflicting duplicate manifest entry"
        for result in report.results
    )
