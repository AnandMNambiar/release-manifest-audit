# Release Manifest Audit

A small standalone Python prototype for deterministic release-manifest auditing.

The auditor reads a release manifest, verifies SHA3-512 hashes for referenced files, classifies entries into canonical and noncanonical audit scopes, and validates that findings remain consistent with the manifest.

## Architecture Overview

The prototype is organized into a few focused components:

- Manifest Parser — Parses SOURCE, VERIFICATION, and EVIDENCE entries from the release manifest.
- Hash Verification — Calculates SHA3-512 hashes and compares them with the expected manifest values.
- Release Auditor — Performs manifest validation, safe path resolution, duplicate detection, file validation, hash verification, and finding-scope validation.
- Findings Parser — Reads synthetic findings and assigns their explicitly declared audit scope.
- CLI — Runs the audit and reports the final pass/fail status.
- Tests — Covers manifest classification, verification failures, path validation, duplicate entries, findings, and CLI behavior.

The implementation is deterministic and does not require an LLM or external service.

## Project Structure

    release-manifest-audit/
    ├── src/
    │   └── release_audit/
    │       ├── auditor.py
    │       ├── cli.py
    │       ├── findings.py
    │       ├── hash_utils.py
    │       ├── models.py
    │       └── parser.py
    ├── tests/
    │   └── test_audit.py
    ├── data/
    │   ├── canonical/
    │   │   ├── app.py
    │   │   ├── security.py
    │   │   └── verification.py
    │   ├── noncanonical/
    │   │   ├── experiment.py
    │   │   └── old_version.py
    │   ├── findings.txt
    │   └── manifest.txt
    ├── .gitattributes
    └── README.md

## Requirements

- Python 3.10+
- pytest

Install pytest if required:

    pip install pytest

## Running the Audit

From the project root:

    PYTHONPATH=src python -m release_audit.cli --manifest data/manifest.txt --base-dir data --findings data/findings.txt

On Windows PowerShell:

    $env:PYTHONPATH="src"
    python -m release_audit.cli --manifest data/manifest.txt --base-dir data --findings data/findings.txt

The CLI prints the verification results, findings by scope, validation errors, and the final audit status.

## Manifest Format

The manifest contains entries in the following format:

    SOURCE: path/to/file.py:sha3-512-hash
    VERIFICATION: path/to/file.py:sha3-512-hash
    EVIDENCE: path/to/file.py:sha3-512-hash

### Entry Classification

| Entry Type | Audit Scope |
|---|---|
| SOURCE | Canonical |
| VERIFICATION | Canonical |
| EVIDENCE | Noncanonical |

Canonical entries represent the release verification scope.

Evidence entries remain visible but are kept separate from the canonical release scope.

## Verification Logic

### Empty Manifest

An empty manifest is rejected.

### Path Traversal

Manifest paths must remain inside the configured base directory.

Paths that resolve outside the base directory are rejected.

### Missing File

If a manifest references a file that does not exist, verification fails.

### Path Is Not a File

If a referenced path exists but is a directory, verification fails.

### Conflicting Duplicate Entries

Equivalent paths are normalized before duplicate validation.

For example:

    canonical/app.py
    canonical/./app.py

refer to the same logical path.

If duplicate entries for the same path contain conflicting entry types or hashes, the audit fails.

### SHA3-512 Hash Verification

Each manifest file is hashed using SHA3-512.

The calculated hash must match the hash recorded in the manifest.

A mismatch causes the audit to fail.

### Successful Verification

The manifest passes verification when all entries exist, are regular files, remain within the base directory, contain no conflicting duplicates, and their SHA3-512 hashes match their expected values.

## Audit Scopes

The manifest determines the audit scope of each entry.

- SOURCE → Canonical
- VERIFICATION → Canonical
- EVIDENCE → Noncanonical

Canonical and noncanonical results are kept separate throughout the audit.

## Findings

Findings use the following format:

    file_path|scope|severity|message

Example:

    canonical/app.py|canonical|MEDIUM|Example canonical finding
    noncanonical/experiment.py|noncanonical|LOW|Example noncanonical finding

The scope is explicitly declared in the findings file and is validated against the scope assigned by the manifest.

### Canonical Findings

Findings associated with canonical manifest entries are reported separately.

### Noncanonical Findings

Findings associated with noncanonical manifest entries are reported separately.

Noncanonical findings are never silently promoted into the canonical release scope.

### Finding Scope Mismatch

If a finding declares a scope that differs from the scope assigned to the same file by the manifest, it is reported as a finding scope error.

The audit fails when a finding scope conflicts with the manifest scope.

### Unmanifested Findings

If a finding references a file that does not appear in the manifest, it is not accepted into either audit scope.

It is reported as an unmanifested finding and causes the audit to fail.

This prevents findings from introducing files into the audit scope without a corresponding manifest entry.

## Audit Status

The CLI reports:

    AUDIT STATUS: PASSED

only when:

- all manifest entries pass verification;
- there are no conflicting duplicate entries;
- there are no finding scope errors;
- there are no unmanifested findings.

Otherwise it reports:

    AUDIT STATUS: FAILED

and returns a non-zero exit code.

## Tests

The project currently contains 15 automated tests.

Run them with:

    python -m pytest -q

The test suite covers:

- Manifest entry classification
- Successful manifest verification
- Missing files
- SHA3-512 hash mismatches
- Canonical and noncanonical findings
- Findings file parsing
- Empty manifests
- Path traversal
- Conflicting duplicate entries
- Equivalent duplicate paths
- Directories used as files
- Finding scope mismatches
- CLI failure for finding scope mismatches
- Unmanifested findings
- CLI failure for unmanifested findings

Current result:

    15 passed

## Design Notes

### Deterministic Verification

The audit logic is deterministic and based on explicit manifest data, filesystem state, and SHA3-512 hashes.

### Manifest as Scope Authority

The manifest determines whether a referenced file belongs to the canonical or noncanonical audit scope.

Finding data cannot override the scope assigned by the manifest.

### Findings Are Not Silently Discarded

Findings that cannot be safely associated with the manifest are reported separately as validation errors rather than being silently ignored.

### Safe Path Resolution

Manifest paths are resolved against the configured base directory and checked to ensure they remain within that directory.

### Synthetic Test Data

The files under data/ are synthetic fixtures created specifically for testing the prototype.

## Line Ending Consistency

The repository uses LF line endings for source and test files.

.gitattributes is included to help maintain consistent line endings across environments.

This is important because changing CRLF/LF line endings changes file hashes and can therefore affect SHA3-512 verification.
