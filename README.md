# Release Manifest Audit

A small standalone Python prototype for verifying release-manifest integrity using SHA3-512 hashes and separating audit findings into canonical and noncanonical scopes.

## Overview

The prototype reads a synthetic release manifest containing:

- `SOURCE` entries
- `VERIFICATION` entries
- `EVIDENCE` entries

Each manifest entry contains a file path and an expected SHA3-512 hash.

The auditor:

1. Parses the manifest.
2. Classifies entries into canonical or noncanonical scope.
3. Checks whether the referenced path stays within the configured base directory.
4. Checks whether the referenced path exists and is a file.
5. Calculates its SHA3-512 hash.
6. Compares the actual hash with the manifest.
7. Detects conflicting duplicate manifest entries.
8. Rejects an empty manifest.
9. Separates findings by audit scope.
10. Detects findings whose scope conflicts with the corresponding manifest entry.

For this prototype, `SOURCE` and `VERIFICATION` entries are treated as canonical, while `EVIDENCE` entries are treated as noncanonical. This is the synthetic scope convention used by the prototype.
## Project Structure

```text
release-manifest-audit/
├── .gitattributes
├── data/
│   ├── canonical/
│   │   ├── app.py
│   │   ├── security.py
│   │   └── verification.py
│   ├── noncanonical/
│   │   ├── old_version.py
│   │   └── experiment.py
│   ├── findings.txt
│   └── manifest.txt
│
├── src/
│   └── release_audit/
│       ├── __init__.py
│       ├── auditor.py
│       ├── cli.py
│       ├── findings.py
│       ├── hash_utils.py
│       ├── models.py
│       └── parser.py
│
└── tests/
    └── test_audit.py
```
## Requirements

- Python 3.10+
- pytest

The prototype uses only Python standard-library modules at runtime.

## Setup

Clone the repository and move into the project directory:

    git clone https://github.com/AnandMNambiar/release-manifest-audit.git
    cd release-manifest-audit

Install pytest:

    python -m pip install pytest

Set the source directory on `PYTHONPATH`:

    $env:PYTHONPATH="src"
## Run the Audit

Run the prototype with:

    python -m release_audit.cli --manifest data/manifest.txt --base-dir data --findings data/findings.txt

The audit reports the scope, entry type, verification status, and result for each manifest entry.

A successful verification means the referenced path exists, is a file, and its SHA3-512 hash matches the expected hash in the manifest.
## Verification Logic

Each manifest entry is checked independently.

### Empty Manifest

An empty manifest is rejected because a release audit must contain at least one manifest entry.

    [FAIL] ... | Manifest contains no entries

### Path Traversal

Manifest paths are resolved against the configured base directory.

If a path resolves outside the base directory, the audit rejects it:

    [FAIL] ... | File path escapes the base directory

This prevents manifest entries from referencing files outside the intended audit scope.

### File Missing

If a referenced file does not exist, the audit reports:

    [FAIL] ... | File is missing

### Path Is Not a File

If a referenced path exists but points to a directory or another non-file path, the audit reports:

    [FAIL] ... | Path is not a file

### Conflicting Duplicate Entries

If the manifest contains multiple entries for the same file with different entry types or different expected hashes, the conflicting entry is rejected:

    [FAIL] ... | Conflicting duplicate manifest entry

### Hash Mismatch

If the file exists and is a regular file but its SHA3-512 hash differs from the expected hash in the manifest:

    [FAIL] ... | SHA3-512 hash mismatch

### Successful Verification

If the referenced path exists, is a file, and its SHA3-512 hash matches:

    [PASS] ... | File exists and SHA3-512 hash matches

SHA3-512 verification is performed against the file's actual bytes.
## Audit Scopes

For this prototype, the synthetic manifest convention is:

- `SOURCE` → Canonical
- `VERIFICATION` → Canonical
- `EVIDENCE` → Noncanonical

Canonical and noncanonical findings are reported separately.

The auditor also checks that a finding's scope agrees with the scope assigned to the same file by the manifest.

If a finding has a different scope from its corresponding manifest entry, it is reported as a scope error instead of being silently placed into the wrong audit scope.

Findings from noncanonical files are therefore not presented as canonical-release findings.
## Findings

Synthetic findings are supplied through `data/findings.txt`.

Each finding uses the following format:

    file_path|severity|message

Example:

    canonical/app.py|MEDIUM|Example canonical finding
    noncanonical/experiment.py|LOW|Example noncanonical finding

The audit report separates findings into canonical and noncanonical scopes.

A finding is also checked against the manifest entry for the same file. If the finding's declared scope conflicts with the manifest-defined scope, the finding is reported separately as a scope error rather than being included in either canonical or noncanonical findings.
## Tests

Run the test suite with:

    python -m pytest -q

The test suite contains 10 tests covering:

- Manifest entry classification
- Successful SHA3-512 verification
- Missing file detection
- Hash mismatch detection
- Canonical and noncanonical finding separation
- Findings-file parsing
- Empty manifest rejection
- Path traversal protection
- Conflicting duplicate manifest detection
- Directory used as a file detection
- Finding scope mismatch detection

The tests verify both the expected successful audit path and the failure conditions identified in the audit requirements.
## Design Notes

This project is intentionally small and standalone.

The implementation is divided into focused components:

- `parser.py` — parses manifest entries
- `models.py` — defines manifest entry and scope models
- `hash_utils.py` — calculates and verifies SHA3-512 hashes
- `auditor.py` — performs release auditing, validates paths and duplicates, and separates findings
- `findings.py` — parses synthetic findings
- `cli.py` — provides the command-line interface

The manifest, source files, and findings are synthetic test data created specifically for this prototype.

The prototype focuses on deterministic file verification and audit-scope separation without requiring an external service or LLM.

The `.gitattributes` file configures Git to use LF line endings for Python and text files, helping keep the synthetic release data consistent across environments.
