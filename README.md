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
3. Checks whether referenced files exist.
4. Calculates their SHA3-512 hashes.
5. Compares actual hashes with the manifest.
6. Reports missing files and hash mismatches.
7. Keeps canonical and noncanonical findings separate.

For this prototype, `SOURCE` and `VERIFICATION` entries are treated as canonical, while `EVIDENCE` entries are treated as noncanonical. This is the synthetic scope convention used by the prototype.

## Project Structure

```text
release-manifest-audit/
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
## Verification Logic

Each manifest entry is checked independently.

### File Missing

If a referenced file does not exist, the audit reports:

    [FAIL] ... | File is missing

### Hash Mismatch

If the file exists but its SHA3-512 hash differs from the expected hash in the manifest:

    [FAIL] ... | SHA3-512 hash mismatch

### Successful Verification

If the file exists and its SHA3-512 hash matches:

    [PASS] ... | File exists and SHA3-512 hash matches
## Audit Scopes

For this prototype, the synthetic manifest convention is:

- `SOURCE` → Canonical
- `VERIFICATION` → Canonical
- `EVIDENCE` → Noncanonical

Canonical and noncanonical findings are reported separately.

Findings from noncanonical files are therefore not presented as canonical-release findings.
## Findings

Synthetic findings are supplied through `data/findings.txt`.

Each finding uses the following format:

    file_path|severity|message

Example:

    canonical/app.py|MEDIUM|Example canonical finding
    noncanonical/experiment.py|LOW|Example noncanonical finding

The audit report keeps findings from the canonical and noncanonical scopes separate.
## Tests

Run the test suite with:

    pytest -q

The tests cover:

- Manifest entry classification
- Successful SHA3-512 verification
- Missing file detection
- Hash mismatch detection
- Canonical finding separation
- Noncanonical finding separation
- Findings-file parsing

The test suite contains six tests covering the core audit requirements
## Design Notes

This project is intentionally small and standalone.

The implementation is divided into focused components:

- `parser.py` — parses manifest entries
- `models.py` — defines manifest entry and scope models
- `hash_utils.py` — calculates and verifies SHA3-512 hashes
- `auditor.py` — performs release auditing and separates findings
- `findings.py` — parses synthetic findings
- `cli.py` — provides the command-line interface

The manifest, source files, and findings are synthetic test data created specifically for this prototype.

The prototype focuses on deterministic file verification and audit-scope separation without requiring an external service or LLM.
