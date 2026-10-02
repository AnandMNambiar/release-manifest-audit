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
