import argparse
from pathlib import Path

from .auditor import ReleaseAuditor
from .findings import parse_findings_file
from .parser import ManifestParser


def main():
    parser = argparse.ArgumentParser(
        description="Audit a release manifest using SHA3-512 verification."
    )

    parser.add_argument(
        "--manifest",
        required=True,
        help="Path to the release manifest.",
    )

    parser.add_argument(
        "--base-dir",
        required=True,
        help="Base directory containing the files referenced by the manifest.",
    )

    parser.add_argument(
        "--findings",
        required=False,
        help="Optional path to a findings file.",
    )

    args = parser.parse_args()

    manifest_path = Path(args.manifest)
    base_directory = Path(args.base_dir)

    entries = ManifestParser().parse_file(manifest_path)

    findings = []

    if args.findings:
        findings = parse_findings_file(Path(args.findings))

    report = ReleaseAuditor(base_directory).audit(
        entries,
        findings,
    )

    print("=== Release Audit Report ===")
    print()

    for result in report.results:
        print(
            f"[{result.status}] "
            f"{result.scope.value.upper()} | "
            f"{result.entry_type} | "
            f"{result.file_path} | "
            f"{result.message}"
        )

    print()
    print("=== Findings ===")

    print()
    print("Canonical findings:")

    if report.canonical_findings:
        for finding in report.canonical_findings:
            print(
                f"- [{finding.severity}] "
                f"{finding.file_path}: {finding.message}"
            )
    else:
        print("- None")

    print()
    print("Noncanonical findings:")

    if report.noncanonical_findings:
        for finding in report.noncanonical_findings:
            print(
                f"- [{finding.severity}] "
                f"{finding.file_path}: {finding.message}"
            )
    else:
        print("- None")

    print()

    failed_results = [
        result for result in report.results
        if result.status == "FAIL"
    ]

    if failed_results:
        print("AUDIT STATUS: FAILED")
        return 1

    print("AUDIT STATUS: PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())