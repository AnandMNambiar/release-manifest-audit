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

    if report.finding_scope_errors:
        print()
        print("Finding scope errors:")

        for finding in report.finding_scope_errors:
            print(
                f"- [{finding.severity}] "
                f"{finding.file_path}: "
                "Finding scope conflicts with the manifest scope"
            )

    if report.unmanifested_findings:
        print()
        print("Unmanifested findings:")

        for finding in report.unmanifested_findings:
            print(
                f"- [{finding.severity}] "
                f"{finding.file_path}: "
                "Finding refers to a file that is not present in the manifest"
            )

    print()

    failed_results = [
        result
        for result in report.results
        if result.status == "FAIL"
    ]

    has_scope_errors = bool(report.finding_scope_errors)
    has_unmanifested_findings = bool(report.unmanifested_findings)

    if (
        failed_results
        or has_scope_errors
        or has_unmanifested_findings
    ):
        print("AUDIT STATUS: FAILED")
        return 1

    print("AUDIT STATUS: PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())