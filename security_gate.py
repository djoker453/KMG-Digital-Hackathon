import json
import sys
from pathlib import Path


DEFAULT_REPORT_PATH = Path("security-reports/security-report.json")


def main():
    report_path = (
        Path(sys.argv[1])
        if len(sys.argv) > 1
        else DEFAULT_REPORT_PATH
    )

    if not report_path.exists():
        print("ERROR: Security report not found.")
        print(f"Path: {report_path}")
        sys.exit(2)

    try:
        with report_path.open(
            "r",
            encoding="utf-8",
        ) as file:
            report = json.load(file)
    except Exception as error:
        print(f"ERROR: Cannot read security report: {error}")
        sys.exit(2)

    ib_summary = report.get("ib_summary", {})

    violations = ib_summary.get("violations", 0)
    parse_errors = ib_summary.get("parse_errors", 0)

    print("========================================")
    print("          KMG SECURITY GATE")
    print("========================================")
    print()

    print(
        f"ИБ requirements: {ib_summary.get('total_requirements', 0)}"
    )
    print(
        f"ИБ PASS:         {ib_summary.get('passed', 0)}"
    )
    print(
        f"ИБ VIOLATIONS:   {violations}"
    )
    print(
        f"Parse errors:    {parse_errors}"
    )

    print()

    for requirement in report.get("requirements", []):
        print(
            f"{requirement.get('requirement_id')}: "
            f"{requirement.get('status')}"
        )

    print()

    if parse_errors > 0:
        print("STATUS: EMERGENCY")
        print("Reason: Project parse errors.")
        print("Exit code: 2")
        sys.exit(2)

    if violations > 0:
        print("STATUS: BLOCKED")
        print(
            "Reason: Information security violations detected."
        )
        print("Exit code: 1")
        sys.exit(1)

    print("STATUS: PASSED")
    print("No information security violations detected.")
    print("Exit code: 0")
    sys.exit(0)


if __name__ == "__main__":
    main()
