import json
import sys
from pathlib import Path


REPORT_PATH = Path("security-reports/security-report.json")


def main():
    if not REPORT_PATH.exists():
        print("ERROR: Security report not found.")
        sys.exit(1)

    with REPORT_PATH.open("r", encoding="utf-8") as file:
        report = json.load(file)

    summary = report.get("summary", {})

    critical = summary.get("critical", 0)
    high = summary.get("high", 0)
    medium = summary.get("medium", 0)
    low = summary.get("low", 0)

    print("========================================")
    print("          KMG SECURITY GATE")
    print("========================================")
    print()
    print(f"Critical: {critical}")
    print(f"High:     {high}")
    print(f"Medium:   {medium}")
    print(f"Low:      {low}")
    print()

    if critical > 0:
        print("STATUS: BLOCKED")
        print("Reason: Critical security findings detected.")
        sys.exit(1)

    if high > 0:
        print("STATUS: BLOCKED")
        print("Reason: High-risk security findings detected.")
        sys.exit(1)

    print("STATUS: PASSED")
    print("No Critical or High risk findings detected.")

    sys.exit(0)


if __name__ == "__main__":
    main()
