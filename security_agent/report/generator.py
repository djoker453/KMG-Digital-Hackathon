import json
import subprocess
from datetime import datetime
from pathlib import Path


def generate_report(
    ib_results,
    ib_summary,
    semgrep_result,
    risk_result,
    start_time,
    end_time,
    target=".",
    report_dir="security-reports",
):
    duration = (end_time - start_time).total_seconds()

    commit_id = "unknown"

    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=False,
            cwd=target,
        )

        if result.returncode == 0:
            commit_id = result.stdout.strip()

    except Exception:
        pass

    overall_result = (
        "VIOLATION"
        if ib_summary["violations"] > 0
        else "PASS"
    )

    report = {
        "agent": "KMG Security AI Agent",
        "commit_id": commit_id,
        "target": str(target),
        "start_time": start_time.isoformat(),
        "end_time": end_time.isoformat(),
        "duration_seconds": duration,
        "overall_result": overall_result,
        "violation_count": sum(
            len(result["violations"])
            for result in ib_results
        ),
        "requirements": ib_results,
        "ib_summary": ib_summary,
        "semgrep": {
            "version": semgrep_result.get(
                "semgrep_version"
            ),
            "findings_count": semgrep_result.get(
                "findings_count",
                0,
            ),
        },
        "risk_summary": risk_result.get(
            "summary",
            {},
        ),
    }

    report_dir = Path(report_dir)

    report_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    json_path = (
        report_dir / "security-report.json"
    )

    json_path.write_text(
        json.dumps(
            report,
            indent=4,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    markdown = build_markdown_report(report)

    markdown_path = (
        report_dir / "security-report.md"
    )

    markdown_path.write_text(
        markdown,
        encoding="utf-8",
    )

    return report


def build_markdown_report(report):
    lines = []

    lines.append(
        "# KMG Security AI Agent — Security Report"
    )
    lines.append("")

    lines.append(
        f"**Commit:** `{report['commit_id']}`"
    )

    lines.append(
        f"**Start:** {report['start_time']}"
    )

    lines.append(
        f"**End:** {report['end_time']}"
    )

    lines.append(
        f"**Duration:** "
        f"{report['duration_seconds']:.2f} seconds"
    )

    lines.append(
        f"**Overall result:** "
        f"**{report['overall_result']}**"
    )

    lines.append(
        f"**Violations:** "
        f"{report['violation_count']}"
    )

    lines.append("")

    lines.append("## Requirements")
    lines.append("")

    for result in report["requirements"]:

        lines.append(
            f"### {result['requirement_id']} — "
            f"{result['status']}"
        )

        lines.append("")

        lines.append(
            f"**Requirement:** "
            f"{result['requirement']}"
        )

        lines.append("")

        violations = result.get(
            "violations",
            [],
        )

        if not violations:

            lines.append(
                "Нарушений не обнаружено."
            )

            lines.append("")

            continue

        for number, violation in enumerate(
            violations,
            start=1,
        ):

            location = violation.get(
                "location",
                {},
            )

            lines.append(
                f"#### Нарушение {number}"
            )

            lines.append("")

            lines.append(
                f"**Location:** "
                f"`{location.get('file', 'unknown')}:"
                f"{location.get('line', '?')}`"
            )

            lines.append("")

            lines.append("**Code:**")
            lines.append("")

            lines.append("```text")

            lines.append(
                violation.get(
                    "evidence",
                    "",
                )
            )

            lines.append("```")
            lines.append("")

            lines.append(
                f"**Rationale:** "
                f"{violation.get('explanation', '')}"
            )

            lines.append("")

            lines.append(
                f"**Criticality:** "
                f"{violation.get('criticality', 'UNKNOWN')}"
            )

            lines.append("")

            lines.append(
                f"**Remediation:** "
                f"{violation.get('recommendation', '')}"
            )

            lines.append("")

    lines.append("## Summary")
    lines.append("")

    lines.append(
        f"- Requirements checked: "
        f"{report['ib_summary']['total_requirements']}"
    )

    lines.append(
        f"- Passed: "
        f"{report['ib_summary']['passed']}"
    )

    lines.append(
        f"- Requirements with violations: "
        f"{report['ib_summary']['violations']}"
    )

    lines.append(
        f"- Parse errors: "
        f"{report['ib_summary']['parse_errors']}"
    )

    lines.append(
        f"- Total violations: "
        f"{report['violation_count']}"
    )

    lines.append("")

    return "\n".join(lines)
