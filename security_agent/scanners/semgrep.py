import json
import subprocess
from pathlib import Path


def run_semgrep(
    target=".",
    report_dir="/tmp/kmg-security-reports",
):
    report_dir = Path(report_dir)
    report_dir.mkdir(parents=True, exist_ok=True)

    report_path = report_dir / "semgrep.json"

    command = [
        "semgrep",
        "scan",
        "--config=auto",
        "--json",
        target,
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        return {
            "success": False,
            "error": "Semgrep не установлен или не найден в PATH.",
            "results": [],
        }

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return {
            "success": False,
            "error": "Semgrep вернул некорректный JSON.",
            "stdout": result.stdout,
            "stderr": result.stderr,
            "results": [],
        }

    report_path.write_text(
        json.dumps(
            data,
            indent=4,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    findings = []

    for item in data.get("results", []):
        extra = item.get("extra", {})
        metadata = extra.get("metadata", {})

        findings.append(
            {
                "rule": item.get("check_id"),
                "file": item.get("path"),
                "line": item.get("start", {}).get("line"),
                "severity": extra.get("severity"),
                "message": extra.get("message"),
                "confidence": metadata.get("confidence"),
                "likelihood": metadata.get("likelihood"),
                "impact": metadata.get("impact"),
                "cwe": metadata.get("cwe", []),
                "owasp": metadata.get("owasp", []),
            }
        )

    return {
        "success": True,
        "semgrep_version": data.get("version"),
        "findings_count": len(findings),
        "results": findings,
        "report_path": str(report_path),
    }
