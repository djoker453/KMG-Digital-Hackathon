import sys
from datetime import datetime, timezone

from security_agent.scanners.semgrep import run_semgrep
from security_agent.checks.runner import (
    run_all_checks,
    build_summary as build_ib_summary,
)
from security_agent.risk.analyzer import analyze_findings
from security_agent.ai.analyzer import analyze_finding
from security_agent.report.generator import generate_report


def run_security_analysis(
    target=".",
    use_ai=True,
    report_dir="/tmp/kmg-security-reports",
    start_time = datetime.now(timezone.utc)
):

    print("========================================")
    print("      KMG SECURITY AI AGENT")
    print("========================================")
    print()

    print("[0/4] Проверка требований ИБ-01 ... ИБ-08...")

    ib_results = run_all_checks(target)
    ib_summary = build_ib_summary(ib_results)

    print(
        f"Проверка ИБ завершена: "
        f"{ib_summary['passed']} PASS, "
        f"{ib_summary['violations']} VIOLATION, "
        f"{ib_summary['parse_errors']} PARSE ERRORS"
    )

    print()

    for result in ib_results:
        print(
            f"  {result['requirement_id']}: "
            f"{result['status']} "
            f"({len(result['violations'])} нарушений)"
        )

    print()
    print("[1/4] Запуск Semgrep...")

    semgrep_result = run_semgrep(
    target,
    report_dir=report_dir,
)

    if not semgrep_result["success"]:
        print("Ошибка Semgrep:")
        print(semgrep_result.get("error"))
        return 2

    print(
        f"Semgrep завершён. "
        f"Найдено: {semgrep_result['findings_count']}"
    )

    print()
    print("[2/4] Анализ уровня риска...")

    risk_result = analyze_findings(
        semgrep_result["results"]
    )

    summary = risk_result["summary"]

    print("Анализ риска завершён.")

    print()
    print("Risk Summary:")
    print(f"  Critical: {summary['critical']}")
    print(f"  High:     {summary['high']}")
    print(f"  Medium:   {summary['medium']}")
    print(f"  Low:      {summary['low']}")

    print()

    if use_ai:
        print("[3/4] AI-анализ Qwen...")

        findings = risk_result["findings"]

        ai_findings = [
            finding
            for finding in findings
            if finding["risk"] in ["HIGH", "MEDIUM"]
        ]

        max_ai_requests = 3
        ai_findings = ai_findings[:max_ai_requests]

        print(
            f"В AI будет отправлено максимум: "
            f"{len(ai_findings)}"
        )

        for index, finding in enumerate(
            ai_findings,
            start=1,
        ):
            print()
            print(
                f"AI анализ {index}/{len(ai_findings)}:"
            )
            print(f"  Rule: {finding['rule']}")
            print(f"  File: {finding['file']}")
            print(f"  Line: {finding['line']}")
            print(f"  Risk: {finding['risk']}")

            ai_result = analyze_finding(finding)

            if ai_result["success"]:
                finding["ai_analysis"] = ai_result["analysis"]
                finding["ai_provider"] = ai_result["provider"]
                finding["ai_model"] = ai_result["model"]

                print("  ✓ Qwen анализ завершён")

            else:
                error = ai_result.get(
                    "error",
                    "Неизвестная ошибка AI",
                )

                print("  ✗ AI временно недоступен")
                print(f"    {error}")

                print()
                print("STATUS: EMERGENCY")
                print("Reason: AI model unavailable.")
                print("Exit code: 2")

                return 2

    else:
        print("[3/4] AI-анализ пропущен (--no-ai)")

    print()
    print("[4/4] Сохранение отчёта...")

    end_time = datetime.now(timezone.utc)

    report = generate_report(
        ib_results=ib_results,
        ib_summary=ib_summary,
        semgrep_result=semgrep_result,
        risk_result=risk_result,
        start_time=start_time,
        end_time=end_time,
        target=target,
        report_dir=report_dir,
    )

    print(
        "JSON отчёт: "
        "security-reports/security-report.json"
    )

    print(
        "Markdown отчёт: "
        "security-reports/security-report.md"
    )

    print()
    print("========================================")
    print("           SECURITY SUMMARY")
    print("========================================")

    print(
        f"ИБ requirements: "
        f"{ib_summary['total_requirements']}"
    )

    print(
        f"ИБ PASS:         "
        f"{ib_summary['passed']}"
    )

    print(
        f"ИБ VIOLATIONS:   "
        f"{ib_summary['violations']}"
    )

    print(
        f"ИБ parse errors: "
        f"{ib_summary['parse_errors']}"
    )

    print()
    print(f"Semgrep findings: {summary['total']}")
    print(f"Critical:         {summary['critical']}")
    print(f"High:             {summary['high']}")
    print(f"Medium:           {summary['medium']}")
    print(f"Low:              {summary['low']}")

    print()
    print(
        f"Overall result:   "
        f"{report['overall_result']}"
    )

    print("========================================")

    return 0


if __name__ == "__main__":
    use_ai = "--no-ai" not in sys.argv

    exit_code = run_security_analysis(
        use_ai=use_ai
    )

    sys.exit(exit_code)
