import json
from pathlib import Path

from security_agent.scanners.semgrep import run_semgrep
from security_agent.risk.analyzer import analyze_findings
from security_agent.ai.analyzer import analyze_finding


def run_security_analysis(target="."):
    print("========================================")
    print("      KMG SECURITY AI AGENT")
    print("========================================")
    print()

    # ========================================
    # 1. SEMGREP
    # ========================================

    print("[1/4] Запуск Semgrep...")

    semgrep_result = run_semgrep(target)

    if not semgrep_result["success"]:
        print("Ошибка Semgrep:")
        print(semgrep_result.get("error"))
        return False

    print(
        f"Semgrep завершён. "
        f"Найдено: {semgrep_result['findings_count']}"
    )

    # ========================================
    # 2. RISK ENGINE
    # ========================================

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

    # ========================================
    # 3. QWEN AI ANALYSIS
    # ========================================

    print()
    print("[3/4] AI-анализ Qwen...")

    findings = risk_result["findings"]

    # Выбираем только HIGH и MEDIUM
    ai_findings = [
        finding
        for finding in findings
        if finding["risk"] in ["HIGH", "MEDIUM"]
    ]

    # Бесплатный API имеет ограничение запросов.
    # За один запуск анализируем максимум 3 находки.
    max_ai_requests = 3
    ai_findings = ai_findings[:max_ai_requests]

    print(
        f"В AI будет отправлено максимум: "
        f"{len(ai_findings)}"
    )

    for index, finding in enumerate(ai_findings, start=1):
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
            finding["ai_analysis"] = None
            finding["ai_error"] = ai_result["error"]

            print("  ✗ AI временно недоступен")
            print(f"    {ai_result['error']}")

            # Если получили rate limit,
            # прекращаем дальнейшие AI-запросы.
            if "429" in ai_result["error"]:
                print()
                print(
                    "Получен HTTP 429. "
                    "Останавливаем AI-запросы."
                )
                break

    # ========================================
    # 4. SAVE REPORT
    # ========================================

    print()
    print("[4/4] Сохранение отчёта...")

    report = {
        "agent": "KMG Security AI Agent",
        "ai_provider": "openrouter",
        "ai_model": "qwen/qwen3.8-27b:free",
        "semgrep_version": semgrep_result["semgrep_version"],
        "summary": summary,
        "findings": findings,
    }

    report_path = Path(
        "security-reports/security-report.json"
    )

    report_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    report_path.write_text(
        json.dumps(
            report,
            indent=4,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    print(
        f"Отчёт сохранён: {report_path}"
    )

    # ========================================
    # FINAL SUMMARY
    # ========================================

    print()
    print("========================================")
    print("           SECURITY SUMMARY")
    print("========================================")

    print(f"Total:    {summary['total']}")
    print(f"Critical: {summary['critical']}")
    print(f"High:     {summary['high']}")
    print(f"Medium:   {summary['medium']}")
    print(f"Low:      {summary['low']}")

    print("========================================")

    return True


if __name__ == "__main__":
    success = run_security_analysis()

    if not success:
        raise SystemExit(1)

