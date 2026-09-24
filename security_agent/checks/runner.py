import importlib


CHECKS = {
    "ib01_admin_access": "check_ib01",
    "ib02_session_token": "check_ib02",
    "ib03_tls": "check_ib03",
    "ib04_personal_data": "check_ib04",
    "ib05_audit_log": "check_ib05",
    "ib06_normative_links": "check_ib06",
    "ib07_activity_log": "check_project_audit",
    "ib08_data_export": "check_ib08",
}


def run_all_checks(target="."):
    results = []

    for module_name, function_name in CHECKS.items():
        module = importlib.import_module(
            f"security_agent.checks.{module_name}"
        )

        check_function = getattr(module, function_name)

        result = check_function(target)

        results.append({
            "requirement_id": result["requirement_id"],
            "requirement": result["requirement"],
            "status": result["status"],
            "violations": result.get("violations", []),
            "parse_errors": result.get("parse_errors", []),
        })

    return results


def build_summary(results):
    return {
        "total_requirements": len(results),
        "passed": sum(
            1 for result in results
            if result["status"] == "PASS"
        ),
        "violations": sum(
            1 for result in results
            if result["status"] == "VIOLATION"
        ),
        "parse_errors": sum(
            len(result["parse_errors"])
            for result in results
        ),
    }


if __name__ == "__main__":
    import json

    results = run_all_checks()

    output = {
        "checks": results,
        "summary": build_summary(results),
    }

    print(
        json.dumps(
            output,
            indent=2,
            ensure_ascii=False,
        )
    )
