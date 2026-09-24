import json
from pathlib import Path

from security_agent.checks.ast_utils import (
    iter_python_files,
    parse_python_file,
)


REQUIREMENT_ID = "ИБ-07"

REQUIREMENT = (
    "Проект должен иметь единый журнал действий пользователей, "
    "имеющих доступ к данным, а также журнал событий базы данных. "
    "Аудит должен применяться ко всему проекту, а не только к одному модулю."
)


def build_violation(
    file,
    line,
    evidence,
    explanation,
    recommendation,
):
    return {
        "requirement_id": REQUIREMENT_ID,
        "requirement": REQUIREMENT,
        "location": {
            "file": str(file),
            "line": line,
        },
        "evidence": evidence,
        "explanation": explanation,
        "criticality": "HIGH",
        "recommendation": recommendation,
    }


def check_project_audit(target="."):
    audit_found = False
    db_audit_found = False

    audit_location = None
    db_audit_location = None

    violations = []
    parse_errors = []

    for path in iter_python_files(target):
        if "security_agent" in path.parts:
            continue

        source, tree, error = parse_python_file(path)

        if error:
            parse_errors.append({
                "file": str(path),
                "error": error,
            })
            continue

        text = source.lower()

        if not audit_found and any(
            marker in text
            for marker in (
                "audit.record",
                "post_save.connect",
                "post_delete.connect",
                "user_logged_in.connect",
                "user_logged_out.connect",
            )
        ):
            audit_found = True
            audit_location = (
                path,
                1,
                source.splitlines()[0]
                if source.splitlines()
                else "",
            )

        if not db_audit_found and any(
            marker in text
            for marker in (
                "connection.execute",
                "cursor.execute",
                "set_trace_callback",
                "database_audit",
                "db_audit",
                "sql_audit",
            )
        ):
            db_audit_found = True
            db_audit_location = (
                path,
                1,
                source.splitlines()[0]
                if source.splitlines()
                else "",
            )

    if not audit_found:
        violations.append(
            build_violation(
                Path("project"),
                1,
                "По исходному коду проекта единый механизм "
                "пользовательского аудита не обнаружен.",
                "Не обнаружен единый механизм аудита действий "
                "пользователей во всём проекте.",
                "Реализовать централизованный журнал действий "
                "пользователей для всего проекта.",
            )
        )

    if not db_audit_found:
        violations.append(
            build_violation(
                Path("project"),
                1,
                "По исходному коду проекта отдельный механизм "
                "аудита событий базы данных не обнаружен.",
                "Не обнаружен отдельный журнал событий базы данных.",
                "Добавить аудит событий базы данных и обеспечить "
                "его централизованную регистрацию.",
            )
        )

    return {
        "requirement_id": REQUIREMENT_ID,
        "requirement": REQUIREMENT,
        "violations": violations,
        "parse_errors": parse_errors,
        "status": "VIOLATION" if violations else "PASS",
        "evidence": {
            "user_audit_found": audit_found,
            "user_audit_location": (
                str(audit_location[0])
                if audit_location
                else None
            ),
            "database_audit_found": db_audit_found,
            "database_audit_location": (
                str(db_audit_location[0])
                if db_audit_location
                else None
            ),
        },
    }


if __name__ == "__main__":
    result = check_project_audit(".")
    print(
        json.dumps(
            result,
            indent=2,
            ensure_ascii=False,
        )
    )
