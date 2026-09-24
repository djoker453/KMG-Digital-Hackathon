import ast
import json
from pathlib import Path

from security_agent.checks.ast_utils import (
    get_decorators,
    get_function_source,
    iter_python_files,
    parse_python_file,
)


REQUIREMENT_ID = "ИБ-08"

REQUIREMENT = (
    "Экспорт персональных данных должен быть доступен только администратору. "
    "Каждая операция экспорта должна регистрироваться в журнале аудита."
)


def build_violation(
    path,
    line,
    evidence,
    explanation,
    recommendation,
):
    return {
        "requirement_id": REQUIREMENT_ID,
        "requirement": REQUIREMENT,
        "location": {
            "file": str(path),
            "line": line,
        },
        "evidence": evidence,
        "explanation": explanation,
        "criticality": "HIGH",
        "recommendation": recommendation,
    }


def is_export_function(function):
    name = function.name.lower()

    return name in {
        "export_csv",
        "export_json",
    }


def has_admin_protection(function):
    decorators = get_decorators(function)

    return any(
        decorator in {
            "admin_required",
            "access.admin_required",
        }
        for decorator in decorators
    )


def has_audit_record(function):
    source = ast.unparse(function).lower()

    return "audit.record" in source


def check_ib08(target="."):
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

        for node in ast.walk(tree):
            if not isinstance(
                node,
                (ast.FunctionDef, ast.AsyncFunctionDef),
            ):
                continue

            if not is_export_function(node):
                continue

            evidence = get_function_source(source, node)

            if not has_admin_protection(node):
                violations.append(
                    build_violation(
                        path,
                        node.lineno,
                        evidence,
                        "Функция экспорта персональных данных не защищена "
                        "администраторской проверкой.",
                        "Ограничить экспорт только администратором "
                        "с серверной проверкой роли."
                    )
                )

            if not has_audit_record(node):
                violations.append(
                    build_violation(
                        path,
                        node.lineno,
                        evidence,
                        "Операция экспорта не регистрируется "
                        "в журнале аудита.",
                        "Добавить audit.record для каждой операции экспорта."
                    )
                )

    unique = []
    seen = set()

    for violation in violations:
        location = violation["location"]

        key = (
            location["file"],
            location["line"],
            violation["explanation"],
        )

        if key in seen:
            continue

        seen.add(key)
        unique.append(violation)

    return {
        "requirement_id": REQUIREMENT_ID,
        "requirement": REQUIREMENT,
        "violations": unique,
        "parse_errors": parse_errors,
        "status": "VIOLATION" if unique else "PASS",
    }


if __name__ == "__main__":
    result = check_ib08(".")
    print(json.dumps(result, indent=2, ensure_ascii=False))
