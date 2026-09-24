import json

from security_agent.checks.ast_utils import (
    iter_python_files,
    parse_python_file,
)


REQUIREMENT_ID = "ИБ-05"

REQUIREMENT = (
    "Локальные журналы приложения должны быть защищены от изменения "
    "пользователем до передачи на сервер. При необходимости хранения "
    "локальной копии персональные данные и содержимое журнала должны "
    "быть защищены криптографическими средствами."
)


def line_text(source, line):
    lines = source.splitlines()

    if 1 <= line <= len(lines):
        return lines[line - 1].strip()

    return ""


def build_violation(
    path,
    line,
    evidence,
    explanation,
    criticality,
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
        "criticality": criticality,
        "recommendation": recommendation,
    }


def find_audit_files(target):
    files = []

    for path in iter_python_files(target):
        name = path.name.lower()

        if name in {
            "audit.py",
            "logging.py",
            "logger.py",
            "journal.py",
            "audit_log.py",
        }:
            files.append(path)

    return files


def analyze_audit_file(path, source, tree):
    violations = []

    text = source.lower()

    has_encryption = any(
        value in text
        for value in (
            "aesgcm",
            "fernet",
            "chacha20poly1305",
            "encrypt(",
        )
    )

    has_local_write = any(
        value in text
        for value in (
            "write_bytes",
            "write_text",
            "open(",
            "filehandler",
        )
    )

    has_authenticated_encryption = any(
        value in text
        for value in (
            "aesgcm",
            "fernet",
            "chacha20poly1305",
        )
    )

    has_integrity_protection = any(
        value in text
        for value in (
            "hmac",
            "hash_hmac",
            "signature",
            "sign(",
            "verify(",
            "mac",
        )
    )

    has_remote_transfer = any(
        value in text
        for value in (
            "requests.post",
            "requests.put",
            "httpx.post",
            "httpx.put",
            "urllib.request",
            "upload",
            "send_event",
            "send_log",
            "transmit",
        )
    )

    if has_local_write and not has_encryption:
        violations.append(
            build_violation(
                path,
                1,
                line_text(source, 1),
                "Локальный журнал записывается на диск, "
                "но криптографическая защита содержимого "
                "журнала не обнаружена.",
                "HIGH",
                "Защитить локальную копию журнала "
                "криптографическим средством, например "
                "аутентифицированным шифрованием.",
            )
        )

    if has_local_write and has_encryption:
        if has_authenticated_encryption:
            pass
        elif not has_integrity_protection:
            violations.append(
                build_violation(
                    path,
                    1,
                    line_text(source, 1),
                    "Журнал шифруется, но отдельный механизм "
                    "контроля целостности не обнаружен.",
                    "MEDIUM",
                    "Использовать аутентифицированное шифрование "
                    "или добавить отдельный механизм контроля "
                    "целостности.",
                )
            )

    if has_local_write and not has_remote_transfer:
        violations.append(
            build_violation(
                path,
                1,
                line_text(source, 1),
                "Механизм передачи накопленного локального "
                "журнала на сервер не обнаружен.",
                "MEDIUM",
                "Реализовать защищённую передачу журнала "
                "на сервер и удалённое хранение аудита.",
            )
        )

    return violations


def check_ib05(target="."):
    violations = []
    parse_errors = []

    audit_files = find_audit_files(target)

    for path in audit_files:
        source, tree, error = parse_python_file(path)

        if error:
            parse_errors.append({
                "file": str(path),
                "error": error,
            })
            continue

        violations.extend(
            analyze_audit_file(
                path,
                source,
                tree,
            )
        )

    return {
        "requirement_id": REQUIREMENT_ID,
        "requirement": REQUIREMENT,
        "violations": violations,
        "parse_errors": parse_errors,
        "status": (
            "VIOLATION"
            if violations
            else "PASS"
        ),
    }


if __name__ == "__main__":
    result = check_ib05(".")

    print(
        json.dumps(
            result,
            indent=2,
            ensure_ascii=False,
        )
    )
