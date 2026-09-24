import ast
import json
from pathlib import Path

from security_agent.checks.ast_utils import (
    iter_python_files,
    parse_python_file,
)


REQUIREMENT_ID = "ИБ-04"

REQUIREMENT = (
    "Персональные данные должны храниться с криптографической "
    "защитой с параметрами не ниже требований СТ РК 1073-2007. "
    "Пароли должны храниться с использованием bcrypt, argon2 или "
    "scrypt. Хранение паролей в открытом виде или использование "
    "обычных быстрых хешей без адаптивного алгоритма является нарушением."
)


ADAPTIVE_HASHERS = {
    "bcrypt",
    "argon2",
    "scrypt",
}


WEAK_HASHERS = {
    "md5",
    "sha1",
    "sha224",
    "sha256",
    "sha384",
    "sha512",
}


PASSWORD_FUNCTIONS = {
    "set_password",
    "make_password",
    "check_password",
}


PASSWORD_NAMES = {
    "password",
    "passwd",
    "password_hash",
    "passwordhash",
    "hashed_password",
    "password_digest",
}


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
    criticality="HIGH",
    recommendation=None,
):
    if recommendation is None:
        recommendation = (
            "Использовать bcrypt, argon2 или scrypt "
            "через безопасный механизм хранения паролей."
        )

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


def get_call_name(node):
    if not isinstance(node, ast.Call):
        return ""

    if isinstance(node.func, ast.Name):
        return node.func.id

    if isinstance(node.func, ast.Attribute):
        return node.func.attr

    return ""


def get_attribute_name(node):
    if isinstance(node, ast.Attribute):
        return node.attr

    if isinstance(node, ast.Name):
        return node.id

    return ""


def node_source(source, node):
    try:
        return ast.unparse(node)
    except Exception:
        return line_text(
            source,
            getattr(node, "lineno", 1),
        )


def contains_adaptive_hasher(node):
    text = node_source(
        "",
        node,
    ).lower()

    return any(
        hasher in text
        for hasher in ADAPTIVE_HASHERS
    )


def contains_weak_hasher(node):
    text = node_source(
        "",
        node,
    ).lower()

    return any(
        hasher in text
        for hasher in WEAK_HASHERS
    )


def is_password_name(name):
    normalized = name.lower().replace("-", "_")

    return (
        normalized in PASSWORD_NAMES
        or "password" in normalized
        or normalized == "passwd"
    )


def assignment_targets(node):
    if isinstance(node, ast.Assign):
        return node.targets

    if isinstance(node, ast.AnnAssign):
        return [node.target]

    return []


def target_is_password(target):
    if isinstance(target, ast.Name):
        return is_password_name(target.id)

    if isinstance(target, ast.Attribute):
        return is_password_name(target.attr)

    return False


def analyze_password_assignment(path, source, node):
    targets = assignment_targets(node)

    if not any(
        target_is_password(target)
        for target in targets
    ):
        return None

    value = getattr(
        node,
        "value",
        None,
    )

    if value is None:
        return None

    # Прямой вызов set_password/make_password/check_password
    # рассматривается как корректный механизм Django.
    if isinstance(value, ast.Call):
        call_name = get_call_name(value)

        if call_name in PASSWORD_FUNCTIONS:
            return None

    # Адаптивный алгоритм явно указан.
    if contains_adaptive_hasher(value):
        return None

    # Явный быстрый hash.
    if contains_weak_hasher(value):
        return build_violation(
            path,
            node.lineno,
            node_source(
                source,
                node,
            ),
            (
                "Для хранения пароля используется быстрый "
                "криптографический hash без обнаруженного "
                "адаптивного password hasher."
            ),
            "HIGH",
            (
                "Заменить MD5/SHA-1/SHA-2 или другой быстрый "
                "hash на bcrypt, argon2 или scrypt."
            ),
        )

    # Открытая строка.
    if isinstance(value, ast.Constant):
        if isinstance(value.value, str):
            return build_violation(
                path,
                node.lineno,
                node_source(
                    source,
                    node,
                ),
                (
                    "Пароль присваивается строковой константе, "
                    "что указывает на потенциальное хранение "
                    "пароля в открытом виде."
                ),
                "CRITICAL",
                (
                    "Не хранить пароль в открытом виде. "
                    "Использовать bcrypt, argon2 или scrypt."
                ),
            )

    return None


def analyze_password_calls(path, source, tree):
    violations = []

    for node in ast.walk(tree):

        if not isinstance(node, ast.Call):
            continue

        call_name = get_call_name(node)

        if call_name not in {
            "md5",
            "sha1",
            "sha224",
            "sha256",
            "sha384",
            "sha512",
        }:
            continue

        parent_context = node_source(
            source,
            node,
        ).lower()

        # Если hash явно связан с password,
        # считаем это нарушением.
        if "password" not in parent_context:
            continue

        violations.append(
            build_violation(
                path,
                node.lineno,
                line_text(
                    source,
                    node.lineno,
                ),
                (
                    f"Для обработки пароля используется "
                    f"быстрый hash {call_name.upper()}."
                ),
                "HIGH",
                (
                    "Использовать bcrypt, argon2 или scrypt "
                    "вместо быстрого hash."
                ),
            )
        )

    return violations


def analyze_password_fields(path, source, tree):
    violations = []

    for node in ast.walk(tree):

        if not isinstance(node, ast.Call):
            continue

        call_name = get_call_name(node)

        # Django model field:
        # password = models.CharField(...)
        if call_name not in {
            "CharField",
            "TextField",
        }:
            continue

        source_text = node_source(
            source,
            node,
        ).lower()

        if "password" not in source_text:
            continue

        # Само наличие поля password ещё не является
        # нарушением — Django может использовать его
        # совместно с password hasher.
        #
        # Поэтому здесь ничего не блокируем.
        continue

    return violations


def analyze_custom_hashers(path, source, tree):
    violations = []

    # Файл portal/hashers.py потенциально содержит
    # собственную реализацию password hashing.
    if path.name != "hashers.py":
        return violations

    text = source.lower()

    for weak in WEAK_HASHERS:

        if weak not in text:
            continue

        violations.append(
            build_violation(
                path,
                1,
                weak,
                (
                    "В файле пользовательских password hashers "
                    f"обнаружено использование {weak.upper()}."
                ),
                "HIGH",
                (
                    "Проверить реализацию custom password hasher. "
                    "Для хранения паролей использовать bcrypt, "
                    "argon2 или scrypt."
                ),
            )
        )

    return violations


def check_ib04(target="."):
    violations = []
    parse_errors = []

    root = Path(target)

    for path in iter_python_files(root):

        path_string = str(path)

        if path_string.startswith("security_agent/"):
            continue

        source, tree, error = parse_python_file(path)

        if error:
            parse_errors.append(
                {
                    "file": path_string,
                    "error": error,
                }
            )
            continue

        violations.extend(
            analyze_password_assignment(
                path,
                source,
                node,
            )
            for node in ast.walk(tree)
            if isinstance(
                node,
                (
                    ast.Assign,
                    ast.AnnAssign,
                ),
            )
        )

        violations.extend(
            analyze_password_calls(
                path,
                source,
                tree,
            )
        )

        violations.extend(
            analyze_password_fields(
                path,
                source,
                tree,
            )
        )

        violations.extend(
            analyze_custom_hashers(
                path,
                source,
                tree,
            )
        )

    # Убираем None.
    violations = [
        violation
        for violation in violations
        if violation is not None
    ]

    # Убираем дубликаты.
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
        "status": (
            "VIOLATION"
            if unique
            else "PASS"
        ),
    }


if __name__ == "__main__":
    result = check_ib04(".")

    print(
        json.dumps(
            result,
            indent=2,
            ensure_ascii=False,
        )
    )
