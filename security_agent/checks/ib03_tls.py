import json
import re
from pathlib import Path


REQUIREMENT_ID = "ИБ-03"

REQUIREMENT = (
    "Обмен данными между клиентом и сервером должен выполняться "
    "исключительно по TLS версии не ниже 1.2 с использованием "
    "стойких наборов шифров. Разрешение незащищённой передачи, "
    "старых версий протокола или слабых шифров является нарушением."
)


CONFIG_NAMES = {
    "settings.py",
    "config.py",
    "proxy.json",
    "nginx.conf",
    "httpd.conf",
    "apache.conf",
    "haproxy.cfg",
    "traefik.yml",
    "traefik.yaml",
    "docker-compose.yml",
    "docker-compose.yaml",
    "Dockerfile",
    ".env",
}


CONFIG_EXTENSIONS = {
    ".py",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".ini",
    ".cfg",
    ".conf",
    ".cnf",
    ".env",
    ".sh",
}


IGNORED_PARTS = {
    ".git",
    ".venv",
    "__pycache__",
    "security-reports",
    "node_modules",
    "vendor",
}


WEAK_PROTOCOL_PATTERNS = (
    (
        r"\bSSLv3\b",
        "Разрешён устаревший протокол SSLv3.",
    ),
    (
        r"\bTLSv1\.0\b",
        "Разрешён устаревший TLS 1.0.",
    ),
    (
        r"\bTLSv1\.1\b",
        "Разрешён устаревший TLS 1.1.",
    ),
    (
        r"\bTLS_?v?1_?0\b",
        "Обнаружена настройка TLS 1.0.",
    ),
    (
        r"\bTLS_?v?1_?1\b",
        "Обнаружена настройка TLS 1.1.",
    ),
    (
        r"\bPROTOCOL_TLSv1\b",
        "Используется устаревший TLS 1.0.",
    ),
    (
        r"\bPROTOCOL_TLSv1_1\b",
        "Используется устаревший TLS 1.1.",
    ),
)


WEAK_CIPHER_PATTERNS = (
    (
        r"(?:cipher|ciphers|ssl_ciphers)\s*[:=]\s*['\"][^'\"]*\bRC4\b",
        "Конфигурация cipher suites разрешает RC4.",
    ),
    (
        r"(?:cipher|ciphers|ssl_ciphers)\s*[:=]\s*['\"][^'\"]*\b3DES\b",
        "Конфигурация cipher suites разрешает 3DES.",
    ),
    (
        r"(?:cipher|ciphers|ssl_ciphers)\s*[:=]\s*['\"][^'\"]*\bDES\b",
        "Конфигурация cipher suites разрешает DES.",
    ),
    (
        r"(?:cipher|ciphers|ssl_ciphers)\s*[:=]\s*['\"][^'\"]*\bNULL\b",
        "Конфигурация cipher suites разрешает NULL cipher.",
    ),
    (
        r"(?:cipher|ciphers|ssl_ciphers)\s*[:=]\s*['\"][^'\"]*\bEXPORT\b",
        "Конфигурация cipher suites разрешает EXPORT cipher.",
    ),
    (
        r"(?:cipher|ciphers|ssl_ciphers)\s*[:=]\s*['\"][^'\"]*\bANON\b",
        "Конфигурация cipher suites разрешает анонимные cipher suites.",
    ),
)


def should_ignore(path):
    parts = set(path.parts)

    # Никогда не анализируем код самого security-agent.
    if "security_agent" in parts:
        return True

    # Не анализируем сторонний helpdesk-код.
    if "src" in parts and "helpdesk" in parts:
        return True

    return any(
        part in IGNORED_PARTS
        for part in path.parts
    )


def is_config_file(path):
    if path.name in CONFIG_NAMES:
        return True

    return path.suffix.lower() in CONFIG_EXTENSIONS


def line_number(text, position):
    return text.count("\n", 0, position) + 1


def line_text(text, line):
    lines = text.splitlines()

    if 1 <= line <= len(lines):
        return lines[line - 1].strip()

    return ""


def build_violation(path, line, evidence, explanation):
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
        "recommendation": (
            "Удалить поддержку устаревших TLS/SSL протоколов "
            "и слабых cipher suites. Использовать TLS 1.2 "
            "или новее и современные стойкие наборы шифров. "
            "Для веб-приложения включить принудительный HTTPS."
        ),
    }


def scan_protocols(path, text):
    violations = []

    for pattern, explanation in WEAK_PROTOCOL_PATTERNS:
        for match in re.finditer(
            pattern,
            text,
            flags=re.IGNORECASE,
        ):
            line = line_number(text, match.start())

            violations.append(
                build_violation(
                    path,
                    line,
                    line_text(text, line),
                    explanation,
                )
            )

    return violations


def scan_ciphers(path, text):
    violations = []

    for pattern, explanation in WEAK_CIPHER_PATTERNS:
        for match in re.finditer(
            pattern,
            text,
            flags=re.IGNORECASE,
        ):
            line = line_number(text, match.start())

            violations.append(
                build_violation(
                    path,
                    line,
                    line_text(text, line),
                    explanation,
                )
            )

    return violations


def scan_http_redirect(path, text):
    violations = []

    patterns = (
        (
            r"\bSECURE_SSL_REDIRECT\s*=\s*False\b",
            "Django SECURE_SSL_REDIRECT отключён, поэтому приложение не требует HTTPS redirect.",
        ),
        (
            r"\bSECURE_SSL_REDIRECT\s*=\s*false\b",
            "Django SECURE_SSL_REDIRECT отключён, поэтому приложение не требует HTTPS redirect.",
        ),
        (
            r"\bssl_redirect\s*[:=]\s*(?:False|false)\b",
            "SSL redirect отключён.",
        ),
        (
            r"\bsecure_ssl_redirect\s*[:=]\s*(?:False|false)\b",
            "Безопасный SSL redirect отключён.",
        ),
        (
            r"\ballow_http\s*[:=]\s*(?:True|true)\b",
            "Конфигурация явно разрешает HTTP.",
        ),
        (
            r"\ballow_insecure\s*[:=]\s*(?:True|true)\b",
            "Конфигурация явно разрешает небезопасное соединение.",
        ),
    )

    for pattern, explanation in patterns:
        for match in re.finditer(pattern, text):
            line = line_number(text, match.start())

            violations.append(
                build_violation(
                    path,
                    line,
                    line_text(text, line),
                    explanation,
                )
            )

    return violations


def scan_file(path):
    try:
        text = path.read_text(
            encoding="utf-8",
            errors="ignore",
        )
    except OSError:
        return []

    violations = []

    violations.extend(
        scan_protocols(path, text)
    )

    violations.extend(
        scan_ciphers(path, text)
    )

    violations.extend(
        scan_http_redirect(path, text)
    )

    return violations


def check_ib03(target="."):
    root = Path(target)

    violations = []
    parse_errors = []

    for path in root.rglob("*"):

        if not path.is_file():
            continue

        if should_ignore(path):
            continue

        if not is_config_file(path):
            continue

        violations.extend(
            scan_file(path)
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
        "status": (
            "VIOLATION"
            if unique
            else "PASS"
        ),
    }


if __name__ == "__main__":
    result = check_ib03(".")

    print(
        json.dumps(
            result,
            indent=2,
            ensure_ascii=False,
        )
    )
