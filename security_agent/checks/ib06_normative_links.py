import json
import re
from pathlib import Path


REQUIREMENT_ID = "ИБ-06"

REQUIREMENT = (
    "README или техническая спецификация проекта должны содержать "
    "ссылки на нормативные правовые акты и стандарты, предусмотренные "
    "техническим заданием."
)

REQUIRED_DOCUMENTS = {
    "Закон РК о персональных данных": [
        r"Z1300000094",
        r"персональных данных и их защите",
    ],
    "СТ РК 1073-2007": [
        r"СТ\s*РК\s*1073",
        r"1073-2007",
    ],
}


def build_violation(name, explanation, recommendation):
    return {
        "requirement_id": REQUIREMENT_ID,
        "requirement": REQUIREMENT,
        "location": {
            "file": "README.md",
            "line": 1,
        },
        "evidence": name,
        "explanation": explanation,
        "criticality": "MEDIUM",
        "recommendation": recommendation,
    }


def find_document_links(text):
    found = {}

    for name, patterns in REQUIRED_DOCUMENTS.items():
        matches = []

        for pattern in patterns:
            for match in re.finditer(pattern, text, re.IGNORECASE):
                matches.append(match.start())

        if matches:
            found[name] = True
        else:
            found[name] = False

    return found


def check_ib06(target="."):
    root = Path(target)

    documentation_files = [
        root / "README.md",
        root / "docs" / "Техническая_спецификация_ИС_обработки_обращений_КМГ.docx",
    ]

    existing_files = [
        path for path in documentation_files
        if path.exists()
    ]

    violations = []

    if not existing_files:
        violations.append(
            build_violation(
                "Документация не найдена",
                "Не найден README или файл технической спецификации.",
                "Добавить README или техническую спецификацию с нормативными источниками."
            )
        )

        return {
            "requirement_id": REQUIREMENT_ID,
            "requirement": REQUIREMENT,
            "violations": violations,
            "parse_errors": [],
            "status": "VIOLATION",
        }

    combined_text = ""

    for path in existing_files:
        if path.suffix.lower() == ".md":
            try:
                combined_text += "\n" + path.read_text(
                    encoding="utf-8",
                    errors="ignore"
                )
            except OSError:
                pass

    found = find_document_links(combined_text)

    for name, exists in found.items():
        if not exists:
            violations.append(
                build_violation(
                    name,
                    f"В доступной Markdown-документации не обнаружена ссылка или упоминание: {name}.",
                    f"Добавить в README ссылку на {name}."
                )
            )

    return {
        "requirement_id": REQUIREMENT_ID,
        "requirement": REQUIREMENT,
        "violations": violations,
        "parse_errors": [],
        "status": "VIOLATION" if violations else "PASS",
    }


if __name__ == "__main__":
    result = check_ib06(".")
    print(json.dumps(result, indent=2, ensure_ascii=False))
