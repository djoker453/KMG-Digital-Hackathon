from pathlib import Path

from dotenv import dotenv_values
from openai import OpenAI


# Находим .env в корне проекта
BASE_DIR = Path(__file__).resolve().parents[2]
ENV_FILE = BASE_DIR / ".env"

# Читаем .env напрямую
ENV = dotenv_values(ENV_FILE)

AI_PROVIDER = ENV.get("AI_PROVIDER", "deepseek")
AI_API_KEY = ENV.get("AI_API_KEY")
AI_MODEL = ENV.get("AI_MODEL", "deepseek-chat")


def analyze_finding(finding):
    """
    Отправляет одну находку Semgrep в AI
    и получает объяснение риска.
    """

    if not AI_API_KEY:
        return {
            "success": False,
            "error": "AI_API_KEY не указан в .env",
        }

    if AI_PROVIDER == "openrouter":
        base_url = "https://openrouter.ai/api/v1"

    elif AI_PROVIDER == "deepseek":
        base_url = "https://api.deepseek.com"

    else:
        return {
            "success": False,
            "error": f"Неизвестный AI_PROVIDER: {AI_PROVIDER}",
        }

    client = OpenAI(
        api_key=AI_API_KEY,
        base_url=base_url,
    )

    prompt = f"""
Ты — специалист по Application Security и DevSecOps.

Проанализируй результат статического анализа безопасности.

Finding:
Rule: {finding.get("rule")}
File: {finding.get("file")}
Line: {finding.get("line")}
Severity: {finding.get("severity")}
Impact: {finding.get("impact")}
Likelihood: {finding.get("likelihood")}
Confidence: {finding.get("confidence")}

Описание Semgrep:
{finding.get("message")}

Верни ответ строго в следующем формате:

VERDICT: TRUE_POSITIVE / FALSE_POSITIVE / NEEDS_REVIEW

RISK: LOW / MEDIUM / HIGH / CRITICAL

EXPLANATION:
кратко объясни проблему и почему она важна.

RECOMMENDATION:
что разработчику нужно сделать для исправления.

Не придумывай факты, которых нет в finding.
"""

    try:
        response = client.chat.completions.create(
            model=AI_MODEL,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "Ты анализируешь результаты DevSecOps "
                        "security scanning."
                    ),
                },
                {
                    "role": "user",
                    "content": prompt,
                },
            ],
            temperature=0.1,
        )

        answer = response.choices[0].message.content

        return {
            "success": True,
            "provider": AI_PROVIDER,
            "model": AI_MODEL,
            "analysis": answer,
        }

    except Exception as error:
        return {
            "success": False,
            "error": str(error),
        }
