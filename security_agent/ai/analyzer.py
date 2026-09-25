import os
from pathlib import Path

from dotenv import dotenv_values
from openai import OpenAI


BASE_DIR = Path(__file__).resolve().parents[2]
ENV_FILE = BASE_DIR / ".env"

ENV = dotenv_values(ENV_FILE)

AI_PROVIDER = os.getenv(
    "AI_PROVIDER",
    ENV.get("AI_PROVIDER", "openrouter"),
)

AI_API_KEY = os.getenv(
    "AI_API_KEY",
    ENV.get("AI_API_KEY"),
)

AI_MODEL = os.getenv(
    "AI_MODEL",
    ENV.get("AI_MODEL", "qwen/qwen3.8-27b:free"),
)


def analyze_finding(finding):
    """
    Анализирует одну находку Semgrep
    с помощью Qwen через OpenRouter.
    """

    if not AI_API_KEY:
        return {
            "success": False,
            "error": "AI_API_KEY не указан.",
        }

    if AI_PROVIDER == "openrouter":
        base_url = "https://openrouter.ai/api/v1"

    elif AI_PROVIDER == "deepseek":
        base_url = "https://api.deepseek.com"

    elif AI_PROVIDER == "qwen":
        base_url = "https://dashscope.aliyuncs.com/compatible-mode/v1"

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
            max_tokens=2000
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
