SEVERITY_SCORE = {
    "INFO": 1,
    "WARNING": 2,
    "ERROR": 3,
}

IMPACT_SCORE = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
}

LIKELIHOOD_SCORE = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
}

CONFIDENCE_SCORE = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
}


def calculate_risk(finding):
    """
    Рассчитывает уровень риска отдельной находки.
    """

    severity = finding.get("severity", "INFO")
    impact = finding.get("impact", "LOW")
    likelihood = finding.get("likelihood", "LOW")
    confidence = finding.get("confidence", "LOW")

    severity_score = SEVERITY_SCORE.get(severity, 1)
    impact_score = IMPACT_SCORE.get(impact, 1)
    likelihood_score = LIKELIHOOD_SCORE.get(likelihood, 1)
    confidence_score = CONFIDENCE_SCORE.get(confidence, 1)

    # Confidence немного влияет на итоговый результат,
    # чтобы низкая уверенность не превращала находку
    # автоматически в критическую.
    score = (
        severity_score
        + impact_score
        + likelihood_score
        + confidence_score
    )

    if score >= 10:
        risk = "CRITICAL"
    elif score >= 8:
        risk = "HIGH"
    elif score >= 6:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return {
        **finding,
        "risk_score": score,
        "risk": risk,
    }


def analyze_findings(findings):
    """
    Рассчитывает риск для всех найденных проблем.
    """

    analyzed = [
        calculate_risk(finding)
        for finding in findings
    ]

    summary = {
        "total": len(analyzed),
        "critical": sum(
            1 for item in analyzed
            if item["risk"] == "CRITICAL"
        ),
        "high": sum(
            1 for item in analyzed
            if item["risk"] == "HIGH"
        ),
        "medium": sum(
            1 for item in analyzed
            if item["risk"] == "MEDIUM"
        ),
        "low": sum(
            1 for item in analyzed
            if item["risk"] == "LOW"
        ),
    }

    return {
        "findings": analyzed,
        "summary": summary,
    }
