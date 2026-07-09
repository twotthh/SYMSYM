from typing import List

from backend.models.threat_event import ThreatEvent


# 민감 정보 키워드
HIGH_KEYWORDS = [
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "aws_access_key",
    "private_key",
    "access_key"
]


def calculate_risk(
    events: List[ThreatEvent]
) -> List[ThreatEvent]:
    """
    ThreatEvent 위험도 계산
    """

    for event in events:

        text = (
            (event.description or "")
            + " "
            + (event.leaked_keyword or "")
        ).lower()

        # HIBP
        if event.source == "HIBP":

            event.threat_level = "HIGH"

        # GitHub
        elif event.source == "GitHub":

            if any(keyword in text for keyword in HIGH_KEYWORDS):
                event.threat_level = "HIGH"
            else:
                event.threat_level = "MEDIUM"

        # Telegram
        elif event.source == "Telegram":

            if any(keyword in text for keyword in HIGH_KEYWORDS):
                event.threat_level = "HIGH"

            elif event.email:
                event.threat_level = "HIGH"

            else:
                event.threat_level = "LOW"

        # 기타
        else:

            event.threat_level = "LOW"

        # 검증된 이벤트는 위험도 1단계 상승
        if event.is_confirmed:

            if event.threat_level == "LOW":
                event.threat_level = "MEDIUM"

            elif event.threat_level == "MEDIUM":
                event.threat_level = "HIGH"

            elif event.threat_level == "HIGH":
                event.threat_level = "CRITICAL"

    return events
