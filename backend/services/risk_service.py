from collections import Counter
from typing import List
from backend.models.threat_event import ThreatEvent
from backend.utils.risk_rules import RISK_LEVEL, RISK_SCORE

HIGH_KEYWORDS = {
    "password": "PASSWORD",
    "passwd": "PASSWORD",

    "api_key": "API_KEY",
    "apikey": "API_KEY",

    "token": "TOKEN",

    "private_key": "PRIVATE_KEY",
    "aws_access_key": "API_KEY"
}


def calculate_risk(events: List[ThreatEvent]) -> List[ThreatEvent]:
    
    # 같은 이메일/키워드가 여러 Source에서 발견됐는지 확인
    indicators = []

    for event in events:

        indicator = event.email or event.leaked_keyword

        if indicator:
            indicators.append(indicator.lower())

    multi_source = Counter(indicators)

    # 이벤트별 위험도 계산
    for event in events:

        score = 0

        text = (
            (event.description or "")
            + " "
            + (event.leaked_keyword or "")
        ).lower()

        # 출처 점수
        source = event.source.upper()

        if source in RISK_SCORE:
            score += RISK_SCORE[source]

        # 이메일
        if event.email:
            score += RISK_SCORE["EMAIL"]

        # 민감 키워드
        for keyword, risk_type in HIGH_KEYWORDS.items():

            if keyword in text:
                score += RISK_SCORE[risk_type]

        # 검증 여부
        if event.is_confirmed:
            score += RISK_SCORE["CONFIRMED"]

        # 여러 OSINT에서 발견
        indicator = event.email or event.leaked_keyword

        if indicator:

            if multi_source[indicator.lower()] >= 2:
                score += RISK_SCORE["MULTI_SOURCE"]

        # 점수 → 위험도
        if score >= RISK_LEVEL["CRITICAL"][0]:
            event.threat_level = "CRITICAL"

        elif score >= RISK_LEVEL["HIGH"][0]:
            event.threat_level = "HIGH"

        elif score >= RISK_LEVEL["MEDIUM"][0]:
            event.threat_level = "MEDIUM"

        else:
            event.threat_level = "LOW"

    return events
