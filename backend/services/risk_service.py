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
        reasons = []

        text = (
            (event.description or "")
            + " "
            + (event.leaked_keyword or "")
        ).lower()

        # 출처 점수
        source = event.source.upper()

        if source in RISK_SCORE:
            score += RISK_SCORE[source]
            reasons.append(f"{event.source}에서 탐지")

        # 이메일
        if event.email:
            score += RISK_SCORE["EMAIL"]
            reasons.append("이메일 정보 포함")

        # 민감 키워드
        for keyword, risk_type in HIGH_KEYWORDS.items():

            if keyword in text:
                score += RISK_SCORE[risk_type]
                reasons.append(f"{keyword} 노출")

        # 검증 여부
        if event.is_confirmed:
            score += RISK_SCORE["CONFIRMED"]
            reasons.append("검증된 정보")

        # 여러 OSINT에서 발견
        indicator = event.email or event.leaked_keyword

        if indicator:

            if multi_source[indicator.lower()] >= 2:
                score += RISK_SCORE["MULTI_SOURCE"]
                reasons.append("여러 OSINT에서 동시 발견")

        # 점수 저장 (최대 100점)
        event.risk_score = min(score, 100)

        # 위험도 산정 근거 저장
        event.risk_reason = reasons

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
