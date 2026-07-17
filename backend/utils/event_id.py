"""
backend/utils/event_id.py

ThreatEvent의 고유 event_id를 생성하는 공통 유틸리티

[생성 규칙]

HIBP
    source + target + breach_name + breach_date

GitHub (Repository Match)
    source + target + repository + url

GitHub (Code Match)
    source + target + repository + url

Google Search
    source + target + url

Telegram
    source + target + url

Shodan
    source + ip

Censys
    source + ip

HackerTarget
    source + domain + ip

※ 동일한 입력값이면 항상 동일한 event_id 생성
※ 중복 적재 방지를 위해 SHA-256 Hash 사용
"""

import hashlib


def generate_event_id(source: str, *keys) -> str:
    """
    source와 각 Collector의 고유 식별 정보를 이용하여
    항상 동일한 event_id 생성

    Parameters
    ----------
    source : str
        데이터 출처 (HIBP, GitHub, Google Search, Telegram ...)

    *keys :
        event를 식별할 수 있는 고유 값들

    Returns
    -------
    str
        SHA-256 기반 event_id
    """

    values = [source]

    for key in keys:

        if key is None:
            continue

        value = str(key).strip()

        if value == "":
            continue

        values.append(value)

    raw = "|".join(values)

    return hashlib.sha256(
        raw.encode("utf-8")
    ).hexdigest()