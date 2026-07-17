from dataclasses import dataclass
from datetime import datetime
from typing import Optional

@dataclass
class ThreatEvent:

    # 데이터 출처
    source: str

    # 이벤트 고유 식별자
    event_id: Optional[str] = None

    # 유출 대상 정보
    email: Optional[str] = None
    leaked_keyword: Optional[str] = None

    # HIBP 정보
    breach_name: Optional[str] = None
    breach_date: Optional[str] = None

    # GitHub 정보
    repository: Optional[str] = None
    file_path: Optional[str] = None
    url: Optional[str] = None

    # Telegram 정보
    channel_name: Optional[str] = None
    channel_id: Optional[str] = None
    message_id: Optional[str] = None

    # 위험도 정보
    threat_level: str = "LOW"

    # 상세 설명
    description: str = ""

    # 탐지 시간
    detected_at: Optional[datetime] = None

    # 데이터 유형
    data_type: str = "live"

    # 확인 여부
    is_confirmed: bool = False