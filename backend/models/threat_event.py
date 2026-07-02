from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass
class ThreatEvent:
    """
    OSINT 기반 위협 이벤트 모델
    (HIBP, GitHub, Telegram 공통 사용)
    """

    source: str

    email: Optional[str] = None
    leaked_keyword: Optional[str] = None

    breach_name: Optional[str] = None

    repository: Optional[str] = None
    file_path: Optional[str] = None
    url: Optional[str] = None

    channel_name: Optional[str] = None
    channel_id: Optional[str] = None
    message_id: Optional[str] = None

    threat_level: str = "LOW"

    description: str = ""

    detected_at: Optional[datetime] = None

    is_confirmed: bool = False