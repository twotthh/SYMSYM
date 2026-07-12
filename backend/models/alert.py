from dataclasses import dataclass
from datetime import datetime

@dataclass
class Alert:
    
    # 알림을 받을 사용자
    user_email: str

    # 원본 ThreatEvent ID
    event_id: str

    # 탐지 출처
    source: str

    # 알림 유형
    alert_type: str

    # 알림 제목
    title: str

    # 알림 내용
    message: str

    # 위험도
    threat_level: str

    # 생성 시간
    sent_at: datetime

    # 읽음 여부
    is_read: bool = False
