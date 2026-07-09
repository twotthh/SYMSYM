from dataclasses import dataclass
from datetime import datetime


@dataclass
class Alert:
    """
    사용자에게 전달되는 알림 모델
    """

    user_email: str

    event_id: str

    source: str

    alert_type: str

    title: str

    message: str

    threat_level: str

    sent_at: datetime

    is_read: bool = False
