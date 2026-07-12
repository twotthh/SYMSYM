from datetime import datetime
from typing import List

from backend.models.alert import Alert
from backend.models.user import User
from backend.models.threat_event import ThreatEvent

def create_alerts(
    user: User,
    events: List[ThreatEvent]
) -> List[Alert]:

    alerts = []

    for event in events:

        # LOW 위험도는 알림 생성 제외
        if event.threat_level == "LOW":
            continue

        alert = Alert(

            # 사용자 이메일
            user_email=user.email,

            # 원본 이벤트 ID
            event_id=event.event_id,

            # 탐지 출처
            source=event.source,

            # 알림 유형
            alert_type=event.source,

            # 제목
            title=f"[{event.threat_level}] {event.source} 위협 탐지",

            # 내용
            message=event.description,

            # 위험도
            threat_level=event.threat_level,

            # 생성 시간
            sent_at=datetime.now(),

            # 읽음 여부
            is_read=False
        )
        alerts.append(alert)

    return alerts
