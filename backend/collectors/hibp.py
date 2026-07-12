import os
import time
import uuid
import requests
import dataclasses
from datetime import datetime
from dotenv import load_dotenv

from backend.models.threat_event import ThreatEvent
from backend.services.aws_db import save_to_dynamodb
from backend.utils.mapper import threat_event_to_dynamodb_item
from backend.services.risk_service import calculate_risk
from backend.models.user import User
from backend.services.alert_service import create_alerts

load_dotenv()
API_KEY = os.getenv("HIBP_API_KEY")

def search_breach(email: str):
    if not API_KEY: return []
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false"
    
    try:
        response = requests.get(url, headers={"hibp-api-key": API_KEY, "user-agent": "symsym-alert-extension"}, timeout=10)
        if response.status_code != 200: return []
        
        events = []
        for breach in response.json():
            breach_date = breach.get("BreachDate")
            event = ThreatEvent(
                source="HIBP", email=email, breach_name=breach.get("Name"),
                description=breach.get("Description"),
                detected_at=breach_date if breach_date else datetime.now().strftime("%Y-%m-%d"), is_confirmed=False
            )

            # 1. 채점 및 ID
            event = calculate_risk([event])[0]
            if not hasattr(event, 'event_id') or not event.event_id:
                event.event_id = str(uuid.uuid4())

            # 2. Events 저장
            events.append(event)
            save_to_dynamodb("symsym-threat-events", threat_event_to_dynamodb_item(event))

            # 3. Alerts 저장
            alerts = create_alerts(User(email=email), [event])
            for alert in alerts:
                alert_item = dataclasses.asdict(alert) if hasattr(alert, '__dataclass_fields__') else alert.dict()
                if 'sent_at' in alert_item and not isinstance(alert_item['sent_at'], str):
                    alert_item['sent_at'] = alert_item['sent_at'].strftime("%Y-%m-%d %H:%M:%S")
                save_to_dynamodb('symsym-alerts', alert_item)
                print(f"[긴급 알림] '{email}' 관리자에게 {alert.threat_level} 경고 적재 완료")
        return events
    except Exception as e:
        print(f"HIBP 스캔 에러 : {e}")
        return []

if __name__ == "__main__":
    for email in ["samsung.com", "ahnlab.com", "duksung.ac.kr"]:
        search_breach(email)
        time.sleep(2)