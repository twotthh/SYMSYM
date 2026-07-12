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
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
GOOGLE_SEARCH_CX = os.getenv("GOOGLE_SEARCH_CX")

def search_google_leaks(target: str):
    if not GOOGLE_API_KEY or not GOOGLE_SEARCH_CX: return []
    url = "https://www.googleapis.com/customsearch/v1"
    search_query = f'"{target}" (password | leak | "db dump" | "internal source" | confidential | cv)'
    
    try:
        response = requests.get(url, params={'key': GOOGLE_API_KEY, 'cx': GOOGLE_SEARCH_CX, 'q': search_query, 'num': 5}, timeout=10)
        if response.status_code != 200: return []
        events = []

        for item in response.json().get("items", []):
            event = ThreatEvent(
                source="Google Search", email=target, url=item.get("link", ""),
                description=f"[{item.get('title', '')}] {item.get('snippet', '')}",
                detected_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"), is_confirmed=False
            )
        
            # 1. 채점 및 ID
            event = calculate_risk([event])[0]
            if not hasattr(event, 'event_id') or not event.event_id:
                event.event_id = str(uuid.uuid4())
            
            # 2. Events 저장
            events.append(event)
            save_to_dynamodb('symsym-threat-events', threat_event_to_dynamodb_item(event))

            # 3. Alerts 저장
            alerts = create_alerts(User(email=target), [event])
            for alert in alerts:
                alert_item = dataclasses.asdict(alert) if hasattr(alert, '__dataclass_fields__') else alert.dict()
                if 'sent_at' in alert_item and not isinstance(alert_item['sent_at'], str):
                    alert_item['sent_at'] = alert_item['sent_at'].strftime("%Y-%m-%d %H:%M:%S")
                save_to_dynamodb('symsym-alerts', alert_item)
                print(f"[긴급 알림] '{target}' 관리자에게 {alert.threat_level} 경고 적재 완료")
        return events
    except Exception as e:
        print(f"구글 검색 에러 : {e}")
        return []

if __name__ == "__main__":
    for domain in ["samsung.com", "ahnlab.com", "go.kr", "duksung.ac.kr"]:
        search_google_leaks(domain)
        time.sleep(2)