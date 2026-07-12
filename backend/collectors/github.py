import os
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

TOKEN = os.getenv("GITHUB_API_TOKEN")

def search_github_leaks(target: str):
    if not TOKEN: return []
    url = "https://api.github.com/search/repositories"
    headers = {"Authorization": f"Bearer {TOKEN}", "Accept": "application/vnd.github+json"}
    all_events = []

    print(f"[GitHub] '{target}' 실시간 검색 중")
    try:
        response = requests.get(url, headers=headers, params={"q": f'"{target}"', "per_page": 3}, timeout=10)
        if response.status_code == 200:
            for item in response.json().get("items", []):
                event = ThreatEvent(
                    source="GitHub", email=target, leaked_keyword="N/A", repository=item.get("full_name"),
                    url=item.get("html_url"), description=f"[저장소 유출] {item.get('description', '')[:150]}",
                    detected_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"), is_confirmed=False
                )
                
                event = calculate_risk([event])[0]
                if not hasattr(event, 'event_id') or not event.event_id:
                    event.event_id = str(uuid.uuid4())

                all_events.append(event)
                save_to_dynamodb('symsym-threat-events', threat_event_to_dynamodb_item(event))

                alerts = create_alerts(User(email=target), [event])
                for alert in alerts:
                    alert_item = dataclasses.asdict(alert) if hasattr(alert, '__dataclass_fields__') else alert.dict()
                    if 'sent_at' in alert_item and not isinstance(alert_item['sent_at'], str):
                        alert_item['sent_at'] = alert_item['sent_at'].strftime("%Y-%m-%d %H:%M:%S")
                    save_to_dynamodb('symsym-alerts', alert_item)
    except Exception as e:
        print(f"GitHub 에러: {e}")
    return all_events