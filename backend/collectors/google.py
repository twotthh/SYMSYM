import os
import time
import requests
from datetime import datetime
from dotenv import load_dotenv

from backend.models.threat_event import ThreatEvent
from backend.models.user import User
from backend.services.aws_db import save_to_dynamodb
from backend.services.risk_service import calculate_risk
from backend.services.alert_service import create_alerts
from backend.utils.mapper import (
    threat_event_to_dynamodb_item,
    alert_to_dynamodb_item
)
from backend.utils.event_id import generate_event_id

load_dotenv()

SERPAPI_API_KEY = os.getenv("SERPAPI_API_KEY")

THREAT_EVENT_TABLE = "symsym-threat-events-v2"
ALERT_TABLE = "symsym-alerts"

def search_google_leaks(target: str):
    
    if not SERPAPI_API_KEY:
        print("[오류] SerpApi 설정값이 없습니다.")
        return []

    # SerpApi 엔드포인트로 변경
    url = "https://serpapi.com/search"

    search_query = (
        f'"{target}" '
        f'(ext:sql OR ext:env OR ext:log OR ext:bak OR ext:txt OR ext:csv) '
        f'(intext:password OR intext:"api_key" OR intext:token OR intext:"db_pass")'
    )

    try:
        response = requests.get(
            url,
            params={
                "engine": "google",
                "q": search_query,
                "api_key": SERPAPI_API_KEY,
                "num": 5
            },
            timeout=10
        )

        if response.status_code != 200:
            print(
                f"[오류] SerpApi 응답 실패 "
                f"(Status: {response.status_code})"
            )
            return []

        events = []

        # SerpApi는 검색 결과를 "organic_results"라는 키로 반환
        results = response.json().get("organic_results", [])
        for item in results:

            event = ThreatEvent(
                source="Google Search",
                event_id=generate_event_id(
                    "Google Search",
                    target,
                    item.get("link")
                ),
                email=target,
                url=item.get("link", ""),
                description=(
                    f"[{item.get('title', '')}] "
                    f"{item.get('snippet', '')}"
                ),
                detected_at=datetime.now(),
                data_type="live",
                is_confirmed=False
            )

            event = calculate_risk([event])[0]
            events.append(event)

            event_item = threat_event_to_dynamodb_item(event)
            save_to_dynamodb(THREAT_EVENT_TABLE, event_item)

            alerts = create_alerts(User(email=target), [event])

            for alert in alerts:
                alert_item = alert_to_dynamodb_item(alert)
                save_to_dynamodb(ALERT_TABLE, alert_item)

                print(
                    f"[긴급 알림] '{target}' 관리자에게 "
                    f"{alert.threat_level} 경고 적재 완료"
                )

        return events

    except Exception as e:
        print(f"[오류] Google(SerpApi) 검색 중 문제가 발생했습니다: {e}")
        return []