import os
import time
import uuid
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

load_dotenv()

GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
GOOGLE_SEARCH_CX = os.getenv("GOOGLE_SEARCH_CX")

THREAT_EVENT_TABLE = "symsym-threat-events"
ALERT_TABLE = "symsym-alerts"


def search_google_leaks(target: str):
    """
    Google Custom Search를 통해 유출 의심 정보를 검색하여
    위험도를 계산하고 ThreatEvent 및 Alert를 DynamoDB에 저장한다.
    """

    if not GOOGLE_API_KEY or not GOOGLE_SEARCH_CX:
        print("[오류] Google API 설정값이 없습니다.")
        return []

    url = "https://www.googleapis.com/customsearch/v1"

    search_query = (
        f'"{target}" '
        f'(password | leak | "db dump" | '
        f'"internal source" | confidential | cv)'
    )

    try:
        # 1. Google API 호출
        response = requests.get(
            url,
            params={
                "key": GOOGLE_API_KEY,
                "cx": GOOGLE_SEARCH_CX,
                "q": search_query,
                "num": 5
            },
            timeout=10
        )

        # 2. 응답 상태 확인
        if response.status_code != 200:
            print(
                f"[오류] Google API 응답 실패 "
                f"(Status: {response.status_code})"
            )
            return []

        events = []

        # 3. Google 검색 결과를 ThreatEvent 모델로 변환
        for item in response.json().get("items", []):

            event = ThreatEvent(
                source="Google Search",

                # ThreatEvent 생성 시 고유 ID 생성
                event_id=str(uuid.uuid4()),

                email=target,
                url=item.get("link", ""),
                description=(
                    f"[{item.get('title', '')}] "
                    f"{item.get('snippet', '')}"
                ),
                detected_at=datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
                is_confirmed=False
            )

            # 4. RiskService를 이용하여 위험도 계산
            event = calculate_risk([event])[0]

            events.append(event)

            # 5. ThreatEvent를 공통 Mapper로 변환 후 DynamoDB 저장
            event_item = threat_event_to_dynamodb_item(event)

            save_to_dynamodb(
                THREAT_EVENT_TABLE,
                event_item
            )

            # 6. ThreatEvent를 기반으로 Alert 생성
            alerts = create_alerts(
                User(email=target),
                [event]
            )

            # 7. Alert를 공통 Mapper로 변환 후 DynamoDB 저장
            for alert in alerts:

                alert_item = alert_to_dynamodb_item(alert)

                save_to_dynamodb(
                    ALERT_TABLE,
                    alert_item
                )

                print(
                    f"[긴급 알림] '{target}' 관리자에게 "
                    f"{alert.threat_level} 경고 적재 완료"
                )

        return events

    except Exception as e:
        print(f"[오류] Google 검색 중 문제가 발생했습니다: {e}")
        return []


if __name__ == "__main__":

    test_domains = [
        "samsung.com",
        "ahnlab.com",
        "go.kr",
        "duksung.ac.kr"
    ]

    for domain in test_domains:
        search_google_leaks(domain)
        time.sleep(2)