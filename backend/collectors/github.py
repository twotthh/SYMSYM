import os
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

TOKEN = os.getenv("GITHUB_API_TOKEN")

THREAT_EVENT_TABLE = "symsym-threat-events"
ALERT_TABLE = "symsym-alerts"


def search_github_leaks(target: str):
    """
    GitHub에서 대상 키워드를 검색하여
    위험도를 계산하고 ThreatEvent 및 Alert를 DynamoDB에 저장한다.
    """

    if not TOKEN:
        print("[오류] GITHUB_API_TOKEN이 없습니다.")
        return []

    url = "https://api.github.com/search/repositories"

    headers = {
        "Authorization": f"Bearer {TOKEN}",
        "Accept": "application/vnd.github+json"
    }

    all_events = []

    print(f"[GitHub] '{target}' 실시간 검색 중")

    try:
        # 1. GitHub API 호출
        response = requests.get(
            url,
            headers=headers,
            params={
                "q": f'"{target}"',
                "per_page": 3
            },
            timeout=10
        )

        # 2. 응답 상태 확인
        if response.status_code != 200:
            print(
                f"[오류] GitHub API 응답 실패 "
                f"(Status: {response.status_code})"
            )
            return []

        # 3. GitHub 응답을 ThreatEvent 모델로 변환
        for item in response.json().get("items", []):

            event = ThreatEvent(
                source="GitHub",

                # ThreatEvent 생성 시 고유 ID 생성
                event_id=str(uuid.uuid4()),

                email=target,
                leaked_keyword="N/A",
                repository=item.get("full_name"),
                url=item.get("html_url"),
                description=(
                    f"[저장소 유출] "
                    f"{item.get('description', '')[:150]}"
                ),
                detected_at=datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
                is_confirmed=False
            )

            # 4. RiskService를 이용하여 위험도 계산
            event = calculate_risk([event])[0]

            all_events.append(event)

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

        return all_events

    except Exception as e:
        print(f"[오류] GitHub 검색 중 문제가 발생했습니다: {e}")
        return []