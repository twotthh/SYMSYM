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

API_KEY = os.getenv("HIBP_API_KEY")

THREAT_EVENT_TABLE = "symsym-threat-events"
ALERT_TABLE = "symsym-alerts"

def search_breach(email: str):

    if not API_KEY:
        print("[오류] HIBP_API_KEY가 없습니다.")
        return []

    url = (
        f"https://haveibeenpwned.com/api/v3/"
        f"breachedaccount/{email}?truncateResponse=false"
    )

    headers = {
        "hibp-api-key": API_KEY,
        "user-agent": "symsym-alert-extension"
    }

    try:
        # 1. HIBP API 호출
        response = requests.get(
            url,
            headers=headers,
            timeout=10
        )

        # 2. 응답 상태 확인
        if response.status_code == 404:
            print(f"[HIBP] '{email}'의 유출 내역이 없습니다.")
            return []

        if response.status_code == 401:
            print("[오류] HIBP API 키가 유효하지 않습니다.")
            return []

        if response.status_code == 429:
            print("[오류] HIBP API 요청 한도를 초과했습니다.")
            return []

        if response.status_code != 200:
            print(
                f"[오류] HIBP API 응답 실패 "
                f"(Status: {response.status_code})"
            )
            return []
        

        events = []

        # 3. HIBP 응답을 ThreatEvent 모델로 변환
        for breach in response.json():

            breach_date = breach.get("BreachDate")

            event = ThreatEvent(
                source="HIBP",

                # ThreatEvent 생성 시 고유 ID 생성
                event_id=str(uuid.uuid4()),

                email=email,
                breach_name=breach.get("Name"),
                description=breach.get("Description"),
                detected_at=(
                    breach_date
                    if breach_date
                    else datetime.now().strftime("%Y-%m-%d")
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
                User(email=email),
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
                    f"[긴급 알림] '{email}' 관리자에게 "
                    f"{alert.threat_level} 경고 적재 완료"
                )

        return events

    except Exception as e:
        print(f"[오류] HIBP 스캔 중 문제가 발생했습니다: {e}")
        return []