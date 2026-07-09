import os
import time
import requests
from datetime import datetime
from dotenv import load_dotenv

from backend.models.threat_event import ThreatEvent
from backend.services.aws_db import save_to_dynamodb
from backend.utils.mapper import threat_event_to_dynamodb_item

load_dotenv()

API_KEY = os.getenv("HIBP_API_KEY")
TABLE_NAME = "symsym-threat-events" #테이블 명 변경 시 해당 코드 수정해서 사용


def search_breach(email: str):
    """
    HIBP에서 이메일 유출 정보를 조회하여
    ThreatEvent 생성 후 DynamoDB에 저장한다.

    Return:
        List[ThreatEvent]
    """

    if not API_KEY:
        print("[오류] HIBP_API_KEY가 없습니다. .env 파일을 확인하세요.")
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
            return []

        if response.status_code == 401:
            print("[오류] HIBP API 키가 유효하지 않습니다.")
            return []

        if response.status_code == 429:
            print("[경고] API 요청 한도를 초과했습니다.")
            return []

        if response.status_code != 200:
            print(f"[오류] HIBP API 응답 실패 (Status: {response.status_code})")
            return []

        breaches = response.json()
        events = []

        # 3. HIBP 응답을 ThreatEvent 모델로 변환
        for breach in breaches:

            breach_date = breach.get("BreachDate")

            detected_at = (
                breach_date
                if breach_date
                else datetime.now().strftime("%Y-%m-%d")
            )

            event = ThreatEvent(
                source="HIBP",
                email=email,
                breach_name=breach.get("Name"),

                # TODO:
                # 현재는 임시로 HIGH를 사용
                # RiskService 구현 후 Collector에서는 threat_level을 설정하지 않도록 변경 예정
                threat_level="HIGH",

                description=breach.get("Description"),
                detected_at=detected_at,
                is_confirmed=False
            )

            events.append(event)

            # 4. ThreatEvent → DynamoDB 저장 형식으로 변환
            #mapper.py에서 저장함수 끌어옴
            #GitHub,Telegram 둘 다 해당 함수 사용하여 DB에 저장 가능
            item = threat_event_to_dynamodb_item(event) 

            # 5. DynamoDB 저장
            save_to_dynamodb(
                TABLE_NAME,
                item
            )

        return events

    except Exception as e:
        print(f"[오류] HIBP 스캔 중 문제가 발생했습니다: {e}")
        return []


if __name__ == "__main__":

    print("===== HIBP 데이터 수집 및 AWS 저장 테스트 =====\n")

    test_emails = [
        "test@duksung.ac.kr",
        "myemail@gmail.com"
    ]

    for email in test_emails:

        print(f"[{email}] 유출 정보 조회 중...")

        events = search_breach(email)

        if not events:
            print("유출 내역이 없습니다.\n")

        else:
            print(f"{len(events)}건의 유출 정보를 DynamoDB에 저장했습니다.\n")

        time.sleep(2)