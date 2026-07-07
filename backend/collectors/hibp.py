import os
import time
import requests
from datetime import datetime
from dotenv import load_dotenv

from backend.models.threat_event import ThreatEvent
from backend.services.aws_db import save_to_dynamodb

load_dotenv()

API_KEY = os.getenv("HIBP_API_KEY")

def search_breach(email: str):
    if not API_KEY:
        print("[오류] HIBP_API_KEY가 없음 -> env 파일 확인")
        return []

    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false"
    
    headers = {
        "hibp-api-key": API_KEY,
        "user-agent": "symsym-alert-extension" 
    }

    try:
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 404:
            return []
            
        if response.status_code == 401:
            print("[오류] HIBP API 키가 유효하지 않음")
            return []
            
        if response.status_code == 429:
            print("[경고] API 요청 한도 초과")
            return []

        if response.status_code != 200:
            print(f"HIBP API 에러 (상태 코드: {response.status_code})")
            return []

        breaches = response.json()
        events = []

        for breach in breaches:
            # 1. 시간 데이터 정리
            breach_date_str = breach.get("BreachDate")
            if breach_date_str:
                detected_at = breach_date_str 
            else:
                detected_at = datetime.now().strftime("%Y-%m-%d")

            # 2. 파이썬 규격에 먼저 맞추기
            event = ThreatEvent(
                source="HIBP",
                email=email,
                breach_name=breach.get("Name"),
                threat_level="HIGH",
                description=breach.get("Description"), 
                detected_at=detected_at,
                is_confirmed=False
            )
            events.append(event)

            # 3. AWS 전용 규격으로 맞추고 DB로 전송
            # 테이블의 파티션 키(email)와 정렬 키(detected_at) 필수
            item_to_save = {
                "event_id": f"HIBP-{email}-{breach.get('Name')}", # 고유 식별자 생성
                "email": email,                                   # 파티션 키
                "detected_at": detected_at,                       # 정렬 키
                "source": "HIBP",
                "threat_level": "HIGH",
                "breach_name": breach.get("Name"),
                "description": str(breach.get("Description"))[:200] + "..." 
            }

            save_to_dynamodb('symsym-threat-events', item_to_save)

        return events

    except Exception as e:
        print(f"HIBP 스캔 중 문제 발생: {e}")
        return []

if __name__ == "__main__":
    print("HIBP 데이터 수집 및 AWS 적재 테스트 시작\n")
    
    test_emails = ["test@duksung.ac.kr", "myemail@gmail.com"]
    
    for email in test_emails:
        print(f"[{email}] 유출 내역 검사 및 저장 중")
        
        events = search_breach(email)
        
        if not events:
            print(f"해당 계정은 안전해요\n")
        else:
            print(f"총 {len(events)}건의 유출 데이터를 AWS에 적재 완료\n")
        
        time.sleep(2)