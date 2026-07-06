import os
import time
import requests
from datetime import datetime
from dotenv import load_dotenv

from backend.models.threat_event import ThreatEvent

load_dotenv()

API_KEY = os.getenv("HIBP_API_KEY")

def search_breach(email: str):
    """
    HIBP 이메일 유출 조회 (실제 API 연동)
    """
    if not API_KEY:
        print("[오류] HIBP_API_KEY가 없습니다. .env 파일을 확인해주세요.")
        return []

    # HIBP 공식 API 엔드포인트 (특정 계정 조회)
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false"
    
    headers = {
        "hibp-api-key": API_KEY,
        "user-agent": "symsym-alert-extension" 
    }

    try:
        response = requests.get(url, headers=headers, timeout=10)
        
        # 404 : 에러가 아니라 "유출된 내역이 없음(안전함)"을 의미
        if response.status_code == 404:
            return []
            
        if response.status_code == 401:
            print("[오류] HIBP API 키가 유효하지 않음. 결제 상태나 키 값을 확인")
            return []
            
        if response.status_code == 429:
            print("[경고] API 요청 한도(1분 10회)를 초과 잠시 후 다시 시도")
            return []

        if response.status_code != 200:
            print(f"HIBP API 에러 (상태 코드: {response.status_code})")
            return []

        breaches = response.json()
        events = []

        for breach in breaches:
            # 유출 날짜 파싱
            breach_date_str = breach.get("BreachDate")
            if breach_date_str:
                detected_at = datetime.strptime(breach_date_str, "%Y-%m-%d")
            else:
                detected_at = datetime.now()

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

        return events

    except Exception as e:
        print(f"HIBP 스캔 중 문제 발생: {e}")
        return []


if __name__ == "__main__":
    print("HIBP 유출 조회 테스트 시작\n")
    
    test_emails = ["test@duksung.ac.kr", "myemail@gmail.com"]
    
    for email in test_emails:
        print(f"[{email}] 유출 내역 검사 중")
        
        events = search_breach(email)
        
        if not events:
            print(f"해당 계정은 안전합니다\n")
        else:
            print(f"총 {len(events)}건의 유출이 발견되었습니다")
            for event in events:
                print(f" - 털린 곳: {event.breach_name}")
                print(f" - 위험도: {event.threat_level}")
            print("\n")
        
        time.sleep(2)