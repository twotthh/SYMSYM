import os
import time
import requests
from datetime import datetime
from dotenv import load_dotenv

from backend.models.threat_event import ThreatEvent
from backend.services.aws_db import save_to_dynamodb

load_dotenv()

GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
GOOGLE_SEARCH_CX = os.getenv("GOOGLE_SEARCH_CX")

def search_google_leaks(email: str):
    if not GOOGLE_API_KEY or not GOOGLE_SEARCH_CX:
        print("[오류] 구글 API 키 또는 CX 값이 없음 -> env 확인")
        return []

    url = "https://www.googleapis.com/customsearch/v1"
    
    # 이메일 주소와 해킹 관련 키워드를 조합해서 검색
    search_query = f'"{email}" (password | leak | dump | credentials | database)'
    
    params = {
        'key': GOOGLE_API_KEY,
        'cx': GOOGLE_SEARCH_CX,
        'q': search_query,
        'num': 5  # 상위 5개 결과만
    }

    try:
        response = requests.get(url, params=params, timeout=10)
        
        if response.status_code != 200:
            print(f"구글 API 에러 (상태 코드: {response.status_code})")
            return []

        data = response.json()
        search_results = data.get("items", [])
        events = []

        for item in search_results:
            detected_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            title = item.get("title", "제목 없음")
            link = item.get("link", "링크 없음")
            snippet = item.get("snippet", "내용 없음")

            # 파이썬 규격화
            event = ThreatEvent(
                source="Google Search",
                email=email,
                url=link,
                threat_level="MEDIUM", # 단순 노출일 수 있으므로 MEDIUM으로 설정
                description=f"[{title}] {snippet}",
                detected_at=detected_at,
                is_confirmed=False
            )
            events.append(event)

            # AWS DynamoDB에 적재하기 위한 데이터 규격화
            item_to_save = {
                "event_id": f"GOOGLE-{email}-{link[-15:]}", 
                "email": email,                            # 파티션 키
                "detected_at": detected_at,                # 정렬 키
                "source": "Google Search",
                "threat_level": "MEDIUM",
                "url": link,
                "description": f"구글 검색 노출: {title}" 
            }
            
            save_to_dynamodb('symsym-threat-events', item_to_save)

        return events

    except Exception as e:
        print(f"구글 검색 중 문제 발생: {e}")
        return []

if __name__ == "__main__":
    print("구글 OSINT 데이터 수집 및 AWS 적재 테스트 시작\n")
    
    test_emails = ["test@duksung.ac.kr", "myemail@gmail.com"]
    
    for email in test_emails:
        print(f"[{email}] 구글 웹 노출 내역 검사 중")
        
        events = search_google_leaks(email)
        
        if not events:
            print(f"인터넷 공개 웹상에 노출된 흔적이 없음\n")
        else:
            print(f"총 {len(events)}건의 웹 노출 데이터를 찾아 AWS에 저장\n")
            for ev in events:
                print(f" - 발견된 곳: {ev.url}")
            print("\n")
        
        time.sleep(2)