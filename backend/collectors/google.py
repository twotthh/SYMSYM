import os
import time
import requests
from datetime import datetime
from dotenv import load_dotenv

from backend.models.threat_event import ThreatEvent
from backend.services.aws_db import save_to_dynamodb
from backend.utils.mapper import threat_event_to_dynamodb_item

load_dotenv()

GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
GOOGLE_SEARCH_CX = os.getenv("GOOGLE_SEARCH_CX")

def search_google_leaks(target: str):
    if not GOOGLE_API_KEY or not GOOGLE_SEARCH_CX:
        print("[오류] 구글 API 키 또는 CX 값이 없음 -> env 확인")
        return []

    url = "https://www.googleapis.com/customsearch/v1"
    
    # 기업 기밀 유출 키워드 조합
    search_query = f'"{target}" (password | leak | "db dump" | "internal source" | confidential | cv)'
    
    params = {
        'key': GOOGLE_API_KEY,
        'cx': GOOGLE_SEARCH_CX,
        'q': search_query,
        'num': 5
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

            event = ThreatEvent(
                source="Google Search",
                email=target, # 타겟 기관/도메인을 기준으로 기록
                url=link,
                description=f"[{title}] {snippet}",
                detected_at=detected_at,
                is_confirmed=False
            )
            events.append(event)

            item_to_save = threat_event_to_dynamodb_item(event)
            save_to_dynamodb('symsym-threat-events', item_to_save)

        return events

    except Exception as e:
        print(f"구글 검색 중 문제 발생: {e}")
        return []

if __name__ == "__main__":
    print("구글 OSINT 기업 기밀 유출 검색 및 AWS 적재 시작\n")
    
    # 타겟 도메인 리스트 확장
    TARGET_DOMAINS = ["samsung.com", "ahnlab.com", "go.kr", "duksung.ac.kr"]
    
    for domain in TARGET_DOMAINS:
        print(f"[{domain}] 구글 딥서치 진행")
        events = search_google_leaks(domain)
        
        if not events:
            print(f"[{domain}] 관련 노출 흔적 없음\n")
        else:
            print(f"총 {len(events)}건의 [{domain}] 웹 노출 데이터를 찾아 AWS에 저장\n")
        
        time.sleep(2)