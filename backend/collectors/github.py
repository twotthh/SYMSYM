import os
import time
import requests
from datetime import datetime
from dotenv import load_dotenv

from backend.models.threat_event import ThreatEvent
from backend.services.aws_db import save_to_dynamodb
from backend.utils.mapper import threat_event_to_dynamodb_item

load_dotenv()

TOKEN = os.getenv("GITHUB_API_TOKEN")

# [교수님 피드백 1] 타겟 확장
TARGET_ORGS = ["samsung", "ahnlab", "duksung.ac.kr", "go.kr"]

# [교수님 피드백 2] 키워드 매칭
THREAT_KEYWORDS = ["internal", "confidential", "dump", "credentials"]

def search_github_leaks():
    if not TOKEN:
        print("[오류] GITHUB_API_TOKEN이 없음 -> env 확인")
        return []

    # [교수님 피드백 3] 'search/code'에서 'search/repositories'로 변경
    url = "https://api.github.com/search/repositories"
    
    headers = {
        "Authorization": f"Bearer {TOKEN}",
        "Accept": "application/vnd.github+json"
    }

    all_events = []

    for org in TARGET_ORGS:
        for keyword in THREAT_KEYWORDS:
            # 예: "samsung internal", "go.kr dump" 등의 쿼리 생성
            search_query = f'"{org}" "{keyword}"'
            print(f"[GitHub] '{search_query}' 검색 중")
            
            params = {
                "q": search_query, 
                "per_page": 3  # 상위 3개 위험 레포지토리만 추출 (API 한도 및 시연용)
            }

            try:
                response = requests.get(url, headers=headers, params=params, timeout=10)

                if response.status_code == 403:
                    print("GitHub API 속도 제한 -> 잠시 대기")
                    time.sleep(10)
                    continue
                elif response.status_code != 200:
                    print(f"GitHub API 에러: {response.text}")
                    continue

                data = response.json()
                
                for item in data.get("items", []):
                    detected_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    repo_name = item.get("full_name")
                    description = item.get("description") or "설명 없음"
                    repo_url = item.get("html_url")

                    event = ThreatEvent(
                        source="GitHub",
                        email=org,             # AWS DB 저장을 위해 기관명을 기준 열쇠로 사용
                        leaked_keyword=keyword,
                        repository=repo_name,
                        url=repo_url,
                        # threat_level 하드코딩 삭제 (risk_service가 할 일)
                        description=f"[저장소 유출] {description[:150]}",
                        detected_at=detected_at,
                        is_confirmed=False
                    )

                    all_events.append(event)

                    # AWS DynamoDB 규격화 및 자동 적재
                    item_to_save = threat_event_to_dynamodb_item(event)
                    save_to_dynamodb('symsym-threat-events', item_to_save)

                time.sleep(3)

            except Exception as e:
                print(f"GitHub 검색 중 에러 발생: {e}")

    return all_events

if __name__ == "__main__":
    print("깃허브 - 기업 기밀 유출 스캔 시작\n")
    events = search_github_leaks()
    
    if not events:
        print("타겟 기관의 기밀이 유출된 깃허브 저장소가 없음")
    else:
        print(f"\n총 {len(events)}건의 위험 저장소를 찾아 AWS에 적재 완료")