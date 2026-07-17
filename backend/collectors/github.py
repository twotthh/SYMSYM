import os
import requests
import time
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

TOKEN = os.getenv("GITHUB_API_TOKEN")

THREAT_EVENT_TABLE = "symsym-threat-events-v2"
ALERT_TABLE = "symsym-alerts"

def search_github_leaks(target: str):
    if not TOKEN:
        print("[오류] GITHUB_API_TOKEN이 없습니다.")
        return []

    repo_url = "https://api.github.com/search/repositories"
    code_url = "https://api.github.com/search/code"

    headers = {
        "Authorization": f"Bearer {TOKEN}",
        "Accept": "application/vnd.github+json"
    }

    all_events = []
    processed_repos = set()  

    print(f"[GitHub] '{target}' 기반 3단계 정밀 모니터링 시작")

    # 1. 리포지토리 이름 검색
    try:
        # in:name 쿼리를 사용하여 저장소 이름만 명확하게 타겟팅
        name_response = requests.get(
            repo_url,
            headers=headers,
            params={"q": f'"{target}" in:name', "per_page": 3},
            timeout=10
        )

        if name_response.status_code == 200:
            for item in name_response.json().get("items", []):
                repo_full_name = item.get("full_name")
                processed_repos.add(repo_full_name) 

                event = ThreatEvent(
                    source="GitHub",
                    event_id=generate_event_id(
                        "GitHub", target, repo_full_name, item.get("html_url")
                    ),
                    email=target,
                    leaked_keyword="Repository Name Match",
                    repository=repo_full_name,
                    url=item.get("html_url"),
                    description=f"[저장소 이름 노출] {item.get('description', '')[:150]}",
                    detected_at=datetime.now(),
                    data_type="live",
                    is_confirmed=False
                )
                
                event = calculate_risk([event])[0]
                all_events.append(event)
                save_to_dynamodb(THREAT_EVENT_TABLE, threat_event_to_dynamodb_item(event))
                
                alerts = create_alerts(User(email=target), [event])
                for alert in alerts:
                    save_to_dynamodb(ALERT_TABLE, alert_to_dynamodb_item(alert))
    except Exception as e:

        print(f"[오류] GitHub 1단계(이름 검색) 실패 : {e}")

    time.sleep(1) 

    # 2. 리포지토리 설명글(Description) 검색
    try:
        # in:description 쿼리를 사용하여 설명글 내부 텍스트 타겟팅
        desc_response = requests.get(
            repo_url,
            headers=headers,
            params={"q": f'"{target}" in:description', "per_page": 3},
            timeout=10
        )

        if desc_response.status_code == 200:
            for item in desc_response.json().get("items", []):
                repo_full_name = item.get("full_name")
                
                # 1단계에서 이미 처리한 저장소면 중복 적재 패스
                if repo_full_name in processed_repos:
                    continue
                
                processed_repos.add(repo_full_name) 

                event = ThreatEvent(
                    source="GitHub",
                    event_id=generate_event_id(
                        "GitHub", target, repo_full_name, item.get("html_url")
                    ),
                    email=target,
                    leaked_keyword="Repository Description Match",
                    repository=repo_full_name,
                    url=item.get("html_url"),
                    description=f"[저장소 설명글 노출] {item.get('description', '')[:150]}",
                    detected_at=datetime.now(),
                    data_type="live",
                    is_confirmed=False
                )
                
                event = calculate_risk([event])[0]
                all_events.append(event)
                save_to_dynamodb(THREAT_EVENT_TABLE, threat_event_to_dynamodb_item(event))
                
                alerts = create_alerts(User(email=target), [event])
                for alert in alerts:
                    save_to_dynamodb(ALERT_TABLE, alert_to_dynamodb_item(alert))
    except Exception as e:
        print(f"[오류] GitHub 2단계(설명글 검색) 실패 : {e}")

    time.sleep(2)

    # 3. 내부 소스코드(Code Content) 텍스트 검색
    try:
        code_response = requests.get(
            code_url,
            headers=headers,
            params={"q": f'"{target}"', "per_page": 5},
            timeout=10
        )

        if code_response.status_code == 200:
            for item in code_response.json().get("items", []):
                repo_info = item.get("repository", {})
                repo_full_name = repo_info.get("full_name")

                # 1, 2단계에서 잡힌 저장소라면 패스
                if repo_full_name in processed_repos:
                    continue

                event = ThreatEvent(
                    source="GitHub",
                    event_id=generate_event_id(
                        "GitHub", target, repo_full_name, item.get("html_url")
                    ),
                    email=target,
                    leaked_keyword="Code Content Match",
                    repository=repo_full_name,
                    url=item.get("html_url"),  
                    description=f"[소스코드 내부 유출] 파일명 : {item.get('name')} (내부에 키워드 존재 파악)",
                    detected_at=datetime.now(),
                    data_type="live",
                    is_confirmed=False
                )

                event = calculate_risk([event])[0]
                all_events.append(event)
                save_to_dynamodb(THREAT_EVENT_TABLE, threat_event_to_dynamodb_item(event))

                alerts = create_alerts(User(email=target), [event])
                for alert in alerts:
                    save_to_dynamodb(ALERT_TABLE, alert_to_dynamodb_item(alert))
    except Exception as e:
        print(f"[오류] GitHub 3단계(소스코드 검색) 실패 : {e}")

    return all_events