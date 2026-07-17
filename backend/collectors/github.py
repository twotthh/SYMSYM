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

    print(f"[GitHub] '{target}' 기반 2단계 정밀 모니터링 시작")

    try:
        # 1. 리포지토리 검색 (이름이나 설명에 키워드가 있는 경우)
        repo_response = requests.get(
            repo_url,
            headers=headers,
            params={"q": f'"{target}"', "per_page": 3},
            timeout=10
        )

        if repo_response.status_code == 200:
            for item in repo_response.json().get("items", []):
                repo_full_name = item.get("full_name")
                processed_repos.add(repo_full_name)  # 1단계에서 잡힌 저장소 등록

                event = ThreatEvent(
                    source="GitHub",
                    event_id=generate_event_id(
                        "GitHub",
                        target,
                        repo_full_name,
                        item.get("html_url")
                    ),
                    email=target,
                    leaked_keyword="Repository Match",
                    repository=repo_full_name,
                    url=item.get("html_url"),
                    description=f"[저장소 노출] {item.get('description', '')[:150]}",
                    detected_at=datetime.now(),
                    is_confirmed=False
                )
                
                # 위험도 채점, 매핑 및 DB 저장
                event = calculate_risk([event])[0]
                all_events.append(event)
                save_to_dynamodb(THREAT_EVENT_TABLE, threat_event_to_dynamodb_item(event))
                
                # 알림 생성 및 저장
                alerts = create_alerts(User(email=target), [event])
                for alert in alerts:
                    save_to_dynamodb(ALERT_TABLE, alert_to_dynamodb_item(alert))

        time.sleep(1)

        # 2. 소스코드 검색 (리포지토리엔 없지만 코드 텍스트 내부에 숨어있는 경우)
        # 전 세계 퍼블릭 코드 전체를 대상으로 타겟 키워드가 박힌 소스파일 검색
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

                # 이미 1단계(리포지토리 이름 검색)에서 처리된 저장소라면 중복 저장 패스
                if repo_full_name in processed_repos:
                    continue

                event = ThreatEvent(
                    source="GitHub",
                    event_id=generate_event_id(
                        "GitHub",
                        target,
                        repo_full_name,
                        item.get("html_url")
                    ),
                    email=target,
                    leaked_keyword="Code Content Match",
                    repository=repo_full_name,
                    url=item.get("html_url"),  # 실제 유출된 소스코드 파일의 직접 링크
                    description=f"[소스코드 내부 유출] 파일명 : {item.get('name')} (해당 소스코드 내부에 키워드 존재 파악)",
                    detected_at=datetime.now(),
                    data_type="live",
                    is_confirmed=False
                )

                # 위험도 채점, 매핑 및 DB 저장
                event = calculate_risk([event])[0]
                all_events.append(event)
                save_to_dynamodb(THREAT_EVENT_TABLE, threat_event_to_dynamodb_item(event))

                # 알림 생성 및 저장
                alerts = create_alerts(User(email=target), [event])
                for alert in alerts:
                    save_to_dynamodb(ALERT_TABLE, alert_to_dynamodb_item(alert))

        return all_events

    except Exception as e:
        print(f"[오류] GitHub 2단계 정밀 검색 중 문제가 발생했습니다 : {e}")
        return []