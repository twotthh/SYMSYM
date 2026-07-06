import os
import requests
from dotenv import load_dotenv

from backend.models.threat_event import ThreatEvent

load_dotenv()

TOKEN = os.getenv("GITHUB_API_TOKEN")

def search_github_email(email: str):
    """
    특정 이메일이 포함된 GitHub 소스 코드를 검색합니다.
    """
    # repositories(저장소) -> code(코드 내용)으로 타겟 변경
    url = "https://api.github.com/search/code"

    headers = {
        "Authorization": f"Bearer {TOKEN}",
        "Accept": "application/vnd.github+json"
    }

    params = {
        "q": f'"{email}"', 
        "per_page": 5
    }

    response = requests.get(
        url,
        headers=headers,
        params=params,
        timeout=10
    )

    if response.status_code != 200:
        print(f"GitHub API 에러: {response.text}")
        return []

    data = response.json()
    events = []

    # 코드 파일(.py, .txt 등) 기준으로 정보 추출
    for item in data.get("items", []):
        repo = item.get("repository", {})

        event = ThreatEvent(
            source="GitHub",
            email=email, # 어떤 이메일이 털렸는지 
            repository=repo.get("full_name"),
            file_path=item.get("path"), # 털린 파일 이름 (예: config.py)
            url=item.get("html_url"),   # 클릭하면 유출된 코드로 바로 가는 링크
            threat_level="HIGH",        # 개인 이메일 유출이므로 위험도 HIGH로
            description=f"GitHub 소스코드 내에서 '{email}' 유출 의심 파일 발견"
        )

        events.append(event)

    return events


if __name__ == "__main__":
    # 나중에 user.py에서 받아올 사용자의 이메일이라고 가정
    test_email = "test@duksung.ac.kr" 
    
    print(f"[{test_email}] 깃허브 코드 유출 검사 시작\n")
    
    events = search_github_email(test_email)

    if not events:
        print("다행히 깃허브에 유출된 코드가 없습니다")
    else:
        for event in events:
            print(event)
            print("-" * 50)