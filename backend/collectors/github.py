import os
import requests
from dotenv import load_dotenv

from backend.models.threat_event import ThreatEvent

load_dotenv()

TOKEN = os.getenv("GITHUB_API_TOKEN")


def search_repository(keyword: str):

    url = "https://api.github.com/search/repositories"

    headers = {
        "Authorization": f"Bearer {TOKEN}",
        "Accept": "application/vnd.github+json"
    }

    params = {
        "q": keyword,
        "per_page": 5
    }

    response = requests.get(
        url,
        headers=headers,
        params=params,
        timeout=10
    )

    if response.status_code != 200:
        print(response.text)
        return []

    data = response.json()

    events = []

    for repo in data.get("items", []):

        event = ThreatEvent(
            source="GitHub",

            leaked_keyword=keyword,

            repository=repo.get("full_name"),

            url=repo.get("html_url"),

            threat_level="MEDIUM",

            description=f"'{keyword}' 키워드가 포함된 공개 Repository 발견"
        )

        events.append(event)

    return events


if __name__ == "__main__":

    events = search_repository("duksung")

    for event in events:
        print(event)
