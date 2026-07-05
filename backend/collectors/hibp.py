import os
from datetime import datetime

from dotenv import load_dotenv

from backend.models.threat_event import ThreatEvent

load_dotenv()

API_KEY = os.getenv("HIBP_API_KEY")


def search_breach(email: str):
    """
    HIBP 이메일 유출 조회

    *Mock 데이터를 사용
    *API Key가 준비 후 HIBP API 응답으로 교체 예정
    """

    # -------------------------
    # Mock Response
    # (HIBP 공식 Sample Response 기반)
    # -------------------------
    mock_data = [
        {
            "Name": "Adobe",
            "Description": "Adobe accounts were breached."
        },
        {
            "Name": "LinkedIn",
            "Description": "LinkedIn user information leaked."
        }
    ]

    events = []

    for breach in mock_data:

        event = ThreatEvent(

            source="HIBP",

            email=email,

            breach_name=breach.get("Name"),

            threat_level="HIGH",

            description=breach.get("Description"),

            detected_at=datetime.now()

        )

        events.append(event)

    return events


if __name__ == "__main__":

    events = search_breach("abc@duksung.ac.kr")

    for event in events:
        print(event)
