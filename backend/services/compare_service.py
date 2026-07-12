from typing import List
from backend.models.user import User
from backend.models.threat_event import ThreatEvent

def compare_user_with_events(
    user: User,
    events: List[ThreatEvent]
) -> List[ThreatEvent]:

    matched_events = []

    for event in events:

        # 이메일 비교(HIBP)
        if (
            event.email
            and event.email.lower() == user.email.lower()
        ):
            matched_events.append(event)
            continue

        # Repository 비교(GitHub)
        if (
            event.repository
            and user.target_domain.lower()
            in event.repository.lower()
        ):
            matched_events.append(event)
            continue

        # URL 비교
        if (
            event.url
            and user.target_domain.lower()
            in event.url.lower()
        ):
            matched_events.append(event)
            continue

        # 키워드 비교(GitHub / Telegram)
        if (
            event.leaked_keyword
            and user.target_domain.lower()
            in event.leaked_keyword.lower()
        ):
            matched_events.append(event)
            continue

    return matched_events
