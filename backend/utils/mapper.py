from backend.models.threat_event import ThreatEvent


def threat_event_to_dynamodb_item(event: ThreatEvent) -> dict:
    """
    ThreatEvent → DynamoDB 저장 형식(dict) 변환
    """

    return {
        "event_id": (
            f"{event.source}-"
            f"{event.email or event.leaked_keyword or 'unknown'}-"
            f"{event.detected_at}"
        ),

        "email": event.email,

        "detected_at": str(event.detected_at) if event.detected_at else None,

        "source": event.source,

        "threat_level": event.threat_level,

        "breach_name": event.breach_name,

        "repository": event.repository,

        "file_path": event.file_path,

        "url": event.url,

        "channel_name": event.channel_name,

        "channel_id": event.channel_id,

        "message_id": event.message_id,

        "description": event.description,

        "is_confirmed": event.is_confirmed
    }