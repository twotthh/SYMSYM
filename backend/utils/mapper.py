from backend.models.threat_event import ThreatEvent
from backend.models.asm_asset import AsmAsset
from backend.models.alert import Alert


def threat_event_to_dynamodb_item(event: ThreatEvent) -> dict:
    """
    ThreatEvent → DynamoDB 저장 형식(dict) 변환
    """

    return {
        # ThreatEvent에서 생성된 고유 ID를 그대로 사용
        # Alert에서도 동일한 event_id를 사용하여 원본 이벤트와 연결
        "event_id": event.event_id,

        # DynamoDB 기본 키
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


def asm_asset_to_dynamodb_item(asset: AsmAsset) -> dict:
    """
    AsmAsset → DynamoDB 저장 형식(dict) 변환
    """

    return {
        # 출처, IP, 스캔 시간을 조합하여 자산 고유 ID 생성
        "asset_id": f"{asset.source}-{asset.ip}-{asset.last_scan}",

        # DynamoDB 기본 키
        "ip": asset.ip,
        "last_scan": str(asset.last_scan) if asset.last_scan else None,

        "source": asset.source,
        "domain": asset.domain,
        "hostname": asset.hostname,
        "organization": asset.organization,
        "isp": asset.isp,
        "asn": asset.asn,
        "country": asset.country,

        "open_ports": asset.open_ports,
        "service_count": asset.service_count,
        "protocol": asset.protocol,
        "banner": asset.banner,
        "os": asset.os,

        "vulnerabilities": asset.vulnerabilities,
        "reputation_score": asset.reputation_score,
        "reputation_level": asset.reputation_level,

        "is_alerted": asset.is_alerted
    }


def alert_to_dynamodb_item(alert: Alert) -> dict:
    """
    Alert → DynamoDB 저장 형식(dict) 변환
    """

    return {
        # DynamoDB 기본 키
        "user_email": alert.user_email,
        "event_id": alert.event_id,

        "source": alert.source,
        "alert_type": alert.alert_type,
        "title": alert.title,
        "message": alert.message,
        "threat_level": alert.threat_level,

        "sent_at": (
            alert.sent_at.strftime("%Y-%m-%d %H:%M:%S")
            if alert.sent_at
            else None
        ),

        "is_read": alert.is_read
    }