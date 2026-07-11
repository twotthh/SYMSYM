from backend.models.threat_event import ThreatEvent
# AsmAsset 모델을 불러오기
from backend.models.asm_asset import AsmAsset

def threat_event_to_dynamodb_item(event: ThreatEvent) -> dict:
    # ThreatEvent → DynamoDB 저장 형식(dict) 변환
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

def asm_asset_to_dynamodb_item(asset: AsmAsset) -> dict:
    # AsmAsset(인프라 정보) → DynamoDB 저장 형식(dict) 변환
    return {
        # IP와 스캔 시간을 조합해 고유한 ID를 생성
        "asset_id": f"{asset.source}-{asset.ip}-{asset.last_scan}",
        
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