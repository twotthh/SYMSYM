from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional


@dataclass
class AsmAsset:
    """
    ASM(Attack Surface Management) 자산 모델
    (Censys, Shodan 공통 사용 ver.)
    """

    # 데이터 출처
    source: str

    # 자산 정보
    ip: str
    domain: Optional[str] = None
    hostname: Optional[List[str]] = None

    # 네트워크 정보
    organization: Optional[str] = None
    isp: Optional[str] = None
    asn: Optional[str] = None
    country: Optional[str] = None

    # 서비스 정보
    open_ports: Optional[List[int]] = None
    service_count: Optional[int] = None
    protocol: Optional[str] = None
    banner: Optional[str] = None
    os: Optional[str] = None

    # 취약점 정보
    vulnerabilities: Optional[List[dict]] = None

    # 평판 정보 (Censys)
    reputation_score: Optional[int] = None
    reputation_level: Optional[str] = None

    # 스캔 정보
    last_scan: Optional[datetime] = None

    # 시스템 관리
    is_alerted: bool = False
