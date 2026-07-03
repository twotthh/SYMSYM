import os
import requests
from dotenv import load_dotenv

from backend.models.asm_asset import AsmAsset

load_dotenv()

API_TOKEN = os.getenv("CENSYS_API_TOKEN")

HEADERS = {
    "Authorization": f"Bearer {API_TOKEN}",
    "Accept": "application/json"
}


def get_host(host_id: str):
    """
    Censys Host 조회 후 AsmAsset 객체 반환
    """

    url = f"https://api.platform.censys.io/v3/global/asset/host/{host_id}"

    response = requests.get(
        url,
        headers=HEADERS,
        timeout=10
    )

    if response.status_code != 200:
        print(f"Censys API Error: {response.status_code}")
        print(response.text)
        return None

    host = response.json()

    # 실제 자산 데이터
    asset_data = host.get("result", {}).get("resource", {})

    # 열린 포트 추출
    open_ports = [
        service.get("port")
        for service in asset_data.get("services", [])
        if service.get("port") is not None
    ]

    # DNS 정보
    dns_info = asset_data.get("dns", {})

    # 대표 Hostname
    hostname = dns_info.get("reverse_dns", {}).get("names")

    # Domain 목록
    domains = dns_info.get("names", [])

    # ASN 정보
    as_info = asset_data.get("autonomous_system", {})

    # 위치 정보
    location = asset_data.get("location", {})

    asset = AsmAsset(
        source="Censys",

        ip=asset_data.get("ip"),

        domain=", ".join(domains) if domains else None,

        hostname=hostname,

        organization=as_info.get("name"),

        isp=as_info.get("description"),

        asn=str(as_info.get("asn")) if as_info.get("asn") else None,

        country=location.get("country"),

        open_ports=open_ports,

        service_count=asset_data.get("service_count"),

        protocol=None,

        banner=None,

        os=None,

        vulnerabilities=None,

        reputation_score=None,

        reputation_level=None,

        last_scan=None,

        is_alerted=False
    )

    return asset


if __name__ == "__main__":

    asset = get_host("8.8.8.8")

    print(asset)
