import os
import requests
import dataclasses
from datetime import datetime
from dotenv import load_dotenv

from backend.models.asm_asset import AsmAsset
from backend.services.aws_db import save_to_dynamodb

load_dotenv()

API_TOKEN = os.getenv("CENSYS_API_TOKEN")

HEADERS = {
    "Authorization": f"Bearer {API_TOKEN}",
    "Accept": "application/json"
}

def get_host(host_id: str):
    url = f"https://api.platform.censys.io/v3/global/asset/host/{host_id}"

    response = requests.get(url, headers=HEADERS, timeout=10)

    if response.status_code != 200:
        print(f"Censys API Error: {response.status_code}")
        return None

    host = response.json()
    asset_data = host.get("result", {}).get("resource", {})

    open_ports = [
        service.get("port")
        for service in asset_data.get("services", [])
        if service.get("port") is not None
    ]

    dns_info = asset_data.get("dns", {})
    hostname = dns_info.get("reverse_dns", {}).get("names")
    domains = dns_info.get("names", [])
    as_info = asset_data.get("autonomous_system", {})
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
        last_scan=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        is_alerted=False
    )

    item_to_save = {k: v for k, v in dataclasses.asdict(asset).items() if v is not None}
    save_to_dynamodb('symsym-asm-assets', item_to_save)

    return asset


if __name__ == "__main__":
    print("Censys 인프라 스캔 및 AWS 저장 테스트\n")
    asset = get_host("8.8.8.8")
    
    if asset:
        print(f"[Censys] {asset.ip} 자산 정보를 AWS에 저장 완료")