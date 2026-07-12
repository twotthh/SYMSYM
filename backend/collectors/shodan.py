import os
import requests
import dataclasses
from datetime import datetime
from dotenv import load_dotenv

from backend.models.asm_asset import AsmAsset
from backend.services.aws_db import save_to_dynamodb

load_dotenv()

API_KEY = os.getenv("SHODAN_API_KEY")

def get_host(ip: str):
    url = f"https://api.shodan.io/shodan/host/{ip}"
    params = {"key": API_KEY}

    response = requests.get(url, params=params, timeout=10)

    if response.status_code != 200:
        print(f"Shodan API Error: {response.status_code}")
        return None

    data = response.json()

    # Shodan 결과 데이터를 파싱하여 AsmAsset 모델로 규격화
    open_ports = data.get("ports", [])
    domains = data.get("domains", [])
    hostnames = data.get("hostnames", [])

    asset = AsmAsset(
        source="Shodan",
        ip=data.get("ip_str", ip),
        domain=", ".join(domains) if domains else None,
        hostname=", ".join(hostnames) if hostnames else None,
        organization=data.get("org"),
        isp=data.get("isp"),
        asn=str(data.get("asn")) if data.get("asn") else None,
        country=data.get("country_name"),
        open_ports=open_ports,
        service_count=len(open_ports),
        os=data.get("os"),
        last_scan=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        is_alerted=False
    )

    item_to_save = {k: v for k, v in dataclasses.asdict(asset).items() if v is not None}
    save_to_dynamodb('symsym-asm-assets', item_to_save)

    return asset


if __name__ == "__main__":
    print("Shodan 인프라 스캔 및 AWS 저장 테스트\n")
    asset = get_host("8.8.8.8")

    if asset:
        print(f"[Shodan] {asset.ip} 자산 정보를 AWS에 저장 완료")