import os
import requests
from datetime import datetime
from dotenv import load_dotenv

from backend.models.asm_asset import AsmAsset
from backend.services.aws_db import save_to_dynamodb
from backend.utils.mapper import asm_asset_to_dynamodb_item

load_dotenv()

API_KEY = os.getenv("SHODAN_API_KEY")
TABLE_NAME = "symsym-asm-assets"


def get_host(ip: str):
    """
    Shodan에서 IP 기반 인프라 정보를 조회하여
    AsmAsset 생성 후 DynamoDB에 저장한다.

    Return:
        AsmAsset | None
    """

    url = f"https://api.shodan.io/shodan/host/{ip}"
    params = {"key": API_KEY}

    try:
        # 1. Shodan API 호출
        response = requests.get(
            url,
            params=params,
            timeout=10
        )

        # 2. 응답 상태 확인
        if response.status_code != 200:
            print(f"[오류] Shodan API 응답 실패 (Status: {response.status_code})")
            return None

        data = response.json()

        # 3. Shodan 결과 데이터 파싱
        open_ports = data.get("ports", [])
        domains = data.get("domains", [])
        hostnames = data.get("hostnames", [])

        # 4. Shodan 응답을 AsmAsset 모델로 변환
        asset = AsmAsset(
            source="Shodan",
            ip=data.get("ip_str", ip),
            domain=", ".join(domains) if domains else None,
            hostname=hostnames if hostnames else None,
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

        # 5. 공통 Mapper를 이용하여 DynamoDB 저장 형식으로 변환
        item = asm_asset_to_dynamodb_item(asset)

        # 6. DynamoDB 저장
        save_to_dynamodb(TABLE_NAME, item)

        return asset

    except Exception as e:
        print(f"[오류] Shodan 스캔 중 문제가 발생했습니다: {e}")
        return None


if __name__ == "__main__":
    print("===== Shodan 인프라 스캔 및 AWS 저장 테스트 =====\n")

    asset = get_host("8.8.8.8")

    if asset:
        print(f"[Shodan] {asset.ip} 자산 정보를 AWS에 저장 완료")
    else:
        print("Shodan 자산 정보를 가져오지 못했습니다.")