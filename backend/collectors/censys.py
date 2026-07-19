import os
import time
import requests
from datetime import datetime
from dotenv import load_dotenv

from backend.models.asm_asset import AsmAsset
from backend.services.aws_db import save_to_dynamodb
from backend.utils.mapper import asm_asset_to_dynamodb_item

load_dotenv()

API_TOKEN = os.getenv("CENSYS_API_TOKEN")
TABLE_NAME = "symsym-asm-assets"

HEADERS = {
    "Authorization": f"Bearer {API_TOKEN}",
    "Accept": "application/json"
}

def get_host(ip: str): 
    url = f"https://api.platform.censys.io/v3/global/asset/host/{ip}"

    try:
        # 1. Censys API 호출
        response = requests.get(
            url,
            headers=HEADERS,
            timeout=10
        )

        # 2. 응답 상태 확인
        if response.status_code != 200:
            if response.status_code != 404:
                print(f"[오류] Censys API 응답 실패 (IP: {ip}, Status: {response.status_code})")
            return None

        host = response.json()
        asset_data = host.get("result", {}).get("resource", {})

        # 3. Censys 결과 데이터 파싱
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
        
        # 운영체제 정보 추가 파싱 
        os_name = asset_data.get("operating_system", {}).get("product")

        # 4. Censys 응답을 AsmAsset 모델로 변환
        asset = AsmAsset(
            source="Censys",
            ip=asset_data.get("ip", ip),
            domain=", ".join(domains) if domains else None,
            hostname=hostname,
            organization=as_info.get("name"),
            isp=as_info.get("description"),
            asn=str(as_info.get("asn")) if as_info.get("asn") else None,
            country=location.get("country"),
            open_ports=open_ports,
            service_count=asset_data.get("service_count", len(open_ports)),
            os=os_name, 
            vulnerabilities=[], 
            last_scan=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            is_alerted=False
        )

        # 5. 공통 Mapper를 이용하여 DynamoDB 저장 형식으로 변환
        item = asm_asset_to_dynamodb_item(asset)

        # 6. DynamoDB 저장
        save_to_dynamodb(TABLE_NAME, item)

        return asset

    except Exception as e:
        print(f"[오류] Censys 스캔 중 문제가 발생했습니다 ({ip}): {e}")
        return None

def scan_multiple_ips(ip_list: list):
    print(f"\n[Censys] 전달받은 {len(ip_list)}개의 IP에 대한 정밀 스캔을 시작합니다.")
    
    results = []
    for ip in ip_list:
        if not ip or ip.strip() == "":
            continue
            
        print(f" -> 스캔 진행 중: {ip}")
        asset = get_host(ip.strip())
        
        if asset:
            results.append(asset)
            
        time.sleep(1.5) 
        
    print(f"[Censys] 스캔 완료! 총 {len(results)}개 IP의 인프라 정보가 DB에 적재되었습니다.")
    return results

if __name__ == "__main__":
    print("===== Censys 인프라 스캔 및 AWS 저장 테스트 =====\n")
    asset = get_host("8.8.8.8")
    if asset:
        print(f"[Censys] {asset.ip} 자산 정보를 AWS에 저장 완료했습니다.")