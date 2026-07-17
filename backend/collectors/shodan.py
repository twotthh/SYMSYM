import os
import time
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
    url = f"https://api.shodan.io/shodan/host/{ip}"
    params = {"key": API_KEY}

    try:
        response = requests.get(url, params=params, timeout=10)

        if response.status_code != 200:
            # 404 에러(Shodan에 기록 없는 IP)는 패스
            if response.status_code != 404:
                print(f"[오류] Shodan API 응답 실패 (IP: {ip}, Status: {response.status_code})")
            return None

        data = response.json()

        open_ports = data.get("ports", [])
        domains = data.get("domains", [])
        hostnames = data.get("hostnames", [])
        
        # 취약점(CVE) 데이터 추출
        vulns = data.get("vulns", []) 

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
            vulnerabilities=vulns, # 추출한 취약점 리스트 모델에 맵핑
            last_scan=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            is_alerted=False
        )

        item = asm_asset_to_dynamodb_item(asset)
        save_to_dynamodb(TABLE_NAME, item)
        
        if vulns:
            print(f"[경고] {ip} 에서 {len(vulns)}개의 취약점(CVE)이 발견되었습니다!")

        return asset

    except Exception as e:
        print(f"[오류] Shodan 스캔 중 문제 발생 ({ip}): {e}")
        return None


def scan_multiple_ips(ip_list: list):
    print(f"\n[Shodan] 전달받은 {len(ip_list)}개의 IP에 대한 정밀 스캔을 시작합니다.")
    
    results = []
    for ip in ip_list:
        # 중복 IP나 빈 문자열 제거
        if not ip or ip.strip() == "":
            continue
            
        print(f" -> 스캔 진행 중: {ip}")
        asset = get_host(ip.strip())
        
        if asset:
            results.append(asset)
            
        time.sleep(1.5) 
        
    print(f"[Shodan] 스캔 완료! 총 {len(results)}개 IP의 인프라 정보가 DB에 적재되었습니다.")
    return results

if __name__ == "__main__":
    # 단일 IP 테스트
    get_host("8.8.8.8")