import requests
from datetime import datetime

from backend.models.asm_asset import AsmAsset
from backend.services.aws_db import save_to_dynamodb
from backend.utils.mapper import asm_asset_to_dynamodb_item

TABLE_NAME = "symsym-asm-assets"

def scan_subdomains(domain: str):
    print(f"[HackerTarget] 서브도메인 탐색 시작: {domain}")

    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"

    try:
        # 1. HackerTarget API 호출
        response = requests.get(url, timeout=10)

        # 2. 응답 상태 확인
        if response.status_code != 200:
            print(f"API 접속 실패 (상태 코드: {response.status_code})")
            return []

        data = response.text.strip().split("\n")

        if not data or "error" in data[0].lower():
            print("외부에 노출된 서버 정보가 없거나 검색 한도에 도달")
            return []

        assets = []
        extracted_ips = [] # Shodan으로 넘겨줄 IP 리스트

        # 3. HackerTarget 응답을 AsmAsset 모델로 변환
        for line in data:
            if "," in line:
                host, ip = line.split(",", 1)

                asset = AsmAsset(
                    source="HackerTarget",
                    ip=ip,
                    domain=host,
                    last_scan=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                )

                assets.append(asset)
                extracted_ips.append(ip) # IP만 따로 리스트에 보관

                # 4. 공통 Mapper를 이용하여 DynamoDB 저장 형식으로 변환
                item = asm_asset_to_dynamodb_item(asset)

                # 5. DynamoDB 저장
                save_to_dynamodb(TABLE_NAME, item)

        print(f"[HackerTarget] 총 {len(assets)}건의 인프라 정보 AWS 저장 완료")
        
        # Shodan 모니터링 파이프라인으로 넘기기 위해 IP 리스트를 return
        return extracted_ips

    except Exception as e:
        print(f"스캔 중 문제 발생: {e}")
        return []

if __name__ == "__main__":
    results = scan_subdomains("duksung.ac.kr")
    if not results:
        print("발견된 인프라 정보가 없음")
    else:
        print(f"\n추출된 IP 리스트: {results}")