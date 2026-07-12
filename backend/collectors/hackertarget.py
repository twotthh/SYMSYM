import dataclasses
import requests
from datetime import datetime
from backend.models.asm_asset import AsmAsset
from backend.services.aws_db import save_to_dynamodb

def scan_subdomains(domain="duksung.ac.kr"):
    print(f"HackerTarget 서브도메인 탐색 시작: {domain}")
    
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    
    try:
        response = requests.get(url, timeout=10)
        
        if response.status_code != 200:
            print(f"API 접속 실패 (상태 코드: {response.status_code})")
            return []
            
        data = response.text.strip().split('\n')
        
        if not data or "error" in data[0].lower():
            print("외부에 노출된 서버 정보가 없거나 검색 한도에 도달")
            return []
            
        assets = []
        count = 0
        
        for line in data:
            if "," in line and count < 10:
                host, ip = line.split(",")
                
                asset = AsmAsset(
                    source="HackerTarget",
                    ip=ip,
                    domain=host,
                    last_scan=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                )
                assets.append(asset)
                
                item_to_save = {k: v for k, v in dataclasses.asdict(asset).items() if v is not None}
                save_to_dynamodb('symsym-asm-assets', item_to_save)
                
                count += 1
                
        return assets
        
    except Exception as e:
        print(f"스캔 중 문제 발생: {e}")
        return []

if __name__ == '__main__':
    results = scan_subdomains("duksung.ac.kr")
    
    if not results:
        print("발견된 인프라 정보가 없음")
    else:
        print(f"\n총 {len(results)}건의 서브도메인 인프라 정보를 AWS에 저장 완료")