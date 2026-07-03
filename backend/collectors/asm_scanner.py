import os
import requests
from dotenv import load_dotenv
from test_firebase import db

load_dotenv()
API_TOKEN = os.getenv('CENSYS_API_TOKEN')

def scan_infrastructure(domain="duksung.ac.kr"):
    print(f"Censys 인프라 스캔 시작: {domain}")
    
    if not API_TOKEN:
        print("[오류] .env 파일에서 토큰을 찾지 못했습니다. 파일 이름이 정확히 .env 인지 확인해주세요")
        return

    clean_token = API_TOKEN.strip().strip("'").strip('"')
    
    url = "https://search.censys.io/api/v2/hosts/search"
    headers = {
        "Authorization": f"Bearer {clean_token}",
        "Accept": "application/json"
    }
    params = {
        "q": f"services.dns.name: {domain}",
        "per_page": 1
    }
    
    try:
        response = requests.get(url, headers=headers, params=params)
        
        if response.status_code != 200:
            print(f"스캔 실패 (상태 코드: {response.status_code})")
            print(f"거절 이유: {response.text}")
            return
            
        data = response.json()
        results = data.get("result", {}).get("hits", [])
        
        if not results:
            print("해당 도메인으로 외부에 노출된 취약한 서버가 발견되지 않음")
            return
            
        for host in results:
            ip = host.get("ip")
            services = host.get("services", [])
            open_ports = [svc.get("port") for svc in services]
            
            print(f"발견된 IP: {ip} | 열린 포트: {open_ports}")
            
            asm_data = {
                "domain": domain,
                "ip": ip,
                "open_ports": open_ports,
                "is_alerted": False,
                "scanned_at": "now"
            }
            db.collection('asm_vulnerabilities').add(asm_data)
            
        print("ASM 데이터를 파이어베이스에 동기화")
        
    except Exception as e:
        print(f"파이썬 코드 실행 중 문제 발생: {e}")

if __name__ == '__main__':
    scan_infrastructure()