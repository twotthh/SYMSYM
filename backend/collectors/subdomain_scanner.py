import requests
from test_firebase import db 

def scan_subdomains(domain="duksung.ac.kr"):
    print(f"서브도메인 탐색 시작: {domain}")
    
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    
    try:
        response = requests.get(url)
        
        if response.status_code != 200:
            print(f"API 접속 실패 (상태 코드: {response.status_code})")
            return
            
        data = response.text.strip().split('\n')
        
        if not data or "error" in data[0].lower():
            print("외부에 노출된 서버 정보가 없거나 검색 한도에 도달")
            return
            
        print("인프라 정보 발견 & 파이어베이스로 전송\n")
        
        # 발견된 서브도메인 중 상위 10개만 파이어베이스에 저장
        count = 0
        for line in data:
            if "," in line and count < 10:
                host, ip = line.split(",")
                print(f"서브도메인: {host} | IP: {ip}")
                
                # 파이어베이스 데이터베이스(Firestore)에 쏠 데이터 구조
                asm_data = {
                    "domain": host,
                    "ip": ip,
                    "source": "HackerTarget",
                    "is_alerted": False,
                    "scanned_at": "now"
                }
                db.collection('asm_vulnerabilities').add(asm_data)
                count += 1
                
        print("\nASM 데이터를 파이어베이스에 동기화")
        
    except Exception as e:
        print(f"스캔 중 문제 발생: {e}")

if __name__ == '__main__':
    scan_subdomains()