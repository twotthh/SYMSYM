import os
import asyncio
import httpx
from dotenv import load_dotenv

load_dotenv()

NUMVERIFY_API_KEY = os.getenv("NUMVERIFY_API_KEY", "")

async def check_voip_numverify(formatted_number: str):
    # NumVerify를 이용해 가상번호 및 대포폰 식별
    url = f"http://apilayer.net/api/validate?access_key={NUMVERIFY_API_KEY}&number={formatted_number}"
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(url, timeout=5.0)
            data = response.json()
            
            if data.get("valid"):
                line_type = data.get("line_type", "")
                carrier = data.get("carrier", "알 수 없음")
                
                if line_type == "mobile":
                    return {"threat_level": "LOW", "desc": f"정상 모바일 번호입니다. (통신사: {carrier})"}
                elif line_type in ["voip", "landline", "special"]:
                    return {"threat_level": "HIGH", "desc": f"주의! 가상번호(VoIP) 또는 유선 전화입니다. 인증용 가짜 번호일 가능성이 높습니다. (통신사: {carrier})"}
    except Exception as e:
        print(f"[Phone Scanner] NumVerify API 에러: {e}")
        
    return None

async def search_google_exposure(phone_number: str):
    # 구글 검색을 통해 웹상에 번호가 노출되었는지 추적
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }
    # 번호를 따옴표로 묶어 정확히 일치하는 결과만 검색 -> Google Dorking
    query = f'"{phone_number}"'
    url = f"https://www.google.com/search?q={query}"
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=headers, timeout=5.0)
            if response.status_code == 200:
                # 결과 없음 텍스트가 페이지에 포함되어 있지 않다면 -> 검색 결과가 존재
                if "일치하는 검색결과가 없습니다" not in response.text and "did not match any documents" not in response.text:
                    return True
    except Exception as e:
        print(f"[Phone Scanner] 구글 검색 에러: {e}")
        
    return False

async def scan_phone_number(phone_number: str):
    print(f"\n[Phone Scanner] '{phone_number}' 스캔 시작...")
    alerts = []
    
    # 1. 번호 포맷팅
    clean_number = phone_number.replace("-", "").replace(" ", "")
    if clean_number.startswith("010"):
        international_number = "+82" + clean_number[1:]
    else:
        international_number = phone_number

    # 2. 가상번호 조회 실행
    voip_result = await check_voip_numverify(international_number)
    
    # API 결과가 성공적으로 돌아왔을 때만 알림 리스트에 추가 
    if voip_result:
        alerts.append({
            "source": "NumVerify (대포폰 식별)",
            "threat_level": voip_result["threat_level"],
            "description": voip_result["desc"]
        })

    # 3. 구글 Dorking 조회 실행 
    print(f"[Phone Scanner] 구글 웹 노출 정보 추적 중...")
    is_exposed_1 = await search_google_exposure(phone_number) 
    is_exposed_2 = await search_google_exposure(clean_number)   
    
    if is_exposed_1 or is_exposed_2:
        alerts.append({
            "source": "Google OSINT (웹 노출 추적)",
            "threat_level": "MEDIUM",
            "description": "인터넷 상(게시판, 이력서, 중고거래 등)에 해당 전화번호가 노출된 흔적이 발견되었습니다. 스팸 타겟이 될 수 있습니다!"
        })
    else:
        alerts.append({
            "source": "Google OSINT (웹 노출 추적)",
            "threat_level": "LOW",
            "description": "구글 스캔 결과, 웹상에 노출된 흔적이 발견되지 않았습니다. 안전해요^^"
        })
        
    print(f"[Phone Scanner] 스캔 완료! (위협 {len(alerts)}건 발견)\n")
    return alerts