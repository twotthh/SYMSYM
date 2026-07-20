import os
import asyncio
import httpx

from bs4 import BeautifulSoup
from dotenv import load_dotenv
from telethon import TelegramClient
from telethon.tl.functions.contacts import ImportContactsRequest, DeleteContactsRequest
from telethon.tl.types import InputPhoneContact

load_dotenv()

NUMVERIFY_API_KEY = os.getenv("NUMVERIFY_API_KEY", "")
TRUECALLER_API_KEY = os.getenv("TRUECALLER_API_KEY", "") 
TELEGRAM_API_ID = os.getenv("TELEGRAM_API_ID", "")  
TELEGRAM_API_HASH = os.getenv("TELEGRAM_API_HASH", "")

async def check_thecall_spam(phone_number: str):
    formatted_number = phone_number
    if "-" not in phone_number and len(phone_number) == 11:
        formatted_number = f"{phone_number[:3]}-{phone_number[3:7]}-{phone_number[7:]}"

    url = f"https://www.thecall.co.kr/bbs/board.php?bo_table=phone&stx={formatted_number}"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    }

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=headers, timeout=5.0)
            if "게시물이 없습니다" not in response.text:
                return {
                    "threat_level": "HIGH", 
                    "description": "국내 최대 스팸 데이터베이스(더콜)에서 악성/스팸 번호로 신고된 이력이 발견되었습니다."
                }
    except Exception as e:
        print(f"[Phone Scanner] 더콜 크롤링 에러: {e}")
    return None

async def check_voip_numverify(formatted_number: str):
    # 1. 가상번호 및 대포폰 식별
    if not NUMVERIFY_API_KEY: return None
        
    url = f"http://apilayer.net/api/validate?access_key={NUMVERIFY_API_KEY}&number={formatted_number}"
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(url, timeout=5.0)
            data = response.json()
            if data.get("valid"):
                line_type = data.get("line_type", "")
                carrier = data.get("carrier", "알 수 없음")
                
                if line_type == "mobile":
                    return {"threat_level": "LOW", "description": f"정상 모바일 번호입니다. (통신사: {carrier})"}
                elif line_type in ["voip", "landline", "special"]:
                    return {"threat_level": "HIGH", "description": f"주의! 가상번호(VoIP/유선)입니다. 대포폰일 가능성이 높습니다. (통신사: {carrier})"}
    except Exception as e:
        print(f"[Phone Scanner] NumVerify API 에러: {e}")
    return None

async def search_google_exposure(phone_number: str):
    # 2. 구글 웹 Dorking
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    query = f'"{phone_number}"'
    url = f"https://www.google.com/search?q={query}"
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=headers, timeout=5.0)
            if response.status_code == 200:
                if "일치하는 검색결과가 없습니다" not in response.text and "did not match any documents" not in response.text:
                    return True
    except Exception as e:
        print(f"[Phone Scanner] 구글 검색 에러: {e}")
    return False

async def check_truecaller_osint(international_number: str):
    # 3. 글로벌 발신자 DB (Truecaller)
    if not TRUECALLER_API_KEY: return None

    url = "https://truecaller4.p.rapidapi.com/api/v1/getDetails?countryCode=KR"
    querystring = {"phone": international_number}
    headers = {
        "X-RapidAPI-Key": TRUECALLER_API_KEY,
        "X-RapidAPI-Host": "truecaller4.p.rapidapi.com"
    }

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=headers, params=querystring, timeout=5.0)
            if response.status_code == 200:
                data = response.json()
                name = data.get("name", "")
                spam_score = data.get("spamScore", 0)

                if name:
                    t_level = "HIGH" if spam_score > 0 else "LOW"
                    description_text = f"글로벌 연락처 DB(TrueCaller)에서 '{name}'(으)로 저장된 이력이 확인되었습니다."
                    if spam_score > 0: description_text += " (스팸 신고 이력 포함)"
                    return {"threat_level": t_level, "description": description_text}
    except Exception as e:
        print(f"[Phone Scanner] Truecaller 에러: {e}")
    return None

async def check_telegram_account(phone_number: str):
    """[Phase 3] 텔레그램 가입 여부 식별 (주소록 추가/삭제 기법)"""
    if not TELEGRAM_API_ID or not TELEGRAM_API_HASH: 
        return None

    # 국제 번호 포맷으로 변환
    clean_number = phone_number.replace("-", "").replace(" ", "")
    international_number = f"+82{clean_number[1:]}" if clean_number.startswith("010") else phone_number

    # 전화번호 모듈 전용 세션 생성 
    client = TelegramClient('symsym_phone_session', int(TELEGRAM_API_ID), TELEGRAM_API_HASH)
    
    try:
        await client.connect()
        
        # 로그인이 안 되어있다면 스킵 
        if not await client.is_user_authorized():
            print("[Phone Scanner] 텔레그램 전용 로그인이 필요하여 조회를 건너뜁니다.")
            await client.disconnect()
            return None

        # 1. 대상 번호를 가상의 주소록에 추가
        contact = InputPhoneContact(client_id=0, phone=international_number, first_name="Target", last_name="")
        result = await client(ImportContactsRequest([contact]))

        alert_info = None
        # 2. 유저 정보가 반환되었다면 가입된 번호
        if result.users:
            user = result.users[0]
            username = f"@{user.username}" if user.username else "아이디 비공개"
            alert_info = {
                "threat_level": "MEDIUM",
                "description": f"익명 통신에 자주 활용되는 텔레그램 메신저 가입 번호입니다. (프로필: {username})"
            }
            
            await client(DeleteContactsRequest(id=[user.id]))

        await client.disconnect()
        return alert_info

    except Exception as e:
        print(f"[Phone Scanner] 텔레그램 연동 에러: {e}")
        
    return None

async def scan_phone_number(phone_number: str):
    print(f"\n[Phone Scanner] '{phone_number}' 종합 스캔 시작...")
    alerts = []
    
    # 번호 포맷팅
    clean_number = phone_number.replace("-", "").replace(" ", "")
    international_number = f"+82{clean_number[1:]}" if clean_number.startswith("010") else phone_number

    # 한국 스팸 DB (더콜) 조회
    thecall_result = await check_thecall_spam(phone_number)
    if thecall_result:
        alerts.append({"source": "TheCall (한국 스팸 DB)", **thecall_result})

    # 대포폰  조회
    voip_result = await check_voip_numverify(international_number)
    if voip_result:
        alerts.append({"source": "NumVerify (대포폰 식별)", **voip_result})

    # 글로벌 연락처 DB (Truecaller) 조회
    truecaller_result = await check_truecaller_osint(international_number)
    if truecaller_result:
        alerts.append({"source": "Truecaller OSINT", **truecaller_result})

    # 텔레그램 가입 여부 조회
    telegram_result = await check_telegram_account(international_number)
    if telegram_result:
        alerts.append({"source": "Telegram (메신저 추적)", **telegram_result})

    # 구글 웹 Dorking 추적
    print(f"[Phone Scanner] 구글 웹 노출 정보 추적 중...")
    if await search_google_exposure(phone_number) or await search_google_exposure(clean_number):
        alerts.append({
            "source": "Google OSINT (웹 노출 추적)",
            "threat_level": "MEDIUM",
            "description": "인터넷 상(게시판, 이력서 등)에 해당 번호가 노출된 흔적이 발견되었습니다."
        })
    else:
        alerts.append({
            "source": "Google OSINT (웹 노출 추적)",
            "threat_level": "LOW",
            "description": "구글 스캔 결과, 웹상에 노출된 흔적이 발견되지 않았습니다. 안전합니다."
        })
        
    print(f"[Phone Scanner] 스캔 완료! (위협 {len(alerts)}건 발견)\n")
    return alerts