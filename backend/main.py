import os
import boto3
import hashlib
import asyncio
import re

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from boto3.dynamodb.conditions import Key
from dotenv import load_dotenv
from pydantic import BaseModel
from boto3.dynamodb.conditions import Key, Attr

from backend.collectors.hibp import search_breach
from backend.collectors.google import search_google_leaks
from backend.collectors.github import search_github_leaks
from backend.collectors.telegram import scrape_telegram
from backend.collectors.hackertarget import scan_subdomains
from backend.collectors.shodan import scan_multiple_ips
from backend.collectors.phone import scan_phone_number

load_dotenv()

app = FastAPI(
    title="SYMSYM 알림 API 서버",
    description="Chrome Extension과 AWS DynamoDB를 연결하는 백엔드 서버"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

dynamodb = boto3.resource(
    'dynamodb',
    aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
    aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
    region_name=os.getenv('AWS_DEFAULT_REGION')
)

EMAIL_REGEX = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
DOMAIN_REGEX = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
PHONE_REGEX = r'^01[016789]-?([0-9]{3,4})-?([0-9]{4})$'

# 1. 서버 상태 확인 API
@app.get("/")
def read_root():
    return {"status": "ok", "message": "SYMSYM API 서버 정상 작동"}

# 2. 실시간 위협 데이터 조회 API 
@app.get("/api/alerts/{target}")
async def get_user_alerts(target: str):  
    print(f"\n[모니터링 시작] 클라이언트에서 '{target}' 조회를 요청했습니다.")
    
    # 전화번호 모의 결과를 임시로 담을 리스트 추가!
    phone_alerts = [] 
    
    # 입력값 분류 및 라우팅
    if re.match(EMAIL_REGEX, target):
        print("[분류] 입력값이 '이메일'입니다. 기존 OSINT 스캔을 시작합니다.")
        search_breach(target)
        search_google_leaks(target)
        search_github_leaks(target)
        await scrape_telegram(target)

    elif re.match(PHONE_REGEX, target):
        # 👇 TODO를 지우고 전화번호 모듈 실행 코드 추가
        print("[분류] 입력값이 '전화번호'입니다. 전화번호 전용 스캔을 시작합니다.")
        phone_alerts = await scan_phone_number(target)

    elif re.match(DOMAIN_REGEX, target):
        print("[분류] 입력값이 '도메인'입니다. 연쇄 ASM 파이프라인을 가동합니다.")
        # Step 1 : HackerTarget을 통해 서브도메인 및 IP 추출
        extracted_ips = scan_subdomains(target)
        # Step 2 : 추출된 IP 리스트를 Shodan으로 넘겨서 취약점 연속 스캔
        if extracted_ips:
            scan_multiple_ips(extracted_ips)

    else:
        print("[분류] '일반 키워드'입니다. 딥웹/다크웹 키워드 모니터링만 수행합니다.")
        search_google_leaks(target)
        search_github_leaks(target)
        await scrape_telegram(target)

    print(f"\n[{target}] 봇 수집 및 적재 완료 -> DB 결과 가져옴\n")

    try:
        alerts_list = []
        # 1. 기존 OSINT 유출 데이터 조회
        table = dynamodb.Table('symsym-threat-events-v2')
        response = table.query(
            KeyConditionExpression=Key('email').eq(target)
        )
        
        for item in response.get('Items', []):
            alerts_list.append({
                "source": item.get("source", "Unknown"),
                "threat_level": item.get("threat_level", "HIGH"),
                "description": item.get("description", "유출 상세 정보 없음")
            })

        # 2. ASM 인프라 취약점 데이터 조회 
        if re.match(DOMAIN_REGEX, target):
            asm_table = dynamodb.Table('symsym-asm-assets')
            asm_response = asm_table.scan(
                FilterExpression=Attr('domain').contains(target)
            )
            for item in asm_response.get('Items', []):
                vulns = item.get('vulnerabilities', [])
                if vulns:
                    alerts_list.append({
                        "source": "Shodan ASM",
                        "threat_level": "CRITICAL", 
                        "description": f"[{item.get('ip')}] 서버 인프라에서 {len(vulns)}개의 치명적 취약점(CVE) 발견!"
                    })
        
        # 👇 3. 전화번호 검색이었다면, 임시 리스트에 담아둔 결과를 최종 응답에 합치기
        if phone_alerts:
            alerts_list.extend(phone_alerts)

        return {
            "email": target, 
            "message": "모니터링 완료",
            "alerts": alerts_list
        }
        
    except Exception as e:
        print(f"[API 서버 에러] DynamoDB 조회 실패 : {e}")
        raise HTTPException(status_code=500, detail=f"Internal Server Error: {e}")
    
# 클라이언트에서 보낼 데이터 규격 정의
class UserAuth(BaseModel):
    email: str
    password: str

# 비밀번호 암호화 함수
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

# 1. 회원가입 API
@app.post("/api/register")
def register_user(user: UserAuth):
    table = dynamodb.Table('symsym-users')
    
    # 이미 가입된 이메일인지 확인
    response = table.get_item(Key={'email': user.email})
    if 'Item' in response:
        raise HTTPException(status_code=400, detail="이미 가입된 이메일입니다.")
    
    # 새 회원 DB에 저장 (비밀번호는 암호화)
    try:
        table.put_item(
            Item={
                'email': user.email,
                'password_hash': hash_password(user.password)
            }
        )
        return {"message": "회원가입이 완료되었습니다!"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"DB 저장 실패 : {e}")

# 2. 로그인 API
@app.post("/api/login")
def login_user(user: UserAuth):
    table = dynamodb.Table('symsym-users')
    
    # DB에서 이메일 검색
    response = table.get_item(Key={'email': user.email})
    db_user = response.get('Item')
    
    if not db_user:
        raise HTTPException(status_code=400, detail="가입되지 않은 이메일입니다.")
    
    # 비밀번호 검증
    if db_user['password_hash'] != hash_password(user.password):
        raise HTTPException(status_code=400, detail="비밀번호가 일치하지 않습니다.")
    
    # 로그인 성공 시 사용자 이메일 반환
    return {"message": "로그인 성공", "email": user.email}