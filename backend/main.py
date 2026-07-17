import os
import boto3
import hashlib
import asyncio

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from boto3.dynamodb.conditions import Key
from dotenv import load_dotenv
from pydantic import BaseModel

from backend.collectors.hibp import search_breach
from backend.collectors.google import search_google_leaks
from backend.collectors.github import search_github_leaks
from backend.collectors.telegram import scrape_telegram

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

# 1. 서버 상태 확인 API
@app.get("/")
def read_root():
    return {"status": "ok", "message": "SYMSYM API 서버 정상 작동"}

# 2. 실시간 위협 데이터 조회 API 
@app.get("/api/alerts/{email}")
async def get_user_alerts(email: str):  
    print(f"\n[모니터링 시작] 클라이언트에서 '{email}' 조회를 요청했습니다.")
    
    print("1. HIBP, Google, GitHub 스캔 중...")
    search_breach(email)
    search_google_leaks(email)
    search_github_leaks(email)
    
    print("2. 텔레그램 채널 스캔 중...")
    await scrape_telegram(email)  # 텔레그램은 비동기이므로 await 대기

    print(f"[{email}] 봇 수집 및 적재 완료 -> DB 결과 가져옴\n")

    try:
        table = dynamodb.Table('symsym-threat-events-v2')
        response = table.query(
            KeyConditionExpression=Key('email').eq(email)
        )
        items = response.get('Items', [])
        
        alerts_list = []
        for item in items:
            alerts_list.append({
                "source": item.get("source", "Unknown"),
                "threat_level": item.get("threat_level", "HIGH"),
                "description": item.get("description", "유출 상세 정보 없음")
            })
            
        return {
            "email": email,
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