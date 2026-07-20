import os
import boto3
import hashlib
import asyncio
import re
import uuid  

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from boto3.dynamodb.conditions import Key, Attr
from dotenv import load_dotenv
from pydantic import BaseModel

from backend.collectors.hibp import search_breach
from backend.collectors.google import search_google_leaks
from backend.collectors.github import search_github_leaks
from backend.collectors.telegram import scrape_telegram
from backend.collectors.hackertarget import scan_subdomains
from backend.collectors.phone import scan_phone_number

from backend.collectors.shodan import scan_multiple_ips as shodan_scan
from backend.collectors.censys import scan_multiple_ips as censys_scan

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
    
    # 입력값 분류 및 라우팅
    if re.match(EMAIL_REGEX, target):
        print("[분류] 입력값이 '이메일'입니다. OSINT 스캔을 시작합니다.")
        search_breach(target)
        search_google_leaks(target)
        search_github_leaks(target)
        await scrape_telegram(target)

    elif re.match(PHONE_REGEX, target):
        print("[분류] 입력값이 '전화번호'입니다. DB 캐시 확인 및 스캔을 시작합니다.")
        table = dynamodb.Table('symsym-threat-events-v2')
        
        # 1. DB에 결과가 이미 있는지 먼저 확인 
        cache_response = table.query(KeyConditionExpression=Key('email').eq(target))
        
        if cache_response.get('Items'):
            print(f"[{target}] 이미 스캔된 이력이 DB에 있습니다. API 호출을 생략합니다.")
        else:
            print(f"[{target}] 신규 번호입니다. 실시간 모듈 스캔을 가동합니다 (약 3~5초 소요).")
            phone_alerts = await scan_phone_number(target)
            
            # 2. 실시간 스캔 완료 후 결과를 DB에 영구 적재
            for alert in phone_alerts:
                try:
                    table.put_item(
                        Item={
                            'email': target,  
                            'id': uuid.uuid4().hex,  
                            'source': alert.get("source", "Unknown"),
                            'threat_level': alert.get("threat_level", "LOW"),
                            'description': alert.get("description", "유출 상세 정보 없음")
                        }
                    )
                except Exception as e:
                    print(f"[{target}] DB 저장 실패: {e}")
            print(f"[{target}] DB 적재 완료")

    elif re.match(DOMAIN_REGEX, target):
        # Shodan과 Censys를 모두 호출
        print("[분류] 입력값이 '도메인'입니다. ASM 파이프라인(Shodan + Censys)을 가동합니다.")
        extracted_ips = scan_subdomains(target)
        if extracted_ips:
            shodan_scan(extracted_ips)  # Shodan 스캔 진행
            censys_scan(extracted_ips)  # Censys 스캔 진행 

    else:
        print("[분류] '일반 키워드'입니다. 딥웹/다크웹 키워드 모니터링을 수행합니다.")
        search_google_leaks(target)
        search_github_leaks(target)
        await scrape_telegram(target)

    print(f"\n[{target}] 봇 수집 및 적재 완료 -> DB 결과 가져옴\n")

    try:
    alerts_list = []

    # 3. 전화번호든 이메일이든 DB에서 한 번에 가져옴
    table = dynamodb.Table('symsym-threat-events-v2')
    response = table.query(
        KeyConditionExpression=Key('email').eq(target)
    )

    for item in response.get('Items', []):

        alerts_list.append({
            "source": item.get("source", "Unknown"),
            "threat_level": item.get("threat_level", "HIGH"),

            # 추가
            "risk_score": item.get("risk_score", 0),
            "risk_reason": item.get("risk_reason", []),

            "description": item.get("description", "유출 상세 정보 없음")
        })

    # ASM 인프라 취약점 데이터 조회
    if re.match(DOMAIN_REGEX, target):
        asm_table = dynamodb.Table('symsym-asm-assets')

        asm_response = asm_table.scan(
            FilterExpression=Attr('domain').contains(target)
        )

        for item in asm_response.get('Items', []):

            vulns = item.get('vulnerabilities', [])

            if vulns:

                alerts_list.append({
                    "source": f"{item.get('source', 'ASM')} Infrastructure",
                    "threat_level": "CRITICAL",

                    # 추가
                    "risk_score": 100,
                    "risk_reason": [
                        "ASM 취약점 탐지",
                        "치명적 CVE 존재"
                    ],

                    "description": f"[{item.get('ip')}] 서버 인프라에서 {len(vulns)}개의 치명적 취약점(CVE) 발견!"
                })

    return {
        "email": target,
        "message": "모니터링 완료",
        "alerts": alerts_list
    }

except Exception as e:
    print(f"[API 서버 에러] DynamoDB 조회 실패 : {e}")
    raise HTTPException(status_code=500, detail=f"Internal Server Error: {e}")
