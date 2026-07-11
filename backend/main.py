import os
import boto3
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from boto3.dynamodb.conditions import Key
from dotenv import load_dotenv

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
def get_user_alerts(email: str):
    # 입력된 도메인/이메일을 파티션 키로 하여 symsym-threat-events 테이블에서 실시간 유출 내역을 쿼리
    try:
        # 1. 대상 테이블 호출
        table = dynamodb.Table('symsym-threat-events')
        
        # 2. DynamoDB Query 실행 (email이 일치하는 데이터 가져오기)
        response = table.query(
            KeyConditionExpression=Key('email').eq(email)
        )
        
        # 3. 데이터 추출
        items = response.get('Items', [])
        
        # 4. 프론트엔드가 요구하는 규격으로 가공하여 전달
        alerts_list = []
        for item in items:
            alerts_list.append({
                "source": item.get("source", "Unknown"),
                "threat_level": item.get("threat_level", "HIGH"),
                "description": item.get("description", "유출 상세 정보 없음")
            })
            
        return {
            "email": email,
            "message": f"AWS에서 {email}에 대한 위협 데이터를 실시간으로 조회 완료",
            "alerts": alerts_list
        }
        
    except Exception as e:
        print(f"[API 서버 에러] DynamoDB 조회 실패 : {e}")
        raise HTTPException(status_code=500, detail=f"Internal Server Error: {e}")