import os
import boto3
from dotenv import load_dotenv

load_dotenv()

# AWS DynamoDB 연결
dynamodb = boto3.resource(
    "dynamodb",
    aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
    aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
    region_name=os.getenv("AWS_DEFAULT_REGION")
)


def save_to_dynamodb(table_name: str, item: dict):
    try:
        table = dynamodb.Table(table_name)

        # None 값 제거
        item = {k: v for k, v in item.items() if v is not None}

        table.put_item(Item=item)

        print(f"[AWS DB] {table_name} 테이블에 데이터 저장 완료")

    except Exception as e:
        print(f"[AWS DB 에러] 저장 실패: {e}")
