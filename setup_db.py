import os
import boto3
from dotenv import load_dotenv

load_dotenv()

# AWS DynamoDB 연결
dynamodb = boto3.resource(
    'dynamodb',
    aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
    aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
    region_name=os.getenv('AWS_DEFAULT_REGION')
)

def create_threat_events_table():
    table_name = 'symsym-threat-events-v2'
    
    try:
        print(f"[{table_name}] 테이블 생성을 AWS에 요청")
        
        table = dynamodb.create_table(
            TableName=table_name,
            KeySchema=[
                # 파티션 키 (Partition Key) : 데이터를 찾는 가장 큰 기준점
                {'AttributeName': 'email', 'KeyType': 'HASH'},  
                # 정렬 키 (Sort Key) : 같은 기준점 안에서 정렬하는 기준
                {'AttributeName': 'event_id', 'KeyType': 'RANGE'} 
            ],
            AttributeDefinitions=[
                {'AttributeName': 'email', 'AttributeType': 'S'},     
                {'AttributeName': 'event_id', 'AttributeType': 'S'} 
            ],
            # 온디맨드 방식
            BillingMode='PAY_PER_REQUEST' 
        )
    
        table.meta.client.get_waiter('table_exists').wait(TableName=table_name)
        print(f"[{table_name}] 테이블 생성 완료")
        
    except Exception as e:
        print(f"테이블 생성 실패 (이미 존재하는 테이블일 가능성 있음): {e}")

if __name__ == '__main__':
    create_threat_events_table()