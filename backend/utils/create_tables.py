import os
import boto3
from dotenv import load_dotenv

load_dotenv()

dynamodb = boto3.client(
    'dynamodb',
    aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
    aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
    region_name=os.getenv('AWS_DEFAULT_REGION')
)

def create_table(table_name, partition_key, sort_key=None):
    try:
        attribute_definitions = [{"AttributeName": partition_key, "AttributeType": "S"}]
        key_schema = [{"AttributeName": partition_key, "KeyType": "HASH"}]

        if sort_key:
            attribute_definitions.append({"AttributeName": sort_key, "AttributeType": "S"})
            key_schema.append({"AttributeName": sort_key, "KeyType": "RANGE"})

        print(f" [AWS] {table_name} 테이블 생성")
        
        dynamodb.create_table(
            TableName=table_name,
            KeySchema=key_schema,
            AttributeDefinitions=attribute_definitions,
            ProvisionedThroughput={
                'ReadCapacityUnits': 5,
                'WriteCapacityUnits': 5
            }
        )
        print(f"{table_name} 테이블 생성 요청 완료\n")
    except dynamodb.exceptions.ResourceInUseException:
        print(f"{table_name} 테이블이 이미 존재하므로 생략\n")
    except Exception as e:
        print(f"{table_name} 생성 실패 : {e}\n")

if __name__ == "__main__":
    print("SYMSYM 플랫폼 필수 DynamoDB 테이블 생성 시작\n")

    # 1. 사용자 정보 테이블 (익스텐션 설정 값 저장)
    # Partition Key : email (사용자 이메일)
    create_table("symsym-users", "email")

    # 2. 알림 테이블 (크롬 익스텐션 팝업에 뜰 경고장)
    # Partition Key : user_email (알림을 받을 사용자)
    # Sort Key : event_id (어떤 위협 때문에 발생했는지 고유 ID 생성)
    create_table("symsym-alerts", "user_email", "event_id")

    # 3. ASM 자산 취약점 테이블 (Censys, Shodan 스캔 결과 캐싱용)
    # Partition Key : ip (스캔한 서버 IP)
    # Sort Key : last_scan (스캔 시간)
    create_table("symsym-asm-assets", "ip", "last_scan")

    print("모든 테이블 생성 프로세스 완료")