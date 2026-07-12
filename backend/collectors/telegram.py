import os
import uuid
from datetime import datetime
from dotenv import load_dotenv
from telethon.sync import TelegramClient

from backend.models.threat_event import ThreatEvent
from backend.models.user import User
from backend.services.aws_db import save_to_dynamodb
from backend.services.risk_service import calculate_risk
from backend.services.alert_service import create_alerts
from backend.utils.mapper import (
    threat_event_to_dynamodb_item,
    alert_to_dynamodb_item
)

load_dotenv()

API_ID = int(
    os.getenv("TELEGRAM_API_ID")
    .strip()
    .strip("'")
    .strip('"')
)

API_HASH = (
    os.getenv("TELEGRAM_API_HASH")
    .strip()
    .strip("'")
    .strip('"')
)

THREAT_EVENT_TABLE = "symsym-threat-events"
ALERT_TABLE = "symsym-alerts"

TARGET_CHANNELS = [
    "test99026",
    "FalconFeedsio",
    "vxunderground",
    "thehackersnews"
]

async def scrape_telegram(target: str):
    print(f"[텔레그램] '{target}' 실시간 감시 시작\n")

    client = TelegramClient(
        "symsym_session",
        API_ID,
        API_HASH
    )

    await client.start()

    try:
        # 1. 대상 Telegram 채널 순회
        for channel in TARGET_CHANNELS:

            try:
                # 2. 채널에서 대상 키워드가 포함된 메시지 검색
                messages = await client.get_messages(
                    channel,
                    search=target,
                    limit=5
                )

                # 3. 검색 결과를 ThreatEvent 모델로 변환
                for msg in messages:

                    if not msg.text:
                        continue

                    print(
                        f"[@{channel}] "
                        f"'{target}' 관련 내용 발견"
                    )

                    event = ThreatEvent(
                        source="Telegram",

                        # ThreatEvent 생성 시 고유 ID 생성
                        event_id=str(uuid.uuid4()),

                        email=target,
                        leaked_keyword="N/A",
                        url=f"https://t.me/{channel}/{msg.id}",
                        description=msg.text[:200] + "...",
                        detected_at=datetime.now().strftime(
                            "%Y-%m-%d %H:%M:%S"
                        ),
                        is_confirmed=False
                    )

                    # 4. RiskService를 이용하여 위험도 계산
                    event = calculate_risk([event])[0]

                    # 5. ThreatEvent를 공통 Mapper로 변환 후 DynamoDB 저장
                    event_item = threat_event_to_dynamodb_item(event)

                    save_to_dynamodb(
                        THREAT_EVENT_TABLE,
                        event_item
                    )

                    # 6. ThreatEvent를 기반으로 Alert 생성
                    alerts = create_alerts(
                        User(email=target),
                        [event]
                    )

                    # 7. Alert를 공통 Mapper로 변환 후 DynamoDB 저장
                    for alert in alerts:

                        alert_item = alert_to_dynamodb_item(alert)

                        save_to_dynamodb(
                            ALERT_TABLE,
                            alert_item
                        )

            except Exception as e:
                print(f"[@{channel}] 접근 불가: {e}")

    except Exception as e:
        print(
            f"[오류] Telegram 구동 중 문제가 발생했습니다: {e}"
        )

    finally:
        await client.disconnect()