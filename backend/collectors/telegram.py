import os
import uuid
import asyncio
import dataclasses
from datetime import datetime
from dotenv import load_dotenv
from telethon.sync import TelegramClient

from backend.models.threat_event import ThreatEvent
from backend.services.aws_db import save_to_dynamodb
from backend.utils.mapper import threat_event_to_dynamodb_item
from backend.services.risk_service import calculate_risk
from backend.models.user import User
from backend.services.alert_service import create_alerts

load_dotenv()

API_ID = int(os.getenv("TELEGRAM_API_ID").strip().strip("'").strip('"'))
API_HASH = os.getenv("TELEGRAM_API_HASH").strip().strip("'").strip('"')

TARGET_CHANNELS = ['test99026', 'FalconFeedsio', 'vxunderground', 'thehackersnews']

async def scrape_telegram(target: str):
    print(f"[텔레그램] '{target}' 실시간 감시 시작\n")
    client = TelegramClient('symsym_session', API_ID, API_HASH)
    await client.start()
    
    try:
        for channel in TARGET_CHANNELS:
            try:
                # 텔레그램 자체 검색 기능(search)을 활용해 타겟 이메일이 있는 글만 5개 가져옴
                messages = await client.get_messages(channel, search=target, limit=5)
                for msg in messages:
                    if not msg.text: continue
                    
                    print(f"[@{channel}] '{target}' 관련 내용 발견")
                    event = ThreatEvent(
                        source='Telegram', email=target, leaked_keyword="N/A",
                        url=f"https://t.me/{channel}/{msg.id}", description=msg.text[:200] + "...", 
                        detected_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"), is_confirmed=False
                    )
                    
                    event = calculate_risk([event])[0]
                    if not hasattr(event, 'event_id') or not event.event_id:
                        event.event_id = str(uuid.uuid4())
                    
                    item_to_save = threat_event_to_dynamodb_item(event)
                    save_to_dynamodb('symsym-threat-events', item_to_save)
                    
                    alerts = create_alerts(User(email=target), [event])
                    for alert in alerts:
                        alert_item = dataclasses.asdict(alert) if hasattr(alert, '__dataclass_fields__') else alert.dict()
                        if 'sent_at' in alert_item and not isinstance(alert_item['sent_at'], str):
                            alert_item['sent_at'] = alert_item['sent_at'].strftime("%Y-%m-%d %H:%M:%S")
                        save_to_dynamodb('symsym-alerts', alert_item)
                        
            except Exception as e:
                print(f"[@{channel}] 접근 불가 : {e}")
    except Exception as e:
        print(f"텔레그램 구동 에러 : {e}")
    finally:
        await client.disconnect()