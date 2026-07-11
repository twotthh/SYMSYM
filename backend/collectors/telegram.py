import os
import asyncio
from datetime import datetime
from dotenv import load_dotenv
from telethon.sync import TelegramClient

from backend.models.threat_event import ThreatEvent
from backend.services.aws_db import save_to_dynamodb
from backend.utils.mapper import threat_event_to_dynamodb_item

load_dotenv()

API_ID = int(os.getenv("TELEGRAM_API_ID").strip().strip("'").strip('"'))
API_HASH = os.getenv("TELEGRAM_API_HASH").strip().strip("'").strip('"')

TARGET_CHANNELS = [
    'test99026',           
    'FalconFeedsio',       
    'vxunderground',       
    'thehackersnews',        
    'bleepingcomputer'     
]

# B2B 기업 타겟 도메인 및 키워드 추가
TARGET_DOMAINS = ["samsung.com", "ahnlab.com", "go.kr", "duksung.ac.kr"]
THREAT_KEYWORDS = ["db dump", "internal source", "confidential", "cv", "leak", "password"]

async def scrape_telegram():
    print("텔레그램 - 기업 기밀 유출 감시 및 AWS 적재 시작\n")
    client = TelegramClient('symsym_session', API_ID, API_HASH)
    await client.start()
    
    try:
        for channel in TARGET_CHANNELS:
            print(f"[@{channel}] 채널 탐색 중")
            
            try:
                messages = await client.get_messages(channel, limit=15)
                
                for msg in messages:
                    if not msg.text:
                        continue
                        
                    msg_text_lower = msg.text.lower()
                    
                    # 도메인과 위협 키워드가 모두 포함된 메시지만 추출
                    for domain in TARGET_DOMAINS:
                        if domain in msg_text_lower:
                            for keyword in THREAT_KEYWORDS:
                                if keyword in msg_text_lower:
                                    print(f"[@{channel}] '{domain}' 관련 '{keyword}' 유출 정황 감지!")
                                    
                                    detected_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                    url = f"https://t.me/{channel}/{msg.id}"
                                    
                                    event = ThreatEvent(
                                        source='Telegram',
                                        email=domain,          # 타겟 도메인을 기준으로 기록
                                        leaked_keyword=keyword,
                                        url=url,
                                        description=msg.text[:200] + "...", 
                                        detected_at=detected_at,
                                        is_confirmed=False
                                    )
                                    
                                    item_to_save = threat_event_to_dynamodb_item(event)
                                    save_to_dynamodb('symsym-threat-events', item_to_save)
                                    
                                    # 하나의 메시지에서 같은 도메인  중복 저장 방지
                                    break 
                                    
            except Exception as e:
                print(f"[@{channel}] 접근 불가: {e}")
            
            await asyncio.sleep(3) 
            
    except Exception as e:
        print(f"전체 collector 구동 에러: {e}")
    finally:
        await client.disconnect()
        print("이번 사이클 텔레그램 탐색 및 AWS 적재 완료")

if __name__ == "__main__":
    asyncio.run(scrape_telegram())