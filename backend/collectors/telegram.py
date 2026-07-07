import os
import asyncio
from datetime import datetime
from dotenv import load_dotenv
from telethon.sync import TelegramClient

from backend.models.threat_event import ThreatEvent
from backend.services.aws_db import save_to_dynamodb

load_dotenv()

API_ID = int(os.getenv("TELEGRAM_API_ID").strip().strip("'").strip('"'))
API_HASH = os.getenv("TELEGRAM_API_HASH").strip().strip("'").strip('"')

TARGET_CHANNELS = [
    'test99026',           # 내 테스트 채널 
    'FalconFeedsio',       # 해킹, 랜섬웨어 유출 알림 전문 채널
    'vxunderground',       # 전 세계 최대 악성코드/해킹 관련 정보 공유 채널
    'thehackersnews',        # 글로벌 보안 뉴스 채널
    'bleepingcomputer'     # 글로벌 보안 뉴스 채널
]

TARGET_KEYWORDS = ["test@duksung.ac.kr", "myemail@gmail.com", "duksung.ac.kr"]

async def scrape_telegram():
    print("텔레그램 다크웹/해킹 채널 감시 및 AWS 적재 시작\n")
    client = TelegramClient('symsym_session', API_ID, API_HASH)
    await client.start()
    
    try:
        for channel in TARGET_CHANNELS:
            print(f"[@{channel}] 채널 탐색 중")
            
            try:
                # 각 채널당 최신 메시지 15개씩 가져오기
                messages = await client.get_messages(channel, limit=15)
                
                for msg in messages:
                    if not msg.text:
                        continue
                        
                    msg_text_lower = msg.text.lower()
                    
                    # 타겟 키워드가 메시지에 포함되어 있는지 확인
                    for keyword in TARGET_KEYWORDS:
                        if keyword.lower() in msg_text_lower:
                            print(f"[@{channel}]에서 '{keyword}' 관련 유출 의심 데이터 감지")
                            
                            detected_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                            url = f"https://t.me/{channel}/{msg.id}"
                            
                            # 1. 파이썬 규격
                            event = ThreatEvent(
                                source='Telegram',
                                email=keyword, 
                                url=url,
                                threat_level='CRITICAL',
                                description=msg.text[:200] + "...", 
                                detected_at=detected_at,
                                is_confirmed=False
                            )
                            
                            # 2. AWS DynamoDB 규격
                            item_to_save = {
                                "event_id": f"TG-{channel}-{msg.id}",
                                "email": keyword,            # 파티션 키
                                "detected_at": detected_at,  # 정렬 키
                                "source": "Telegram",
                                "threat_level": "CRITICAL",
                                "url": url,
                                "description": f"[@{channel}] {msg.text[:150]}..."
                            }
                            
                            save_to_dynamodb('symsym-threat-events', item_to_save)
                            
            except Exception as e:
                print(f"[@{channel}] 접근 불가 (채널이 삭제되었거나 비공개): {e}")
            
            print(f"대기 중 (텔레그램 서버 속도 제한 방지)\n")
            await asyncio.sleep(3) 
            
    except Exception as e:
        print(f"전체 수집기 구동 에러: {e}")
    finally:
        await client.disconnect()
        print("이번 사이클 텔레그램 탐색 및 AWS 적재 완료")

if __name__ == "__main__":
    asyncio.run(scrape_telegram())