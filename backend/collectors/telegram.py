import os
import asyncio
from dotenv import load_dotenv
from telethon.sync import TelegramClient
from backend.models.threat_event import ThreatEvent

load_dotenv()

API_ID = int(os.getenv("TELEGRAM_API_ID").strip().strip("'").strip('"'))
API_HASH = os.getenv("TELEGRAM_API_HASH").strip().strip("'").strip('"')

# 감시할 채널 리스트
TARGET_CHANNELS = [
    'test99026', 
    'telegram', 
    'bleepingcomputer'
]

async def scrape_telegram():
    print("텔레그램 다중 채널 수집 시작...\n")
    client = TelegramClient('symsym_session', API_ID, API_HASH)
    await client.start()
    
    try:
        for channel in TARGET_CHANNELS:
            print(f"[@{channel}] 채널 탐색 중...")
            
            try:
                # 각 채널당 최신 메시지 10개씩 가져오기
                messages = await client.get_messages(channel, limit=10)
                
                for msg in messages:
                    if msg.text and 'duksung' in msg.text.lower():
                        print(f"[@{channel}]에서 'duksung' 위협 키워드 감지")
                        
                        event = ThreatEvent(
                            source='Telegram',
                            leaked_keyword='duksung',
                            channel_name=channel,
                            message_id=str(msg.id),
                            url=f"https://t.me/{channel}/{msg.id}",
                            threat_level='HIGH',
                            description=msg.text,
                            is_confirmed=False
                        )
                        print(event)
                        
            except Exception as e:
                print(f"[@{channel}] 접근 불가 또는 에러: {e}")
            
            print(f"대기 중... (서버 속도 제한 방지)\n")
            await asyncio.sleep(5) 
            
    except Exception as e:
        print(f"전체 수집기 구동 에러: {e}")
    finally:
        await client.disconnect()
        print("이번 주기 탐색 완료")

if __name__ == "__main__":
    asyncio.run(scrape_telegram())