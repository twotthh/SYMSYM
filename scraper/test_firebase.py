import os
import firebase_admin
from firebase_admin import credentials
from firebase_admin import firestore
from datetime import datetime

KEY_PATH = os.path.join(os.path.dirname(__file__), 'firebase-key.json')
cred = credentials.Certificate(KEY_PATH)

firebase_admin.initialize_app(cred)
db = firestore.client()

def test_push():
    print("파이어베이스에 테스트 데이터 전송 중...")
    
    mock_data = {
        "source": "Python_Test_Script",
        "leaked_keyword": "test_user@duksung.ac.kr",
        "threat_level": "Medium",
        "created_at": datetime.now()
    }
    
    doc_ref = db.collection('threat_intel').add(mock_data)
    print("✅ 전송 완료!")

if __name__ == '__main__':
    test_push()