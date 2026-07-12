import re

def detect_leak(raw_text, target_domain="duksung.ac.kr"):
    # 1. 원본 텍스트에 타겟 도메인이 없으면 바로 종료
    if target_domain not in raw_text:
        return None

    # 2. 이메일:비밀번호 형태의 패턴(콤보 리스트)을 찾는 정규표현식
    combo_pattern = rf"[\w\.-]+@{re.escape(target_domain)}:[\w!@#$%^&*]+"
    leaked_data = re.findall(combo_pattern, raw_text)

    # 3. 오탐지 필터링
    valid_leaks = []
    for data in leaked_data:
        if "test" not in data.lower() and "example" not in data.lower():
            valid_leaks.append(data)

    # 유출이 발견되면 결과 반환
    if valid_leaks:
        return {"type": "Combo List", "data": valid_leaks}
    
    return None

# 테스트용 더미 데이터
telegram_message = """
오늘 긁어온 DB 팝니다.
hello@gmail.com:1234
student@duksung.ac.kr:mysecret!@
test@duksung.ac.kr:password
"""

result = detect_leak(telegram_message)
print(result) 