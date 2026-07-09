"""
위험도 점수 규칙
"""

# 노출 정보 점수
RISK_SCORE = {

    # 개인정보
    "EMAIL": 10,
    "PHONE": 20,
    "USERNAME": 10,

    # 민감 정보
    "PASSWORD": 40,
    "API_KEY": 60,
    "PRIVATE_KEY": 80,
    "TOKEN": 70,

    # 출처
    "HIBP": 30,
    "GITHUB": 20,
    "TELEGRAM": 15,

    # ASM
    "FTP": 35,
    "SSH": 20,
    "RDP": 40,

    # 추가 가중치
    "CONFIRMED": 20,
    "MULTI_SOURCE": 30
}


# 최종 위험도
RISK_LEVEL = {
    "LOW": (0, 29),
    "MEDIUM": (30, 59),
    "HIGH": (60, 89),
    "CRITICAL": (90, 999)
}
