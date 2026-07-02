RISK_SCORE = {
    "EMAIL": 10,
    "PASSWORD": 40,
    "PHONE": 20,
    "USERNAME": 10,
    "API_KEY": 60,
    "PRIVATE_KEY": 80,
    "TOKEN": 70,
}

RISK_LEVEL = {
    "LOW": (0, 29),
    "MEDIUM": (30, 59),
    "HIGH": (60, 89),
    "CRITICAL": (90, 100)
}