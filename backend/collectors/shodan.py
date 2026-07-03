import os
import requests
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("SHODAN_API_KEY")

def get_host(ip: str):
    """
    특정 IP의 정보를 조회
    """

    url = f"https://api.shodan.io/shodan/host/{ip}"

    params = {
        "key": API_KEY
    }

    response = requests.get(
    url,
    params=params,
    timeout=10
)

    return response

if __name__ == "__main__":
    
    response = get_host("8.8.8.8")

    print("Status:", response.status_code)

    if response.status_code == 200:
        print(response.json())
    else:
        print(response.text)
