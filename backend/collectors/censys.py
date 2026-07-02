import os
import requests
from dotenv import load_dotenv

load_dotenv()

API_TOKEN = os.getenv("CENSYS_API_TOKEN")

HEADERS = {
    "Authorization": f"Bearer {API_TOKEN}",
    "Accept": "application/json"
}


def get_host(host_id: str):

    url = f"https://api.platform.censys.io/v3/global/asset/host/{host_id}"

    response = requests.get(
        url,
        headers=HEADERS
    )

    return response


if __name__ == "__main__":

    response = get_host("8.8.8.8")

    print("Status:", response.status_code)

    if response.status_code == 200:
        print(response.json())
    else:
        print(response.text)
