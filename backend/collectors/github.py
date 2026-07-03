"""
GitHub API Collector
"""

import os
import requests
from dotenv import load_dotenv

load_dotenv()

TOKEN = os.getenv("GITHUB_API_TOKEN")


def get_my_info():
    url = "https://api.github.com/user"

    headers = {
        "Authorization": f"Bearer {TOKEN}",
        "Accept": "application/vnd.github+json"
    }

    response = requests.get(
        url,
        headers=headers,
        timeout=10
    )

    return response


if __name__ == "__main__":

    response = get_my_info()

    print("Status:", response.status_code)

    if response.status_code == 200:
        print(response.json())
    else:
        print(response.text)
