import os
import requests
from dotenv import load_dotenv

load_dotenv()

API_ID = os.getenv("CENSYS_API_ID")
API_SECRET = os.getenv("CENSYS_API_SECRET")


def scan_infrastructure(domain: str):
    url = "https://search.censys.io/api/v2/hosts/search"

    params = {
        "q": f"services.dns.name:{domain}",
        "per_page": 10
    }

    response = requests.get(
        url,
        auth=(API_ID, API_SECRET),   # Basic Authentication
        params=params
    )

    return response
