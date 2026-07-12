from backend.collectors.shodan import get_host as shodan_get_host
from backend.collectors.censys import get_host as censys_get_host

class EventService:
    
    def collect_asm(self, ip):
        
        assets = []

        shodan_asset = shodan_get_host(ip)
        if shodan_asset:
            assets.append(shodan_asset)

        censys_asset = censys_get_host(ip)
        if censys_asset:
            assets.append(censys_asset)

        return assets
    
if __name__ == "__main__":

    service = EventService()

    assets = service.collect_asm("8.8.8.8")

    for asset in assets:
        print(asset)
