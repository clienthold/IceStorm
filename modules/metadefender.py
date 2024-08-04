import requests

class MetaDefender:
    def __init__(self, api_key: str):
        self.headers = {
            "apikey": api_key
        }

    def submit_domain(self, domain: str):
        r = requests.get(f"https://api.metadefender.com/v4/domain/{domain}", headers=self.headers)
        if r.status_code == 200:
            results = r.json()

            self.detected = results["lookup_results"]["detected_by"]
            self.allengines = len(results["lookup_results"]["sources"][0])
        else:
            raise Exception(r.json()["error"]["messages"][0])