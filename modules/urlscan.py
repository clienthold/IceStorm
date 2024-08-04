import requests
import json
import time

class DnsError(Exception):
    """DNS Error - standart UrlScan Exception"""
    pass

class UrlScan:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.headers = {
            "API-Key": api_key,
            "Content-Type": "application/json"
        }
    
    def submit_url(self, url: str):
        data = {"url": url, "visibility": "public", "tags": ["Ice Storm"]}
        r = requests.post("https://urlscan.io/api/v1/scan/", headers=self.headers, json=data)
        if r.status_code == 200:
            self.api_results = r.json()["api"]
        elif r.status_code == 400:
            raise DnsError(f"DNS Error: {r.json()['message'].split('-')[1].strip()}")
        else:
            raise Exception(f"[{r.status_code}] {r.text}")

    def get_results(self):
        for _ in range(60):
            r = requests.get(self.api_results)
            if r.status_code == 200:
                break
            
            time.sleep(1)

        result = r.json()

        try:
            self.title = result["page"]["title"]
        except KeyError:
            self.title = None
        
        try:
            self.screenshot = result["task"]["screenshotURL"]
        except KeyError:
            self.title = None

        self.brands = result["verdicts"]["overall"]["brands"]
        self.clasification = result["verdicts"]["overall"]["tags"]
        self.malicious = result["verdicts"]["overall"]["malicious"]