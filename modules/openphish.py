import requests

def openphish_list(domain: str) -> bool:
    r = requests.get("https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt")

    return domain in r.text