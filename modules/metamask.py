import requests

def metamask_list(domain: str) -> bool:
    r = requests.get("https://raw.githubusercontent.com/MetaMask/eth-phishing-detect/refs/heads/main/src/config.json")

    return domain in r.json()["blacklist"]