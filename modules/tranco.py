import requests

def domain_raiting(domain: str) -> int:
    r = requests.get(f"https://tranco-list.eu/api/ranks/domain/{domain}")
    if r.status_code == 200:
        if len(r.json()["ranks"]) > 0:
            rank = r.json()["ranks"][-1:][0]["rank"]
            return rank
        else:
            return 0
    else:
        raise Exception(r.text)