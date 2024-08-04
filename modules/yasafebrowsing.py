import requests

def ya_check(domain: str) -> bool:
    response = requests.post("https://yandex.ru/safety/check", headers={"content-type": "application/json"}, json={"url": domain})

    return response.json()