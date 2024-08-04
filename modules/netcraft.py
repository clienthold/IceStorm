import requests

def netcraft_submit(url: str):
    data = {
    "email": "email@example.com",
    "urls": [
        {
            "url": url
        }
    ]
}

    r = requests.post("https://report.netcraft.com/api/v3/report/urls", json=data)
    if r.status_code == 200:
        return r.json()["uuid"]
    if r.status_code == 400:
        raise ValueError(r.json()["details"][0]["message"])
    else:
        raise Exception(r.text)
