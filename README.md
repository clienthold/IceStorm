# 🌠 Ice Storm ![Flask](https://img.shields.io/badge/flask-%23000.svg?style=for-the-badge&logo=flask&logoColor=white)
**Toolkit** for blocking phishing domains

## ⚙️ Features

- Integrations with [UrlScan](https://urlscan.io/), [Google Safe Browsing](https://safebrowsing.google.com/), [VirusTotal](https://www.virustotal.com/), [MetaDefender](https://metadefender.opswat.com/), [Yandex Safe Browsing](https://yandex.ru/safety/), [Wayback Machine](https://web.archive.org/), [ThreatMiner](https://www.threatminer.org/), [NetCraft](https://www.netcraft.com/)
- Automatic generation of emails for domain registrars
- Generation of csv reports based on all information

## 📥 Installation
```sh
git clone https://github.com/clienthold/IceStorm.git
cd IceStorm
pip3 install -r requirements.txt
```

Insert the necessary **API keys** into the ```config.py``` configuration file

```python
# GOOGLE SAFE BROWSING API KEY
# https://developers.google.com/safe-browsing/v4/get-started
SB_API = ""

# VIRUSTOTAL API KEY
VT_API = ""

# URLSCAN API KEY
US_API = ""

# METADEFENDER API KEY
MD_API = ""
```

Run ```main.py```
```sh
python3 main.py
```

## 🌌 Screenshots
![Index Page](https://github.com/user-attachments/assets/892312c2-cba5-45bc-8d91-322ef108f07e)

![Search Page](https://github.com/user-attachments/assets/65024524-5091-4b33-9c1c-5f4d9a138bea)
