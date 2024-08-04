# 🌠 Ice Storm
**Toolkit** for blocking phishing domains

## 🧩 Features

- Integrations with UrlScan, Google Safe Browsing, VirusTotal, MetaDefender, Yandex Safe Browsing, Wayback Machine, ThreatMiner, NetCraft
- Automatic generation of emails for domain registrars
- Generation of csv reports based on all information

## 📥 Installation
1. Download and unpack the archive then go to the folder and install the necessary libraries
```
pip install -r requirements.txt
```

2. Insert the necessary **API keys** into the ```config.py``` configuration file

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

3. Run ```main.py```. After running the script, you will have a window open in your browser.

## 🌌 Screenshots
![Index Page](https://github.com/user-attachments/assets/892312c2-cba5-45bc-8d91-322ef108f07e)

![Search Page](https://github.com/user-attachments/assets/65024524-5091-4b33-9c1c-5f4d9a138bea)
