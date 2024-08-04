from urllib.parse import urlparse
from tld import get_tld
import whois
import pysafebrowsing
from pysafebrowsing.api import SafeBrowsingWeirdError
import virustotal_python
import threatminer
import waybackpy
from base64 import urlsafe_b64encode
from modules.pycrtsh import Crtsh
from modules.urlscan import UrlScan, DnsError
from modules.metadefender import MetaDefender
from modules.yasafebrowsing import ya_check
from modules.tranco import domain_raiting
from modules.netcraft import netcraft_submit
from config import *
import time

class report_api:
    def __init__(self, url: str, is_domain=False) -> None:
        self.url = url
        self.domain = urlparse(url).netloc.replace("www.", "")
        self.is_domain = is_domain
        self.information = []
        self.report_content = {}

    def whois(self) -> None:
        self.information.append(f"Domain: {self.domain}")

        try:
            whois_data = whois.whois(self.domain)
        except whois.parser.PywhoisError:
            abort(503, "The domain isn't found in WhoIs")

        if not len(self.domain.split(".")) > 2:
            try:
                self.information.append(f"Registrar: {whois_data['registrar']}")
            except KeyError:
                self.information.append(f"Registrar: {whois_data['registrant_name']}")
            
        certapi = Crtsh()
        certs = certapi.search(self.domain)
        if isinstance(certs, list) and len(certs) > 0:
            details = certapi.get(certs[0]["id"], type="id")["issuer"]["organizationName"]
            self.information.append(f"SSL: {details}")

        if isinstance(whois_data["creation_date"], list) and whois_data['creation_date'][0] is not None:
            self.information.append(f"Creation Date: {whois_data['creation_date'][0]}")
        elif isinstance(whois_data["creation_date"], str):
            self.information.append(f"Creation Date: {whois_data['creation_date']}")
        
        rank = domain_raiting(self.domain)
        self.information.append(f"Rank: {rank}")

        if (("email" in whois_data) and (whois_data["email"] is None)) or (("emails" in whois_data) and (whois_data["emails"] is None)) and len(self.domain.split(".")) > 2:
            converted_domain = get_tld(self.url, as_object=True)
            new_whois = whois.whois(f"{converted_domain.domain}.{converted_domain.tld}")
            if "emails" in new_whois:
                emails = new_whois.get("emails", []) if isinstance(new_whois["emails"], list) else [new_whois["emails"]]
                valid_emails = [email for email in emails if email is not None]
                self.information.extend([f"{email}|reportmail" for email in valid_emails])
            elif "email" in new_whois:
                emails = new_whois.get("email", []) if isinstance(new_whois["email"], list) else [new_whois["email"]]
                valid_emails = [email for email in emails if email is not None]
                self.information.extend([f"{email}|reportmail" for email in valid_emails])

        elif "emails" in whois_data:
            emails = whois_data.get("emails", []) if isinstance(whois_data["emails"], list) else [whois_data["emails"]]
            valid_emails = [email for email in emails if email is not None]
            self.information.extend([f"{email}|reportmail" for email in valid_emails])
        elif "email" in whois_data:
            emails = whois_data.get("email", []) if isinstance(whois_data["email"], list) else [whois_data["email"]]
            valid_emails = [email for email in emails if email is not None]
            self.information.extend([f"{email}|reportmail" for email in valid_emails])

    def urlscan(self) -> None:
        self.report_content["UrlScan"] = []

        scan = UrlScan(US_API)
        try:
            scan.submit_url(self.url)
            scan.get_results()

            self.information.insert(0, f"{scan.screenshot}|img")
            self.information.insert(2, f"Title: {scan.title}")

            if scan.malicious == True:
                self.report_content["UrlScan"].append("Malicious|malicious")
            else:
                self.report_content["UrlScan"].append("Clear|clear")

            if len(scan.clasification) > 0:
                self.report_content["UrlScan"].append(f"Classification: {scan.clasification[0]}")

            if len(scan.brands) > 0:
                self.report_content["UrlScan"].append(f"Brands: {scan.brands[0]}")
        except DnsError:
            self.report_content["UrlScan"].append("DNS Error")

    def safe_browsing(self) -> None:
        self.report_content["Safe Browsing"] = []

        try:
            s = pysafebrowsing.SafeBrowsing(SB_API)
            r = s.lookup_urls([self.url])
            sb_result = r[self.url]["malicious"]

            if sb_result == True:
                self.report_content["Safe Browsing"].append("Malicious|malicious")
            else:
                self.report_content["Safe Browsing"].append("Clear|clear")
                self.report_content["Safe Browsing"].append(f"https://safebrowsing.google.com/safebrowsing/report_phish/?url={self.url}&hl=ru|reportlink")
        except SafeBrowsingWeirdError:
            self.report_content["Safe Browsing"].append("Failed")

    def virustotal(self) -> None:
        self.report_content["VirusTotal"] = []

        vt = virustotal_python.Virustotal(VT_API)
        try:
            if self.is_domain is True:
                results = vt.request("urls", data={"url": self.domain}, method="POST")
            else:
                results = vt.request("urls", data={"url": self.url}, method="POST")
            url_id = urlsafe_b64encode(self.url.encode()).decode().strip("=")
            for _ in range(40):
                try:
                    results = vt.request(f"urls/{url_id}")
                    if results.data["attributes"]["last_analysis_stats"]["undetected"] == 0:
                        raise ValueError()
                    break
                except (virustotal_python.virustotal.VirustotalError, ValueError):
                    time.sleep(2)

            malicious = results.data["attributes"]["last_analysis_stats"]["malicious"]
            suspicious = results.data["attributes"]["last_analysis_stats"]["suspicious"]
            undetected = results.data["attributes"]["last_analysis_stats"]["undetected"]

            self.report_content["VirusTotal"].append(f"Malicious: {malicious}|malicious")
            self.report_content["VirusTotal"].append(f"Suspicious: {suspicious}|suspicious")
            self.report_content["VirusTotal"].append(f"Undetected: {undetected}|clear")
        except Exception:
            self.report_content["VirusTotal"].append("Failed")

    def metadefender(self) -> None:
        self.report_content["MetaDefender"] = []

        try:
            md = MetaDefender(MD_API)
            md.submit_domain(self.domain)
            if md.detected > 0:
                self.report_content["MetaDefender"].append(f"{md.detected} / {md.allengines}|malicious")
            else:
                self.report_content["MetaDefender"].append(f"{md.detected} / {md.allengines}|clear")
        except Exception as e:
            self.report_content["MetaDefender"].append("Failed")

    def yandex_status(self) -> None:
        self.report_content["Yandex Status"] = []

        result = ya_check(self.url)
        if len(result["info"]) > 0 and "threat" in result["info"][0]:
            if result["info"][0]["threat"] == "fraud.phishing":
                self.report_content["Yandex Status"].append("Malicious|malicious")
        else:
            self.report_content["Yandex Status"].append("Not Found")
            self.report_content["Yandex Status"].append(f"https://yandex.com/support/search/troubleshooting/delspam.html|reportlink")

    def wayback_machine(self) -> None:
        self.report_content["Wayback Machine"] = []

        try:
            availability_api = waybackpy.WaybackMachineAvailabilityAPI(self.domain)
            self.report_content["Wayback Machine"].append(f"First Snapshot: {availability_api.oldest().timestamp().date()}")
        except (waybackpy.exceptions.ArchiveNotInAvailabilityAPIResponse, ValueError):
            self.report_content["Wayback Machine"].append("Not Found")

    def threatminer(self) -> None:
        self.report_content["ThreatMiner"] = []

        tm = threatminer.ThreatMiner()

        res = tm.get_related_samples(self.domain)
        if isinstance(res, dict) and res["status_message"] == "Results found.":
            samples = res["results"]

            self.report_content["ThreatMiner"].append("Samples Found|malicious")
            for i in samples:
                self.report_content["ThreatMiner"].append(i)
        else:
            self.report_content["ThreatMiner"].append("Not Found")

    def netcraft(self) -> None:
        self.report_content["Netcraft"] = []

        try:
            if self.is_domain is True:
                netcraft_id = netcraft_submit(self.domain)
            else:
                netcraft_id = netcraft_submit(self.url)

            self.report_content["Netcraft"].append(f"https://report.netcraft.com/submission/{netcraft_id}|reportlink")
        except ValueError:
            self.report_content["Netcraft"].append("Already submitted")