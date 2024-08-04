from flask import Flask
from flask import request
from flask import render_template
from flask import abort
from flask import send_file
from api import report_api
from modules.reportgen import create_csv
import threading
import validators
import requests
import io
from ast import literal_eval as make_tuple
import webbrowser
from config import *

if (not SB_API) or (not VT_API) or (not US_API) or (not MD_API):
    raise ValueError("Toolkit is not configured! Please check config.py")

app = Flask(__name__)

def create_report(url: str, is_domain=False) -> tuple:
    report = report_api(url, is_domain)
    todo = [report.whois, report.urlscan, report.safe_browsing, report.virustotal, report.metadefender, report.yandex_status, report.wayback_machine, report.threatminer, report.netcraft]
    threads = []

    for i in todo:
        t = threading.Thread(target=i)
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    return report.domain, report.information, report.report_content

@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")

@app.route("/search", methods=["POST"])
def search():
    try:
        url = request.form.get("url").strip()
    except TypeError:
        return "URL argument not found"

    if (validators.url(url) or validators.domain(url)):
        if not validators.url(url):
            results = create_report(f"https://{url}/", is_domain=True)
        else:
            results = create_report(url)
    
        return render_template("search.html", results=results, domain=results[0], information=results[1], records=results[2])
    else:
        return "Invalid search query"
        
@app.route("/export", methods=["POST"])
def exportcsv():
    try:
        results = make_tuple(request.form.get("results"))
    except TypeError:
        return "Results argument not found"

    report = create_csv(results)
    mem = io.BytesIO()
    mem.write(report.getvalue().encode())
    mem.seek(0)
    return send_file(mem, download_name="report.csv", mimetype="text/csv", as_attachment=True)

if __name__ == "__main__":
    webbrowser.open("http://127.0.0.1:9000/", new=2)
    app.run(host="127.0.0.1", port=9000)
