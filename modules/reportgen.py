import csv
from datetime import datetime
import io

def create_csv(result):
    doc = io.StringIO()

    data = datetime.now()
    r_writer = csv.writer(doc, delimiter=";", quotechar="|", quoting=csv.QUOTE_MINIMAL)
    r_writer.writerow(["Ice Storm", "Report", f"{data.day:02d}/{data.month:02d}/{data.year:02d}"])
    
    r_writer.writerow([])

    r_writer.writerow(["Domain Information"])
    domain_colums = []
    domain_info = []
    for i in result[1]:
        if not "|" in i:
            record = i.split(": ", maxsplit=1)
            if len(record) > 1:
                domain_colums.append(record[0])
                domain_info.append(record[1])
    r_writer.writerow(domain_colums)
    r_writer.writerow(domain_info)
    
    r_writer.writerow([])

    r_writer.writerow(["Security Information"])
    security_colums = []
    security_info = []
    for i in result[2]:
        if len(result[2][i]) == 1:
            security_colums.append(i)
            security_info.append(result[2][i][0].split("|")[0])
    r_writer.writerow(security_colums)
    r_writer.writerow(security_info)

    r_writer.writerow([])
    
    r_writer.writerow(["Abuse Reporting"])
    mails = []
    for i in result[1]:
        if "|reportmail" in i:
            mails.append(i.replace("|reportmail", ""))
    r_writer.writerow(mails)

    return doc