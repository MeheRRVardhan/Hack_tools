import re
import json #converting dictionary -> string, here the final report is a dictionary, so to use regex properly, this needs to convert into --> string
import virustotal_python
from base64 import urlsafe_b64encode
import argparse
print(''' o
o      ______/~/~/~/__           /((
  o  // __            ====__    /_((
 o  //  @))       ))))      ===/__((
    ))           )))))))        __((
    \\     \)     ))))    __===\ _((
     \\_______________====      \_((
                                 \((
# CREDITS: ASCII_ART ARCHIEVE
''')
# Parsing command line options
parser = argparse.ArgumentParser(description="Check URL using VirusTotal API")
parser.add_argument("-u", "--url", required=True, help="Enter the URL of the domain to check using VirusTotal module")
args = parser.parse_args()
url = args.url

# Interacting with VirusTotal API
with virustotal_python.Virustotal("<enter_your_virus_total API") as vtotal:
    try:
        resp = vtotal.request("urls", data={"url": url}, method="POST")
        url_id = urlsafe_b64encode(url.encode()).decode().strip("=")
        report = vtotal.request(f"urls/{url_id}")
        Final_data = report.data
        final_string_data = json.dumps(Final_data)
        pattern = re.compile(r'(\Wmalicious\W\:)(\W\d)')
        matches = pattern.finditer(final_string_data)
        print("VIRUS-TOTAL REPORT")
        for match in matches:
            print(match.group(1), int(match.group(2)))
            if int(match.group(2)) > 0:
                print("THIS IS A PHISHING-EMAIL")
    except virustotal_python.VirustotalError as err:
        print(f"Failed to send URL: {url} for analysis and get the report: {err}")
