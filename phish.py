import virustotal_python
from base64 import urlsafe_b64encode
from optparse import OptionParser
import pprint
# here pprint is a data-pretty printer, I used the print() function, which gave me lumps of data (not gibrish, but umm!! loads of dictionary data not so clear, so using pprint we can get the data more clear and 
# kinda organised!!
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

parser = OptionParser()
parser.add_option("-u", "--url", dest="url", help="Enter the url of the domain to check using virus-total module")
(options, args) = parser.parse_args()
url = options.url

with virustotal_python.Virustotal("<<get your virus_total_API>>") as vtotal:
    try:
        resp = vtotal.request("urls", data={"url": url}, method="POST")
        # Safe encode URL in base64 format
        # https://developers.virustotal.com/reference/url
        url_id = urlsafe_b64encode(url.encode()).decode().strip("=")
        report = vtotal.request(f"urls/{url_id}")

        # Print the type of the report object
        print(report.object_type)

        # Print the final data
        Final_data = report.data
        pprint.pp(Final_data)
    except virustotal_python.VirustotalError as err:
        print(f"Failed to send URL: {url} for analysis and get the report: {err}")


