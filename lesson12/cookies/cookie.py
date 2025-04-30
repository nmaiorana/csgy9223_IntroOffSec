from flask import Flask, request, render_template, make_response
import secrets

app = Flask(__name__)

# Dictionary of credentials in lieu of a database
creds = dict()
creds["admin"] = "1ce4644965fb631a5b9c7ce396b5f50b"

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/get_cookie', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    user_cookie = secrets.token_hex(16)
    creds[username] = user_cookie

    response = make_response(f'{username}! your cookie is: {user_cookie}')
    response.set_cookie('userCookie', user_cookie)
    return response

@app.route('/authenticate', methods=['GET'])
def check_user_cookie():
    user_cookie = request.cookies.get('userCookie')
    user = next((username for username, cookie in creds.items() if cookie == user_cookie), None)
    if user_cookie and user is not None:
        if user == "admin":
            return 'Admin login successful! Welcome back', 200
        else:
            return 'User cookie found. Login successful for ' + user, 200
    return 'No user cookie found', 403

if __name__ == '__main__':
    app.run(debug=True, port=9000)
