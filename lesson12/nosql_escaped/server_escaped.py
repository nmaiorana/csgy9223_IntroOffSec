from flask import Flask, request
from pymongo import MongoClient

app = Flask(__name__)

client = MongoClient('mongodb', 27017)
db = client['test']
collection = db['users']

@app.route('/login', methods=['GET'])
def login():
    username = request.args.get('username')
    password = request.args.get('password')

    # Construct the query using $where
    query = {
        "$where": f"this.username == '{username}' && this.password == '{password}'"
    }

    user = collection.find_one(query)

    if user:
        return f"Login successful! Welcome, {user['username']}!", 200
    else:
        return "Invalid username or password.", 401

# Function to initialize the database with default entries
def init_db():
    if collection.count_documents({}) == 0:  # Check if the collection is empty
        default_users = [
            {"id": 1, "username": "admin", "password": "pass"},
            {"id": 2, "username": "noob", "password": "fail"},
        ]
        collection.insert_many(default_users)

if __name__ == '__main__':
    init_db()
    print("database initialized")
    app.run(host='0.0.0.0', port=9000, debug=True)
