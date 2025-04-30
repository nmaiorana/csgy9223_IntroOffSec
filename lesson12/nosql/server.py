from flask import Flask, jsonify, request
from pymongo import MongoClient

app = Flask(__name__)

MONGO_URI = "mongodb+srv://nam10102:fGnNJoejEcijOGQ4@offsec-cluster.aupafsl.mongodb.net/"
client = MongoClient(MONGO_URI)
db = client['test']
collection = db['users']

@app.route('/login', methods=['POST'])
def authenticate():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    user = collection.find_one({"username": username, "password": password}, {"_id": 0})

    if user:
        return jsonify({"message": "Authentication successful", "user": user}), 200
    else:
        return jsonify({"error": "Invalid username or password"}), 401

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
