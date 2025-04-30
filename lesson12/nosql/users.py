from pymongo import MongoClient

MONGO_URI = "mongodb+srv://nam10102:fGnNJoejEcijOGQ4@offsec-cluster.aupafsl.mongodb.net/"
client = MongoClient(MONGO_URI)

# Select the database and collection
db = client['test']
users_collection = db['users']

# Data to insert
users_data = [
    { "idx": 0, "username": "admin", "password": "pass" },
    { "idx": 1, "username": "noob", "password": "fail" }
]

# Insert the data
result = users_collection.insert_many(users_data)