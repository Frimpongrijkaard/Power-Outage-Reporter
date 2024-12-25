from pymongo import MongoClient

# Connect to a MongoDB instance (local or remote)
client = MongoClient("mongodb://localhost:27017/")

# Access a specific database
db = client["mydatabase"]