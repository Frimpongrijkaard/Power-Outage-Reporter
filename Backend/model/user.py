from mongoengine import Document, StringField, BooleanField

class User(Document):
    meta = {"Collection": "user"}
    name = StringField(required=True, max_length=100)
    email= StringField(require=True, unique=True)
    location = StringField(required=True)
    phone = StringField(required=True, max_length=15)
    password = StringField(required=True)
    adminpin = StringField(required=False, default=None)
    role = StringField(default="user", choice=["user", "admin"])


 