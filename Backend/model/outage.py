from mongoengine import Document, StringField, DateTimeField, ReferenceField, BooleanField
from Backend.model.user import User
import datetime

class Outage(Document):
    meta = {'collection': 'outages'}
    user = ReferenceField(User, required=True)
    description = StringField(required=True, max_length=500)
    location = StringField(required=True)
    status = StringField(default="pending", choices=["pending", "in-progress", "resolved"])
    timestamp = DateTimeField(default=datetime.datetime.now)