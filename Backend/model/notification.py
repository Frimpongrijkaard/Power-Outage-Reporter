from mongoengine import Document, StringField, DateTimeField, ReferenceField, BooleanField
from model import  User
from model import Outage
import datetime

class Notification(Document):
    meta = {'collection': 'notifications'}
    user = ReferenceField(User, required=True)
    outage = ReferenceField(Outage, required=True)
    message = StringField(required=True)
    sent_at = DateTimeField(default=datetime.datetime.utcnow)