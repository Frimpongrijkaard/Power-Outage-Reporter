from mongoengine import connect
from dotenv import load_dotenv
import os

load_dotenv()


def init_db_connection(DB, URI):
    CON = connect(db=DB, host=URI, alias='default')
    return CON