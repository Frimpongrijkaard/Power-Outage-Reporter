from mongoengine import connect, disconnect
from dotenv import load_dotenv
import os




load_dotenv()


def init_db_connection(DB, URI):
    try:
        disconnect(alias='default')

        CON = connect(db=DB, host=URI, alias='default')
        print("successfully connected to database")
        
        return CON
    except Exception as e:
        print(f"Error connecting to the database: {e}")
        return None
    


    

    


