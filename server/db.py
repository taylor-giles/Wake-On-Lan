from pymongo import MongoClient

class Mongo:
    def __init__(self, URL):
        self.client = MongoClient(URL)
        self.db = self.client["Drive_Sharing_Manager"]
        
        
    
    def get_database(self, name):
        return self.client[name]
    
    
    def get_collection(self, name):
        pass
            
        
def get_database():
 
   # Provide the mongodb atlas url to connect python to mongodb using pymongo
   CONNECTION_STRING = "mongodb://localhost:27017/Drive_sharing_Manager"
 
   # Create a connection using MongoClient. You can import MongoClient or use pymongo.MongoClient
   client = MongoClient(CONNECTION_STRING)
   print(client)
 
   # Create the database for our example (we will use the same database throughout the tutorial
   return client['Drive_Sharing_Manager']


if __name__ == "__main__":
  
   # Get the database
   dbname = get_database()
   collection = dbname['sup']
    
   collection.insert_one({
       "hi": "hi"
   })
   print(dbname)