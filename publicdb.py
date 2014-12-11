import sqlite3
import os

clientDirectoryLoc = 'client/'
publicDirectoryLoc = clientDirectoryLoc + 'public/'
dbDirectoryName = 'db/'

"Wrapper for public db used by all clients"

class PublicDb():
    def __init__(self):
        if not os.path.exists(clientDirectoryLoc):
            os.mkdir(clientDirectoryLoc)
        
        if not os.path.exists(publicDirectoryLoc):
            os.mkdir(publicDirectoryLoc)

        self.dbDirectoryLoc = publicDirectoryLoc + dbDirectoryName
        
        if not os.path.exists(self.dbDirectoryLoc):
            os.mkdir(self.dbDirectoryLoc)

        self.publicDirectoryLoc = self.dbDirectoryLoc + 'publicDb.db'

        # Create public data db
        if not os.path.exists(self.publicDirectoryLoc):
            self.dbConn = sqlite3.connect(self.publicDirectoryLoc)
            self.dbCursor = self.dbConn.cursor()

            # Create single table within public data db
            self.dbCursor.execute('''CREATE TABLE publicKeysTable
                                         (username text PRIMARY KEY, publicKey text)''')
            self.dbConn.commit()

        self.dbConn = None
        self.dbCursor = None

    def connectToPublicDb(self):
    	self.connectToDb(self.publicDirectoryLoc)

    def connectToDb(self, loc):
    	self.dbConn = sqlite3.connect(loc)
        self.dbConn.text_factory = str
        self.dbCursor = self.dbConn.cursor()

    def addPublicKey(self, username, publicKey):
    	self.connectToPublicDb()
        values = (username, publicKey)
        self.dbConn.execute("INSERT INTO publicKeysTable VALUES (?,?)", values)
        self.dbConn.commit()

    def getPublicKey(self, username):
    	self.connectToPublicDb()
    	values = (username, )
    	cursor = self.dbConn.execute("SELECT publicKey FROM publicKeysTable where username=?", values)
        publicKey = None
        # for loop should only execute once
        for row in cursor:
            publicKey = row[0]

        return (username, publicKey)

    def getPublicKeysMap(self):
    	self.connectToPublicDb()
    	cursor = self.dbConn.execute("SELECT username, publicKey FROM publicKeysTable")
    	userPublicKeysMap = {}
    	for row in cursor:
    		username = row[0]
    		publicKey = row[1]
    		userPublicKeysMap[username] = publicKey
    	return userPublicKeysMap

