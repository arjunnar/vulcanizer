import sqlite3
import os
import DropboxClient
from dropbox import rest as dbrest

clientDirectoryLoc = 'client/'
publicDirectoryLoc = clientDirectoryLoc + 'public/'
dbDirectoryName = 'db/'
publicDbName = 'publicDb.db'
remotePublicDbName = 'public/' + publicDbName

"Wrapper for public db used by all clients"

class PublicDb():
    def __init__(self):
        self.dropboxClient = DropboxClient.DropboxClient()
        if not os.path.exists(clientDirectoryLoc):
            os.mkdir(clientDirectoryLoc)
        
        if not os.path.exists(publicDirectoryLoc):
            os.mkdir(publicDirectoryLoc)
        self.dbDirectoryLoc = publicDirectoryLoc + dbDirectoryName
        if not os.path.exists(self.dbDirectoryLoc):
            os.mkdir(self.dbDirectoryLoc)
        self.publicDirectoryLoc = self.dbDirectoryLoc + 'publicDb.db'

        # check if table exists remotely 
        if not self.remoteExists():

            # Create public data db
            if not os.path.exists(self.publicDirectoryLoc):
                self.dbConn = sqlite3.connect(self.publicDirectoryLoc)
                self.dbCursor = self.dbConn.cursor()

                # Create single table within public data db
                self.dbCursor.execute('''CREATE TABLE publicKeysTable
                                             (username text PRIMARY KEY, publicKey text)''')
                self.dbConn.commit()

            self.updateRemote()

        else:
            self.dropboxClient.replace(self.publicDirectoryLoc, remotePublicDbName)

        self.dbConn = None
        self.dbCursor = None

    def connectToPublicDb(self):
        self.dropboxClient.replace(self.publicDirectoryLoc, remotePublicDbName)
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
        self.updateRemote()

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

    def usersList(self):
        return self.getPublicKeysMap().keys()

    def updateRemote(self):
        f = open(self.publicDirectoryLoc, 'r')
        self.dropboxClient.upload(remotePublicDbName, f)
        f.close()

    def remoteExists(self):
        try:
            self.dropboxClient.download(remotePublicDbName, False)
            return True
        except dbrest.ErrorResponse:
            print "remote public db doesn't exist"
            return False