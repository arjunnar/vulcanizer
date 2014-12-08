import sqlite3
import os

clientDirectoryLoc = 'client/'
dbDirectoryName = 'db/'

"Wrapper for all the dbs used by a single client"
class ClientDb():
    def __init__(self, username):
        self.username = username
        if not os.path.exists(clientDirectoryLoc):
            os.mkdir(clientDirectoryLoc)
        userDir = clientDirectoryLoc + username + '/'
        
        if not os.path.exists(userDir):
            os.mkdir(userDir)
        self.dbDirectoryLoc = clientDirectoryLoc + username + '/' + dbDirectoryName
        
        if not os.path.exists(self.dbDirectoryLoc):
            os.mkdir(self.dbDirectoryLoc)

        self.userDataDbLoc = self.dbDirectoryLoc + 'userDataDb.db'
        self.filesDbLoc = self.dbDirectoryLoc + 'filesDb.db'
        self.dbConn = None
        self.dbCursor = None

    def setupAllDbs(self):
        self.dbConn = None

        # Create user data db
        if not os.path.exists(self.userDataDbLoc):
            self.dbConn = sqlite3.connect(self.userDataDbLoc)
            self.dbCursor = self.dbConn.cursor()

            # Create single table within user data db
            self.dbCursor.execute('''CREATE TABLE userDataTable
                                         (username text PRIMARY KEY, publicKey text, privateKey text)''')
            self.dbConn.commit()

        # Create filesDb 
        if not os.path.exists(self.filesDbLoc):
            self.dbConn = sqlite3.connect(self.filesDbLoc)
            self.dbCursor = self.dbConn.cursor()

            # Create single table within user data db
            self.dbCursor.execute('''CREATE TABLE filesTable
                                         (filename PRIMARY KEY, encryptedFilename text, permissionsHash text)''')
            self.dbConn.commit()

    def addUserDbRecord(self, user, publicKey, privateKey):
        values = (user, publicKey, privateKey)
        self.dbConn.execute("INSERT INTO userDataTable VALUES (?,?,?)", values)
        self.dbConn.commit()
        
    # returns a 3-tuple of (user, publicKey, privateKey)
    def getUserDbRecord(self, user):
        cursor = self.dbConn.execute("SELECT * FROM userDataTable where username = " + "'" + user + "'")
        username = user
        privateKey = None
        publicKey = None
        
        # for loop should only execute once
        for row in cursor:
            publicKey = row[1]
            privateKey = row[2]

        return (username, publicKey, privateKey)

    def addFileRecord(self, filename, encryptedFilename, permHash):
        values = (filename, encryptedFilename, permHash)
        self.dbConn.execute("INSERT INTO filesTable VALUES (?,?,?)", values)
        self.dbConn.commit()

    def getFileRecord(self, filename):
        cursor = self.dbConn.execute("SELECT * FROM filesTable where filename = " + "'" + filename + "'")
        
        encryptedFilename = None
        permHash = None

        for row in cursor:
            encryptedFilename = row[1]
            permHash = row[2]
        
        return (filename, encryptedFilename, permHash)
        
        


    
            
            
            

        








