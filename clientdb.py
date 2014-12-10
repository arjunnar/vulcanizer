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
        self.sharedFilesDbLoc = self.dbDirectoryLoc + 'sharedFilesDb.db'
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
                                         (filename PRIMARY KEY, fileEncryptionKey text, encryptedFilename text, fileWritePrivateKey text, metadataHash text)''')
            self.dbConn.commit()

        # Create sharedFilesDb 
        if not os.path.exists(self.sharedFilesDbLoc):
            self.dbConn = sqlite3.connect(self.sharedFilesDbLoc)
            self.dbCursor = self.dbConn.cursor()

            # Create single table within user data db
            self.dbCursor.execute('''CREATE TABLE sharedFilesTable
                                         (filename PRIMARY KEY, encryptedFilename text, fileEncryptionKey text, 
                                            fileWritePrivateKey text)''')
            self.dbConn.commit()

    '''
    only to be called after setup of all dbs
    '''
    def connectToUserDb(self):
        self.connectToDb(self.userDataDbLoc)

    def connectToFilesDb(self):
        self.connectToDb(self.filesDbLoc)

    def connectToSharedFilesDb(self):
        self.connectToDb(self.sharedFilesDbLoc)

    def connectToDb(self, loc):
        self.dbConn = sqlite3.connect(loc)
        self.dbConn.text_factory = str
        self.dbCursor = self.dbConn.cursor()

    def userExists(self, user):
        self.connectToUserDb()
        values = (user,)
        cursor = self.dbConn.execute("SELECT count(*) FROM userDataTable where username=?", values)
        userCount = cursor.fetchone()[0]
        self.dbConn.commit()
        return userCount == 1

    def addUserDbRecord(self, user, publicKey, privateKey):
        self.connectToUserDb()
        values = (user, publicKey, privateKey)
        self.dbConn.execute("INSERT INTO userDataTable VALUES (?,?,?)", values)
        self.dbConn.commit()
        
    # returns a 3-tuple of (user, publicKey, privateKey)
    def getUserDbRecord(self, user):
        self.connectToUserDb()
        cursor = self.dbConn.execute("SELECT * FROM userDataTable where username = " + "'" + user + "'")
        username = user
        privateKey = None
        publicKey = None
        
        # for loop should only execute once
        for row in cursor:
            publicKey = row[1]
            privateKey = row[2]

        return (username, publicKey, privateKey)

    def fileExists(self, filename):
        self.connectToFilesDb()
        values = (filename,)
        cursor = self.dbConn.execute("SELECT count(*) FROM filesTable where filename=?", values)
        fileCount = cursor.fetchone()[0]
        self.dbConn.commit()
        return fileCount == 1

    def getEncryptedFilename(self, filename):
        if self.sharedFileExists(filename):
            return self.getSharedEncryptedFilename(filename)
        
        elif self.fileExists(filename):    
            self.connectToFilesDb()
            values = (filename,)
            cursor = self.dbConn.execute("SELECT encryptedFilename FROM filesTable where filename=?", values)
            self.dbConn.commit()
            return cursor.fetchone()[0]
        
        else:
            raise Exception("No such file.")

    def addFileRecord(self, filename, fileEncryptionKey, encryptedFilename, fileWritePrivateKey, metadataHash):
        self.connectToFilesDb()
        self.dbConn.text_factory = str
        values = (filename, fileEncryptionKey, encryptedFilename, fileWritePrivateKey, metadataHash)
        self.dbConn.execute("INSERT INTO filesTable VALUES (?,?,?,?,?)", values)
        self.dbConn.commit()

    def deleteFileRecord(self, filename):
        self.connectToFilesDb()
        values = (filename,)
        self.dbConn.execute("DELETE FROM filesTable WHERE filename=?", values)
        self.dbConn.commit()

    def updateFileRecord(self, filename, fileEncryptionKey, encryptedFilename, fileWritePrivateKey, metadataHash):
        self.connectToFilesDb()
        filename, prevEncryptionKey, prevEncryptedFilename, prevFileWritePrivateKey, prevMetadataHash = self.getFileRecord(filename)
   
        if fileEncryptionKey == None:
            fileEncryptionKey = prevEncryptionKey
        if encryptedFilename == None:
            encryptedFilename = prevEncryptedFilename
        if fileWritePrivateKey == None:
            fileWritePrivateKey = prevFileWritePrivateKey

        if metadataHash == None:
            metadataHash = prevMetadataHash

        values = (fileEncryptionKey, encryptedFilename, fileWritePrivateKey, metadataHash, filename)
        self.dbConn.execute("UPDATE filesTable SET fileEncryptionKey=?, encryptedFilename=?, \
                                fileWritePrivateKey=?, metadataHash=? WHERE filename=?", values)
        self.dbConn.commit()

    def getFileRecord(self, filename):
        self.connectToFilesDb()
        cursor = self.dbConn.execute("SELECT * FROM filesTable where filename = " + "'" + filename + "'")
        
        fileEncryptionKey = None
        encryptedFilename = None
        metadataHash = None

        for row in cursor:
            fileEncryptionKey = row[1]
            encryptedFilename = row[2]
            fileWritePrivateKey = row[3]
            metadataHash = row[4]
        
        return (filename, fileEncryptionKey, encryptedFilename, fileWritePrivateKey, metadataHash)            

    def showAllFiles(self):
        allFiles = []
        allFiles.extend(self.showFiles())
        allFiles.extend(self.showSharedFiles())
        return allFiles

    def showFiles(self):
        self.connectToFilesDb()
        cursor = self.dbConn.execute("SELECT filename FROM filesTable")
        files = []
        for row in cursor:
            files.append(row[0])
        return files

    def showSharedFiles(self):
        self.connectToSharedFilesDb()
        cursor = self.dbConn.execute("SELECT filename FROM sharedFilesTable")
        sharedFiles = []
        for row in cursor:
            sharedFiles.append(row[0])
        return sharedFiles

    def sharedFileExists(self, filename):
        self.connectToSharedFilesDb()
        values = (filename,)
        cursor = self.dbConn.execute("SELECT count(*) FROM sharedFilesTable where filename=?", values)
        sharedFileCount = cursor.fetchone()[0]
        self.dbConn.commit()
        return sharedFileCount == 1

    def addSharedFileRecord(self, filename, encryptedFilename, fileEncryptionKey="", fileWritePrivateKey=""):
        self.connectToSharedFilesDb()
        values = (filename, encryptedFilename, fileEncryptionKey, fileWritePrivateKey)
        self.dbConn.execute("INSERT INTO sharedFilesTable VALUES (?,?,?,?)", values)
        self.dbConn.commit()

    def getSharedFileRecord(self, filename):
        self.connectToSharedFilesDb()
        cursor = self.dbConn.execute("SELECT * FROM sharedFilesTable where filename = " + "'" + filename + "'")
        
        encryptedFilename = None

        for row in cursor:
            encryptedFilename = row[1]
            fileEncryptionKey = row[2]
            fileWritePrivateKey = row[3]
        
        return (filename, encryptedFilename, fileEncryptionKey, fileWritePrivateKey)

    def getSharedEncryptedFilename(self, filename):
        filename, encryptedFilename, fileEncryptionKey, prevFileWritePrivateKey = self.getSharedFileRecord(filename)
        return encryptedFilename

    def deleteSharedFileRecord(self, filename):
        self.connectToFilesDb()
        values = (filename,)
        self.dbConn.execute("DELETE FROM sharedFilesTable WHERE filename=?", values)
        self.dbConn.commit()

    '''
    method to update encryptedFilename of shared file.
    '''
    def updateSharedEncryptedFilename(self, filename, encryptedFilename):
        self.connectToFilesDb()
        if not self.sharedFileExists(filename):
            self.addSharedFileRecord(filename, encryptedFilename)

        else:    
            prevEncryptedFilename = self.getSharedEncryptedFilename(filename)
            if prevEncryptedFilename != encryptedFilename:
                values = (encryptedFilename, filename)
                self.dbConn.execute("UPDATE sharedFilesTable SET encryptedFilename=? WHERE filename=?", values)
                self.dbConn.commit()

    def updateSharedFileRecord(self, filename, encryptedFilename=None, fileEncryptionKey=None, fileWritePrivateKey=None):
        self.connectToSharedFilesDb()
        sharedRecordItems = self.getSharedFileRecord(filename)
        args = locals().items()
        
        # use old values if not supplied
        for i in range(1,len(args)):
            if args[i] == None:
                args[i] = sharedRecordItems[i-1]

        if not self.sharedFileExists(filename):
            print "warning: can't find previous file, adding this one to system."
            self.addSharedFileRecord(filename, encryptedFilename, fileEncryptionKey, fileWritePrivateKey)

        else:    
            values = (encryptedFilename, fileEncryptionKey, fileWritePrivateKey, filename)
            self.dbConn.execute("UPDATE sharedFilesTable SET encryptedFilename=?, fileEncryptionKey=?, fileWritePrivateKey=? WHERE filename=?", values)
            self.dbConn.commit()
    
            
            
            

        








