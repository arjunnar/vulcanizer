## client-side interface

import hashlib
import Crypto.PublicKey.RSA as RSA
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Hash import SHA256
import ClientFile
import pickle
from Crypto.Cipher import PKCS1_OAEP
import globalScope
from globalScope import MockServer, userPublicKeys
from base64 import *
import sqlite3
import os


class VulcanClient:
    def __init__(self):
        self.username = None
	   # maps unencrypted filenames to hash of file contents
        self.fileHashesMap = None
        self.fileKeysMap = None
        # map of (shared) filename to encrypted filename 
        self.sharedFilenamesMap = None
        self.encryptedFilenamesMap = None
        self.rsaPublicKey = None
        self.rsaPrivateKey = None
        self.rsaKeyBits = 2048
        self.signPublicKey = None
        self.signPrivateKey = None
        self.initVectorSize = 16
        # establish connection with dbs.
        self.dbConn = None
        self.dbCursor = None
        self.userDir = None
        self.wd = os.getcwd()

    def initDB(self):
        fileKeysPath = self.userDir + globalScope.dbDirectoryLoc + globalScope.fileKeysDBLoc
        # will create db file if doesn't exist
        if not os.path.exists(fileKeysPath):
            self.dbConn = sqlite3.connect(fileKeysPath)
            self.dbCursor = self.dbConn.cursor()
            # Create table
            self.dbCursor.execute('''CREATE TABLE fileKeys
                         (filename text, encryptedFilename text, readKey text)''')
            self.dbConn.commit()

        else:
            self.dbConn = sqlite3.connect(fileKeysPath)
            self.dbCursor = self.dbConn.cursor()
            self.dbCursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            print self.dbCursor.fetchall()


    def register(self, username):
        if self.username != None:
            raise Exception("Already registered user!")

        self.username = username
        # create table directories. chroot?
        self.userDir = self.wd + "/" + hashlib.sha1(self.username).hexdigest()
        if not os.path.exists(self.userDir):
            os.mkdir(self.userDir)
            dbPath = self.userDir + globalScope.dbDirectoryLoc
            os.mkdir(dbPath)

        self.fileHashesMap = {} # Convert this to a cache later
        self.fileKeysMap = {}
        self.sharedFilenamesMap = {}
        self.encryptedFilenamesMap = {}
        self.rsaPublicKey, self.rsaPrivateKey = self.newRSAKeyPair()
        self.signPublicKey, self.signPrivateKey = self.newRSAKeyPair()
        self.initDB()

    def newRSAKeyPair(self):
        newKey = self.newRSAKey(self.rsaKeyBits)
        publicKey = newKey.publickey().exportKey("PEM")
        privateKey = newKey.exportKey("PEM")
        return (publicKey, privateKey)

    def newFileWriteKeyPair(self):
        newKey = self.newRSAKey(768)
        publicKey = newKey.publickey().exportKey("PEM")
        privateKey = newKey.exportKey("PEM")
        return (publicKey, privateKey)

    def newRSAKey(self, rsaKeyBits):
        return RSA.generate(self.rsaKeyBits)

    def newFileEncryptionKey(self):
        # Random.getrandbits(16)
        return Random.new().read(AES.block_size)

    def newInitVector(self):
        return Random.new().read(self.initVectorSize)

    def addFile(self, clientFile, userPermissions):
        self.addFileHash(clientFile)
        
        filename = clientFile.name

        contents = clientFile.contents
        # encrypt file
        fileEncryptionKey = self.newFileEncryptionKey()
        self.fileKeysMap[filename] = fileEncryptionKey

        # generate another AES key for metadata access
        metadataAccessKey = self.newFileEncryptionKey()
        accessKeyIV = self.newInitVector()
        clientFile.setAccessKey(accessKeyIV + metadataAccessKey)

        fileSignPublicKey, fileSignPrivateKey = self.newFileWriteKeyPair()
        clientFile.metadata.setFileWriteKey(fileSignPublicKey)

        permissionsMap = self.generatePermissionsMap(fileEncryptionKey, fileSignPrivateKey, accessKeyIV, metadataAccessKey, userPermissions)

        clientFile.metadata.setPermissionsMap(permissionsMap)

        # use new initVector
        initVector = self.newInitVector()
        cipher = AES.new(fileEncryptionKey, AES.MODE_CFB, initVector)

        encryptedFilename = cipher.encrypt(clientFile.name)
        encryptedFileContents = initVector + cipher.encrypt(clientFile.contents)
        pickledMetadata = pickle.dumps(clientFile.metadata)

        ### UPDATE db
        self.dbAddFile(filename, encryptedFilename, fileEncryptionKey)
        
        self.encryptedFilenamesMap[clientFile.name] = encryptedFilename

        # call to server to store file
        MockServer[encryptedFilename] = (encryptedFileContents, pickledMetadata)

    def dbAddFile(self, filename, encryptedFilename, fileEncryptionKey):
        ### UPDATE db with filename, encryptedFilename, fileEncryptionKey
        values = (filename, "b".decode("utf-8"), "c".decode("utf-8"))
        self.dbCursor.execute("INSERT INTO fileKeys VALUES (?,?,?)", values)
        self.dbConn.commit()

    def generatePermissionsMap(self, fileEncryptionKey,fileSignPrivateKey, accessKeyIV, accessKey, userPermissions):
        permissionsMap = {}

        for username in userPermissions:
            # check read permission r+w tuple, True/False?
            read, write = userPermissions[username]
            readKey = None
            writeKey = None
            if read:
                # RSA encode with public key
                userPublicKey = userPublicKeys[username]
                readKey = self.encryptReadKey(userPublicKey, fileEncryptionKey)
            
            if write:        
                # use new initVector? No need because thing to encrypt is good size?
                cipher = AES.new(accessKey, AES.MODE_CFB, accessKeyIV)
                # if user has write but not read, userPublicKey will cause problems.
                middle = cipher.encrypt(fileSignPrivateKey)
                writeKey = self.encryptWriteKey(userPublicKey, middle)

            permissionsMap[username] = (readKey, writeKey)

        return permissionsMap

    def addFileHash(self, clientFile):
        filename = clientFile.name
        contentsHash = hashlib.sha1(clientFile.contents)
        self.fileHashesMap[filename] = contentsHash

    def getSharedFile(self, filename, encryptedFilename = None):
        # use pervious encryptedFilename
        if encryptedFilename == None:
            if filename not in self.sharedFilenamesMap:
                raise Exception("File not shared with you!")
            
            encryptedFilename = self.sharedFilenamesMap[fileName]

        else:
            self.sharedFilenamesMap[filename] = encryptedFilename

        # call to server to get file contents
        encryptedFileContents, pickledMetadata = MockServer[encryptedFilename]

        # unpickle metadata
        metadata = pickle.loads(pickledMetadata)
        readKey, writeKey = self.getReadWriteKeys(metadata)

        if readKey == None:
            raise Exception("You don't have permission to access this file.")
        if writeKey == None:
            print "You don't have permission to edit this file."

        # unencrypt file contents
        initVector = encryptedFileContents[:self.initVectorSize]
        cipher = AES.new(readKey, AES.MODE_CFB, initVector)

        fileContents = cipher.decrypt(encryptedFileContents[self.initVectorSize:]).rstrip(b"\0")

        sharedFile = ClientFile.ClientFile(filename, fileContents, metadata)   

        return sharedFile

    def getReadWriteKeys(self, metadata):
        if metadata.permissionsMap == None:
            return (None, None)
        readKey, writeKey = metadata.permissionsMap[self.username]
        if readKey != None:
            readKey = self.decryptReadKey(readKey)
        if writeKey != None:
            writeKey = self.decryptWriteKey(writeKey, metadata.accessKey)
        return (readKey, writeKey)

    def encryptReadKey(self, userPublicKey, encryptionKey):
        rsakey = RSA.importKey(userPublicKey)
        rsakey = PKCS1_OAEP.new(rsakey)
        encryptedKey = rsakey.encrypt(encryptionKey)
        return encryptedKey

    def encryptWriteKey(self, userPublicKey, fileSignPrivateKey):
        return self.encryptReadKey(userPublicKey, fileSignPrivateKey)

    def decryptReadKey(self, readKey):
        # use RSA keys to extract AES file encryption key from readKey
        rsakey = RSA.importKey(self.rsaPrivateKey)
        rsakey = PKCS1_OAEP.new(rsakey)
        decryptedKey = rsakey.decrypt(readKey)
        return decryptedKey

    def decryptWriteKey(self, writeKey, accessKey):
        # initial result is still AES encrypted.
        middle = self.decryptWriteKey(writeKey)
        metadataAccessIV = accessKey[:self.initVectorSize]
        metadataAccessKey = accessKey[self.initVectorSize:]
        cipher = AES.new(accessKey, AES.MODE_CFB, accessKeyIV)
        return cipher.decrypt(middle)

    def getFile(self, filename):
        if filename not in self.fileKeysMap or filename not in self.encryptedFilenamesMap:
            raise Exception("File not owned, possibly shared.")

        fileEncryptionKey = self.fileKeysMap[filename]
        encryptedFilename = self.encryptedFilenamesMap[filename]

        # call to server to get file contents
        encryptedFileContents, pickledMetadata = MockServer[encryptedFilename]
        
        initVector = encryptedFileContents[:self.initVectorSize]
        cipher = AES.new(fileEncryptionKey, AES.MODE_CFB, initVector)

        # unencrypt file contents
        fileContents = cipher.decrypt(encryptedFileContents[self.initVectorSize:])

        if not self.validContents(filename, fileContents):
            # raise warning - file may be corrupt.
            pass

        # get unpickle metadata
        permissionsMap = pickle.loads(pickledMetadata)

        clientFile = ClientFile.ClientFile(filename, fileContents, permissionsMap)   

        return clientFile


    def validContents(self, filename, contents):
        contentsHash = hashlib.sha1(contents)
        previousHash = self.fileHashesMap[filename]
        return contentsHash == previousHash

    def deleteFile(self, filename):
        encryptedFilename = encryptedFilenamesMap[filename]
        del self.fileHashesMap[fileName]
        # call to server to delete for encryptedFileName
        # return response-type thing
        del MockServer[encryptedFilename]

    '''
    assume that filename has not changed.
    '''
    def updateFile(self, filename, clientFile, signature):
        self.addFileHash(clientFile)  
        
        filename = clientFile.name
        contents = clientFile.contents
        metadata = clientFile.metadata

        # need to check for write permission.
        fileWriteKeyKey = metadata.fileWriteKey
        contentsHash = SHA256.new(contents).digest()

        if self.hasWritePermission(fileWriteKey, contentsHash, signature):
            # user has write permissions
            # call to server to update
            # return response-type thing
            print "Has Write Permissions!"
            pass

        # if owner, can also write metadata.

    def hasWritePermission(self, fileWriteKey, contentsHash, signature):
        return fileWriteKey.verify(contentsHash, signature)


    def renameFile(self, filename, newFilename):
        encryptFilename = encryptFilename(fileName)
        newEncryptFilename = encryptFilename(newFilename)

        # call to server to rename
        # return response-type thing

    def encryptFilename(filename):
        encryptedFilename = ""
        return encryptedFilename

    def encryptFileContents(contents):
        encryptedFileContents = ""
        return  
        