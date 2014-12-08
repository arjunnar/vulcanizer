    ## client-side interface

import hashlib
import Crypto.PublicKey.RSA as RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto import Random
from Crypto.Hash import SHA256
import ClientFile
import pickle
import globalScope
from globalScope import MockServer, userPublicKeys
import sqlite3
import os
import clientdb
import clientCrypto

class VulcanClient:
    def __init__(self):
        self.username = None
        self.rsaPublicKey = None
        self.rsaPrivateKey = None
        
        self.db = None

        ### REFERENCE VALUES ###
        self.rsaKeyBits = 2048
        self.initVectorSize = 16
        self.junkDataSize = 16

    '''
    returns boolean indicatign successful registration
    '''
    def register(self, username):
        if self.username != None:
            raise Exception("Already registered user!")

        # need check for if user account already exists
        self.db = clientdb.ClientDb(username)
        self.db.setupAllDbs()
        
        if self.db.userExists(username):
            print "User already exists!"
            return False

        self.username = username

        self.rsaPublicKey, self.rsaPrivateKey = clientCrypto.newRSAKeyPair(self.rsaKeyBits)
        self.db.addUserDbRecord(self.username, self.rsaPublicKey, self.rsaPrivateKey)
        return True

    def login(self, username):
        self.username, self.rsaPublicKey, self.rsaPrivateKey = self.db.getUserDbRecord(username)

    '''
    method to generate junk junkDataSize
    '''
    def getJunkData(self):
        return Random.new().read(self.junkDataSize)

    def addFile(self, clientFile, userPermissions):
        filename = clientFile.name
        contents = clientFile.contents
        metadata = clientFile.metadata

        if self.db.fileExists(filename):
            raise Exception("file already exists!")

        metadataHash = self.getMetadataHash(metadata)

        # encrypt filename
        fileEncryptionKey = clientCrypto.newAESEncryptionKey()

        # get RSA info
        fileRSAKey = clientCrypto.newRSAKey(self.rsaKeyBits)
        fileWritePublicKey, fileWritePrivateKey = clientCrypto.newRSAKeyPair(self.rsaKeyBits, fileRSAKey)
        clientFile.metadata.setFileWritePublicKey(fileWritePublicKey)

        # sign contents
        signFile = clientCrypto.rsaSign(contents, fileRSAKey)
        clientFile.setWriteSignature(signFile)

        # generate another AES key to encrypt the FileWriteKey
        fileWriteEncryptionKey = clientCrypto.newAESEncryptionKey()
        fileWriteEncryptionIV = clientCrypto.newInitVector(self.initVectorSize)

        # encrypt the FileWriteKey
        cipher = AES.new(fileWriteEncryptionKey, AES.MODE_CFB, fileWriteEncryptionIV)
        fileWriteAccessKey = cipher.encrypt(fileWritePrivateKey)
        clientFile.metadata.setFileWriteAccessKey(fileWriteAccessKey)

        permissionsMap = self.generatePermissionsMap(fileEncryptionKey, fileWriteEncryptionKey, fileWriteEncryptionIV, userPermissions)

        clientFile.setPermissionsMap(permissionsMap)

        # encrypt filename and file contents
        initVector = clientCrypto.newInitVector(self.initVectorSize)
        cipher = AES.new(fileEncryptionKey, AES.MODE_CFB, initVector)
        encryptedFilename = cipher.encrypt(clientFile.name)

        # update owner file hash
        self.db.addFileRecord(filename, fileEncryptionKey, encryptedFilename, metadataHash)

        # junk the beginning of contents
        encryptedFileContents = initVector + cipher.encrypt(self.getJunkData() + clientFile.contents)
        pickledMetadata = pickle.dumps(clientFile.metadata)

        # call to server to store file
        MockServer[encryptedFilename] = (encryptedFileContents, signFile, pickledMetadata)

    def generatePermissionsMap(self, fileEncryptionKey, fileWriteEncryptionKey, fileWriteEncryptionIV, userPermissions):
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
                # if user has write but not read, userPublicKey will cause problems.
                writeKey = self.encryptWriteKey(userPublicKey, fileWriteEncryptionKey, fileWriteEncryptionIV)

            permissionsMap[username] = (readKey, writeKey)

        return permissionsMap

    def getEncryptedFilename(self, filename):
        return self.db.getFileRecord(filename)[2]

    def getMetadataHash(self, metadata):
        return clientCrypto.sha1HexHash(pickle.dumps(metadata))

    def validMetadata(self, filename, metadata):
        metadataHash = clientCrypto.sha1HexHash(pickle.dumps(metadata))
        encryptedFilename, encryptedContents, previousHash = self.db.getFileRecord(filename)
        return contentsHash == previousHash

    def getSharedFile(self, filename, encryptedFilename = None):
        # use pervious encryptedFilename
        if encryptedFilename == None:
            if not self.db.sharedFileExists(filename):
                raise Exception("File not shared with you!")

            encryptedFilename = self.db.getSharedEncryptedFilename(filename)

        else:
            self.db.updateSharedEncryptedFilename(filename, encryptedFilename)

        # call to server to get file contents
        encryptedFileContents, signFile, pickledMetadata = MockServer[encryptedFilename]

        # unpickle metadata
        metadata = pickle.loads(pickledMetadata)
        readKey, writeKey = self.getReadWriteKeys(metadata)

        if readKey == None:
            raise Exception("You don't have permission to access this file.")

        if writeKey == None:
            print "You don't have permission to edit this file."
        else:
            print "You have edit access to this file."
        # unencrypt file contents
        initVector = encryptedFileContents[:self.initVectorSize]
        encryptedFileContents = encryptedFileContents[self.initVectorSize:]
        cipher = AES.new(readKey, AES.MODE_CFB, initVector)

        fileContents = cipher.decrypt(encryptedFileContents)[self.junkDataSize:]
        if not self.validSignature(metadata.fileWritePublicKey, fileContents, signFile):
            print "invalid signature!"

        print "valid signature"

        sharedFile = ClientFile.ClientFile(filename, fileContents, metadata)   

        return sharedFile

    def validSignature(self, publicKey, contents, signature):
        contentsHash = SHA256.new(contents).digest()
        rsakey = RSA.importKey(publicKey)
        # rsakey = PKCS1_OAEP.new(rsakey)
        return rsakey.verify(contentsHash, signature)

    def getReadWriteKeys(self, metadata):
        if metadata.permissionsMap == None or self.username not in metadata.permissionsMap:
            return (None, None)
        readKey, writeKey = metadata.permissionsMap[self.username]
        if readKey != None:
            readKey = self.decryptReadKey(readKey)
        if writeKey != None:
            writeKey = self.decryptWriteKey(writeKey, metadata.fileWriteAccessKey)
        return (readKey, writeKey)

    def encryptReadKey(self, userPublicKey, encryptionKey):
        return clientCrypto.rsaEncryptKey(userPublicKey, encryptionKey)

    def encryptWriteKey(self, userPublicKey, fileWriteEncryptionKey, fileWriteEncryptionIV):
        return clientCrypto.rsaEncryptKey(userPublicKey, fileWriteEncryptionIV + fileWriteEncryptionKey)

    def decryptReadKey(self, readKey):
        # use RSA keys to extract AES file encryption key from readKey
        return clientCrypto.rsaDecryptKey(self.rsaPrivateKey, readKey)

    def decryptWriteKey(self, writeKey, fileWriteAccessKey):
        # initial result is still AES encrypted.
        middleKey = clientCrypto.rsaDecryptKey(self.rsaPrivateKey, writeKey)
        fileWriteEncryptionIV = middleKey[:self.initVectorSize]
        fileWriteEncryptionKey = middleKey[self.initVectorSize:]
        cipher = AES.new(fileWriteEncryptionKey, AES.MODE_CFB, fileWriteEncryptionIV)
        # returns AES decrypted fileWriteAccessKey (which is AES encrypted fileWriteKey)
        return cipher.decrypt(fileWriteAccessKey)

    def getFile(self, filename):
        if not self.db.fileExists(filename):
            raise Exception("File not owned, possibly shared.")

        filename, fileEncryptionKey, encryptedFilename, metadataHash = self.db.getFileRecord(filename)

        # call to server to get file contents
        encryptedFileContents, pickledMetadata = MockServer[encryptedFilename]
        
        initVector = encryptedFileContents[:self.initVectorSize]
        cipher = AES.new(fileEncryptionKey, AES.MODE_CFB, initVector)

        # unencrypt file contents
        fileContents = cipher.decrypt(encryptedFileContents)[self.junkDataSize:]

        # get unpickle metadata
        metadata = pickle.loads(pickledMetadata)
        
        if not self.validMetadata(filename, metadata):
            print "invalid metadata"

        clientFile = ClientFile.ClientFile(filename, fileContents, metadata)

        return clientFile

    def deleteFile(self, filename):
        # call to server to delete for encryptedFileName
        # return response-type thing
        del MockServer[encryptedFilename]
        self.db.deleteFileRecord(filename)

    '''
    assume that filename has not changed.
    '''
    def updateFile(self, filename, clientFile, signature):
        self.addFileHash(clientFile)  
        
        filename = clientFile.name
        contents = clientFile.contents
        metadata = clientFile.metadata

        # need to check for write permission.
        fileWritePublicKey = metadata.fileWritePublicKey
        contentsHash = SHA256.new(contents).digest()

        if self.hasWritePermission(fileWritePublicKey, contentsHash, signature):
            # user has write permissions
            # call to server to update
            # return response-type thing
            print "Has Write Permissions!"
            pass

        # if owner, also update metadata.

        # if owner, can also write metadata.

    def hasWritePermission(self, fileWritePublicKey, contentsHash, signature):
        return fileWritePublicKey.verify(contentsHash, signature)

    def renameFile(self, filename, newFilename):
        encryptFilename = encryptFilename(fileName)
        newEncryptFilename = encryptFilename(newFilename)

    def encryptFilename(filename):
        encryptedFilename = ""
        return encryptedFilename

    def encryptFileContents(contents):
        encryptedFileContents = ""
        return  
        