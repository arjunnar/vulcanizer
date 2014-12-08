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
	   # maps unencrypted filenames to hash of file contents
        self.metadataHashesMap = None
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
        self.junkDataSize = 16
        # establish connection with dbs.
        self.dbConn = None
        self.dbCursor = None
        self.userDir = None
        self.wd = os.getcwd()
        self.db = None

    def register(self, username):
        if self.username != None:
            raise Exception("Already registered user!")

        self.username = username
        
        # initialize databases
        self.db = clientdb.ClientDb(self.username)
        self.db.setupAllDbs()

        self.metadataHashesMap = {} # Convert this to a cache later
        self.fileKeysMap = {}
        self.sharedFilenamesMap = {}
        self.encryptedFilenamesMap = {}

        self.rsaPublicKey, self.rsaPrivateKey = clientCrypto.newRSAKeyPair(self.rsaKeyBits)
        self.signPublicKey, self.signPrivateKey = clientCrypto.newRSAKeyPair(self.rsaKeyBits)

    def newAESEncryptionKey(self):
        # Random.getrandbits(16)
        return Random.new().read(AES.block_size)

    def getJunkData(self):
        return Random.new().read(self.junkDataSize)

    def newInitVector(self):
        return Random.new().read(self.initVectorSize)

    def addFile(self, clientFile, userPermissions):
        self.addMetadataHash(clientFile)
        
        filename = clientFile.name
        contents = clientFile.contents

        # junk the beginning of contents

        # encrypt filename
        fileEncryptionKey = self.newAESEncryptionKey()
        self.fileKeysMap[filename] = fileEncryptionKey

        fileRSAKey = clientCrypto.newRSAKey(self.rsaKeyBits)
        fileWritePublicKey, fileWritePrivateKey = clientCrypto.newRSAKeyPair(self.rsaKeyBits, fileRSAKey)
        clientFile.metadata.setFileWritePublicKey(fileWritePublicKey)
        signFile = self.rsaSign(contents, fileRSAKey)
        clientFile.setWriteSignature(signFile)

        # generate another AES key to encrypt the FileWriteKey
        fileWriteEncryptionKey = self.newAESEncryptionKey()
        fileWriteEncryptionIV = self.newInitVector()

        # encrypt the FileWriteKey
        cipher = AES.new(fileWriteEncryptionKey, AES.MODE_CFB, fileWriteEncryptionIV)
        fileWriteAccessKey = cipher.encrypt(fileWritePrivateKey)
        clientFile.metadata.setFileWriteAccessKey(fileWriteAccessKey)

        permissionsMap = self.generatePermissionsMap(fileEncryptionKey, fileWriteEncryptionKey, fileWriteEncryptionIV, userPermissions)

        clientFile.setPermissionsMap(permissionsMap)

        # encrypt filename and file contents
        initVector = self.newInitVector()
        cipher = AES.new(fileEncryptionKey, AES.MODE_CFB, initVector)
        encryptedFilename = cipher.encrypt(clientFile.name)
        encryptedFileContents = initVector + cipher.encrypt(self.getJunkData() + clientFile.contents)
        pickledMetadata = pickle.dumps(clientFile.metadata)
        
        self.encryptedFilenamesMap[clientFile.name] = encryptedFilename

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

    def addMetadataHash(self, clientFile):
        filename = clientFile.name
        metadataHash = hashlib.sha1(pickle.dumps(clientFile.metadata))
        self.metadataHashesMap[filename] = metadataHash

    def validMetadata(self, filename, metadata):
        metadataHash = hashlib.sha1(pickle.dumps(metadata))
        previousHash = self.metadataHashesMap[filename]
        return contentsHash == previousHash

    def getSharedFile(self, filename, encryptedFilename = None):
        # use pervious encryptedFilename
        if encryptedFilename == None:
            if filename not in self.sharedFilenamesMap:
                raise Exception("File not shared with you!")
            
            encryptedFilename = self.sharedFilenamesMap[fileName]

        else:
            # remember encryptedFilename
            self.sharedFilenamesMap[filename] = encryptedFilename

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
        return self.rsaEncryptKey(userPublicKey, encryptionKey)

    def encryptWriteKey(self, userPublicKey, fileWriteEncryptionKey, fileWriteEncryptionIV):
        return self.rsaEncryptKey(userPublicKey, fileWriteEncryptionIV + fileWriteEncryptionKey)

    def rsaSign(self, toSign, rsaKey):
        toSignHash = SHA256.new(toSign).digest()
        return rsaKey.sign(toSignHash, '')

    def rsaEncryptKey(self, publicKey, keyToEncrypt):
        rsakey = RSA.importKey(publicKey)
        rsakey = PKCS1_OAEP.new(rsakey)
        encryptedKey = rsakey.encrypt(keyToEncrypt)
        return encryptedKey

    def rsaDecryptKey(self, keyToDecrypt):
        rsakey = RSA.importKey(self.rsaPrivateKey)
        rsakey = PKCS1_OAEP.new(rsakey)
        decryptedKey = rsakey.decrypt(keyToDecrypt)
        return decryptedKey

    def decryptReadKey(self, readKey):
        # use RSA keys to extract AES file encryption key from readKey
        return self.rsaDecryptKey(readKey)

    def decryptWriteKey(self, writeKey, fileWriteAccessKey):
        # initial result is still AES encrypted.
        middleKey = self.rsaDecryptKey(writeKey)
        fileWriteEncryptionIV = middleKey[:self.initVectorSize]
        fileWriteEncryptionKey = middleKey[self.initVectorSize:]
        cipher = AES.new(fileWriteEncryptionKey, AES.MODE_CFB, fileWriteEncryptionIV)
        # returns AES decrypted fileWriteAccessKey (which is AES encrypted fileWriteKey)
        return cipher.decrypt(fileWriteAccessKey)

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
        fileContents = cipher.decrypt(encryptedFileContents)[self.junkDataSize:]

        # get unpickle metadata
        metadata = pickle.loads(pickledMetadata)
        
        if not self.validMetadata(filename, metadata):
            print "invalid metadata"

        clientFile = ClientFile.ClientFile(filename, fileContents, metadata)

        return clientFile

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
        fileWritePublicKey = metadata.fileWritePublicKey
        contentsHash = SHA256.new(contents).digest()

        if self.hasWritePermission(fileWritePublicKey, contentsHash, signature):
            # user has write permissions
            # call to server to update
            # return response-type thing
            print "Has Write Permissions!"
            pass

        # if owner, can also write metadata.

    def hasWritePermission(self, fileWritePublicKey, contentsHash, signature):
        return fileWritePublicKey.verify(contentsHash, signature)


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
        