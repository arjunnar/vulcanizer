    ## client-side interface

import hashlib
import Crypto.PublicKey.RSA as RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto import Random
from Crypto.Hash import SHA256
import ClientFile
import pickle
import sqlite3
import os
import clientdb
import publicdb
import clientCrypto
from filestore import Filestore, EncryptedFile

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

        self.filestore = Filestore()
        self.publicdb = publicdb.PublicDb()
        self.userPublicKeys = None

    '''
    Code to enable dropbox support.
    '''
    def setupDropbox(self):
        pass

    '''
    returns boolean indicatign successful registration
    '''
    def register(self, username):
        if username in self.publicdb.usersList():
            print "Username already taken!"
            return False

        if self.username != None:
            print "Already registered user!"
            return False

        # need check for if user account already exists
        self.db = clientdb.ClientDb(username)
        self.db.setupAllDbs()
        
        if self.db.userExists(username):
            print "User already exists!"
            return False

        self.username = username
        self.rsaPublicKey, self.rsaPrivateKey = clientCrypto.newRSAKeyPair(self.rsaKeyBits)
        self.db.addUserDbRecord(self.username, self.rsaPublicKey, self.rsaPrivateKey)
        self.publicdb.addPublicKey(self.username, self.rsaPublicKey)
        self.userPublicKeys = self.publicdb.getPublicKeysMap()
        return True

    def login(self, username):
        self.db = clientdb.ClientDb(username)
        self.db.setupAllDbs()
        self.username, self.rsaPublicKey, self.rsaPrivateKey = self.db.getUserDbRecord(username)
        self.userPublicKeys = self.publicdb.getPublicKeysMap()

    '''
    method to generate junkData
    '''
    def getJunkData(self):
        return Random.new().read(self.junkDataSize)

    def addFile(self, clientFile, userPermissions):
        filename = clientFile.name
        contents = clientFile.contents

        if self.db.fileExists(filename):
            raise Exception("file already exists!")

        # encrypt filename
        fileEncryptionKey = clientCrypto.newAESEncryptionKey()

        # get RSA info
        fileRSAKey = clientCrypto.newRSAKey(self.rsaKeyBits)
        fileWritePublicKey, fileWritePrivateKey = clientCrypto.newRSAKeyPair(self.rsaKeyBits, fileRSAKey)
        clientFile.metadata.setFileWritePublicKey(fileWritePublicKey)

        # sign contents
        signFile = clientCrypto.rsaSign(contents, fileWritePrivateKey)
        clientFile.setWriteSignature(signFile)

        # generate another AES key to encrypt the FileWriteKey
        fileWriteEncryptionKey = clientCrypto.newAESEncryptionKey()
        fileWriteEncryptionIV = clientCrypto.newInitVector(self.initVectorSize)

        # encrypt the FileWriteKey
        cipher = AES.new(fileWriteEncryptionKey, AES.MODE_CFB, fileWriteEncryptionIV)
        fileWriteAccessKey = cipher.encrypt(fileWritePrivateKey)
        clientFile.metadata.setFileWriteAccessKey(fileWriteAccessKey)

        try:
            permissionsMap = self.generatePermissionsMap(fileEncryptionKey, fileWriteEncryptionKey, fileWriteEncryptionIV, userPermissions)
        except:
            raise Exception("Error with getting public key of person to share with")

        clientFile.setPermissionsMap(permissionsMap)

        # encrypt filename and file contents
        initVector = clientCrypto.newInitVector(self.initVectorSize)
        cipher = AES.new(fileEncryptionKey, AES.MODE_CFB, initVector)
        encryptedFilename = clientCrypto.sha1HexHash(cipher.encrypt(clientFile.name))

        metadataHash = self.getMetadataHash(clientFile.metadata)

        # update owner file records
        self.db.addFileRecord(filename, fileEncryptionKey, encryptedFilename, fileWritePrivateKey, metadataHash)

        # junk the beginning of contents

        encryptedFileContents = initVector + cipher.encrypt(self.getJunkData() + clientFile.contents)
        pickledMetadata = pickle.dumps(clientFile.metadata)
        # call to server to store file
        tupleToStore = (encryptedFileContents, signFile, pickledMetadata)
        pickledTupleToStore = pickle.dumps(tupleToStore)
        self.filestore.addFile(EncryptedFile(encryptedFilename, pickledTupleToStore))

    def generatePermissionsMap(self, fileEncryptionKey, fileWriteEncryptionKey, fileWriteEncryptionIV, userPermissions):
        permissionsMap = {}

        # generating permissionsMap from userPermissions
        for username in userPermissions:
            if username not in self.userPublicKeys:
                raise Exception("The user you want to share with has not shared his public key.")

            # check read permission r+w tuple, True/False?
            read, write = userPermissions[username]
            readKey = None
            writeKey = None
            if read:
                # RSA encode with public key
                userPublicKey = self.userPublicKeys[username]
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
        previousHash = self.db.getFileRecord(filename)[4]
        return metadataHash == previousHash

    def getSharedFile(self, filename, encryptedFilename = None):
        # use previous encryptedFilename
        if encryptedFilename == None:
            if not self.db.sharedFileExists(filename):
                print "No record of encrypted filename being shared!"
                return

            encryptedFilename = self.db.getSharedEncryptedFilename(filename)

        # call to server to get file contents
        encryptedFile = self.filestore.getFile(encryptedFilename)
        if encryptedFile is None:
            print "ERROR: cannot retrieve file."
            return
        try:
            pickledTuple = encryptedFile.encryptedContents
            unpickledTuple = pickle.loads(pickledTuple)
            encryptedFileContents, signFile, pickledMetadata = unpickledTuple

            # unpickle metadata
            metadata = pickle.loads(pickledMetadata)
        except:
            print "ERROR: unable to retrieve shared file data."
            return

        readKey, writeKey = self.getReadWriteKeys(metadata)

        if readKey == None:
            raise Exception("You don't have permission to access this file.")

        if writeKey == None:
            print "You don't have permission to edit this file."
        else:
            print "You have edit access to this file."
      
        self.db.updateSharedFileRecord(filename, encryptedFilename, readKey, writeKey)

        # unencrypt file contents
        initVector = encryptedFileContents[:self.initVectorSize]
        encryptedFileContents = encryptedFileContents[self.initVectorSize:]
        cipher = AES.new(readKey, AES.MODE_CFB, initVector)

        fileContents = cipher.decrypt(encryptedFileContents)[self.junkDataSize:]

        if not self.validSignature(metadata.fileWritePublicKey, fileContents, signFile):
            print "Invalid signature! File contents may have been tampered."
        else:
            print "Valid signature. File contents appear to be untampered."

        sharedFile = ClientFile.ClientFile(filename, fileContents, metadata)   

        return sharedFile

    def validSignature(self, publicKey, contents, signature):
        return clientCrypto.rsaVerify(contents, publicKey, signature)

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
            raise Exception("File not found.")

        filename, fileEncryptionKey, encryptedFilename, fileWritePrivateKey, metadataHash = self.db.getFileRecord(filename)

        # call to server to get file contents
        encryptedFile = self.filestore.getFile(encryptedFilename)
        
        if encryptedFile is None:
            print "ERROR: cannot retrieve file."
            return

        try:
            pickledTuple = encryptedFile.encryptedContents
            unpickledTuple = pickle.loads(pickledTuple)
            encryptedFileContents, signFile, pickledMetadata = unpickledTuple
        except: 
            print "ERROR: unable to retrieve file data."
            return

        initVector = encryptedFileContents[:self.initVectorSize]
        encryptedFileContents = encryptedFileContents[self.initVectorSize:]
        cipher = AES.new(fileEncryptionKey, AES.MODE_CFB, initVector)

        # unencrypt file contents
        fileContents = cipher.decrypt(encryptedFileContents)[self.junkDataSize:]
        print 'file contents: ' + fileContents
        
        # get unpickle metadata
        metadata = pickle.loads(pickledMetadata)
        
        if not self.validMetadata(filename, metadata):
            print "WARNING: file metadata may have been tampered."

        if not self.validSignature(metadata.fileWritePublicKey, fileContents, signFile):
            print "Invalid signature! File contents may have been tampered."

        clientFile = ClientFile.ClientFile(filename, fileContents, metadata)

        return clientFile

    '''
    assume that filename has not changed.
    '''
    def updateFile(self, clientFile, userPermissions = None):        
        filename = clientFile.name
        contents = clientFile.contents
        metadata = None

        # if owner, also update metadata.
        if self.isOwner(filename):
            metadata = clientFile.metadata
            filename, fileEncryptionKey, encryptedFilename, fileWritePrivateKey, metadataHash = self.db.getFileRecord(filename)
            
            # if permissions should change, just re-add file, because we would have to regenerate
            # AES and RSA keys for the file.
            # only change metadata if userPermissions changes.
            if userPermissions is not None:
                self.deleteFile(filename)
                self.addFile(clientFile, userPermissions)
                return
            
            else:    
                # call to server to get file contents
                pickledTuple = self.filestore.getFile(encryptedFilename).encryptedContents
                unpickledTuple = pickle.loads(pickledTuple)
                prevEncryptedFileContents, prevSignFile, prevPickledMetadata = unpickledTuple
                initVector = prevEncryptedFileContents[:self.initVectorSize]
                cipher = AES.new(fileEncryptionKey, AES.MODE_CFB, initVector)

                signFile = clientCrypto.rsaSign(contents, fileWritePrivateKey)
                print "contents to newly upload: " + fileContentstents
                # junk the beginning of contents
                newEncryptedFileContents = initVector + cipher.encrypt(self.getJunkData() + contents)

        elif self.isSharedFile(filename):
            filename, encryptedFilename, fileEncryptionKey, fileWritePrivateKey = self.db.getSharedFileRecord(filename)

            if fileWritePrivateKey == None:
                print "You don't have permission to write!"
                return

            # call to server to get file contents
            pickledTuple = self.filestore.getFile(encryptedFilename).encryptedContents
            unpickledTuple = pickle.loads(pickledTuple)
            prevEncryptedFileContents, prevSignFile, prevPickledMetadata = unpickledTuple

            initVector = prevEncryptedFileContents[:self.initVectorSize]
            cipher = AES.new(fileEncryptionKey, AES.MODE_CFB, initVector)
            
            # junk the beginning of contents
            newEncryptedFileContents = initVector + cipher.encrypt(self.getJunkData() + contents)
            metadata = pickle.loads(prevPickledMetadata)
            
            try:
                signFile = clientCrypto.rsaSign(contents, fileWritePrivateKey)
            except:
                print "Update of shared file failed."
                return 

            if not self.hasWritePermission(metadata.fileWritePublicKey, contents, signFile):
                print "You don't have permission to update file!"
                return

        else:
            print "Error: no such file exists in your EFS!"
            return

        tupleToStore = (newEncryptedFileContents, signFile, prevPickledMetadata)
        pickledTupleToStore = pickle.dumps(tupleToStore)
        self.filestore.updateFile(encryptedFilename, EncryptedFile(encryptedFilename, pickledTupleToStore))

    def hasWritePermission(self, fileWritePublicKey, contents, signature):
        return clientCrypto.rsaVerify(contents, fileWritePublicKey, signature)

    def isSharedFile(self, filename):
        return self.db.sharedFileExists(filename)

    def isOwner(self, filename):
        return self.db.fileExists(filename)

    def fileExists(self, filename):
        return self.db.fileExists(filename)

    def allUsers(self):
        return self.publicdb.usersList()

    '''
    show all files (owned and shared) in your EFS directory
    '''
    def showAllFiles(self):
        return self.db.showAllFiles()

    def renameFile(self, filename, newFilename):
        if self.isOwner(filename):
            # able to rename.
            # make a new file with the same contents, signFile, and metadata
            # delete old file, upload new file?
            encryptedFilename = self.db.getEncryptedFilename(filename)
            try:
                oldCF = self.getFile(filename)
            except Exception:
                print "Error: problem with file to update."
                return False
            
            if oldCF == None:
                print "Error: file no longer exists."
                return False

            # get previous file contents
            prevFileContents = oldCF.contents
            # create new file with new name and old contents
            newCF = ClientFile.ClientFile(newFilename, prevFileContents)
            # can't use old file metadata.
            prevMetadata = oldCF.metadata
            # use old userPermissions
            userPermissions = self.getUserPermissions(prevMetadata)
            # delete old file
            self.deleteFile(filename)
            # just re-add new file
            self.addFile(newCF, userPermissions)
            return True

        else:
            print "File does not exist, or you do not have permission to rename file."
            return False

    def getUserPermissions(self, metadata):
        permissionsMap = metadata.permissionsMap
        userPermissions = {}
        for username in permissionsMap:
            read, write = permissionsMap[username]
            if write:
                userPermissions[username] = (True, True)
            elif read:
                userPermissions[username] = (True, False)
            else:
                continue
        return userPermissions

    def deleteFile(self, filename):
        # call to server to delete for encryptedFileName
        if self.isOwner(filename):
            encryptedFilename = self.getEncryptedFilename(filename)
            self.db.deleteFileRecord(filename)
            self.filestore.deleteFile(encryptedFilename)
            return True
        else:
            print "File does not exist, or permission to delete file denied."
            return False
        
    def getEncryptedFilename(self, filename):
        try:
            return self.db.getEncryptedFilename(filename)
        except Exception:
            return None