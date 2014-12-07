## client-side interface

import hashlib
import Crypto.PublicKey.RSA as RSA
from Crypto.Cipher import AES
from Crypto import Random
import ClientFile
import pickle
from Crypto.Cipher import PKCS1_OAEP
from globalScope import *
from base64 import *


class VulcanClient:
    def __init__(self, username):
	   # maps unencrypted filenames to hash of file contents
        self.fileHashesMap = None
        self.fileKeysMap = None
        # map of (shared) filename to encrypted filename 
        self.sharedFilenamesMap = None
        self.rsaPublicKey = None
        self.rsaPrivateKey = None
        self.username = username
        self.rsaKeyBits = 2048
        self.register(username)
    
    def register(self, username):
        self.fileHashesMap = {} # Convert this to a cache later
        self.fileKeysMap = {}
        self.sharedFilenamesMap = {}
        self.rsaPublicKey, self.rsaPrivateKey = self.newRSAKeyPair()

    def newRSAKeyPair(self):
        newKey = RSA.generate(self.rsaKeyBits)
        publicKey = newKey.publickey().exportKey("PEM")
        privateKey = newKey.exportKey("PEM")
        return (publicKey, privateKey)

    def newFileEncryptionKey(self):
        newRandomKey = b'0123456789abcdef'
        # Random.getrandbits(16)
        return newRandomKey

    def addFile(self, clientFile, userPermissions):
        self.addFileHash(clientFile)
        fileEncryptionKey = self.newFileEncryptionKey()
        print fileEncryptionKey
        self.fileKeysMap[clientFile.name] = fileEncryptionKey

        permissionsMap = self.generatePermissionsMap(fileEncryptionKey, userPermissions)
        clientFile.userPermissionsMap(permissionsMap)

        # encrypt fileName
        # encrypt fileContents
        global initVector
        cipher = AES.new(fileEncryptionKey, AES.MODE_CFB, initVector)

        encFileName = b64encode(initVector + cipher.encrypt(clientFile.name)).decode(encoding='utf-8')
        encFileContents = b64encode(initVector + cipher.encrypt(clientFile.contents)).decode(encoding='utf-8')
        pickledMetadata = pickle.dumps(clientFile.permissionsMap)

        # call to server to store file
        global MockServer
        MockServer[encFileName] = encFileContents, pickledMetadata

    def generatePermissionsMap(self, fileEncryptionKey, userPermissions):
        permissionsMap = {}

        for user in userPermissions:
            # check read permission r+w tuple
            if userPermissions[user][0]:
                # RSA encode with public key
                userPublicKey = userPublicKeys[user]
                readKey = self.makeReadKey(userPublicKey, fileEncryptionKey)
                permissionsMap[user] = (readKey, None)

        return permissionsMap


    def addFileHash(self, clientFile):
        filename = clientFile.name
        contentsHash = hashlib.sha1(clientFile.contents)
        self.fileHashesMap[filename] = contentsHash


    def getSharedFile(self, filename, encryptedFilename = None):
        if encryptedFilename == None:
            if filename in self.sharedFilenamesMap:
                encryptedFilename = self.sharedFilenamesMap[fileName]
            else:
                raise Exception("File not shared with you!")
        else:
            self.sharedFilenamesMap[filename] = encryptedFilename

        # call to server to get file contents
        global MockServer
        encFileContents, pickledMetadata = MockServer[encryptedFilename]

        # get unpickle metadata
        permissionsMap = pickle.loads(pickledMetadata)
        readKey, writeKey = permissionsMap[self.username]

        if readKey == None:
            raise Exception("")
        else:
            fileEncryptionKey = self.getReadKey(readKey)
            print fileEncryptionKey

        # unencrypt file contents
        global initVector
        cipher = AES.new(fileEncryptionKey, AES.MODE_CFB, initVector)

        fileContents = cipher.decrypt(b64decode(encFileContents[16:])).decode(encoding='utf-8')
        
        clientFile = ClientFile.ClientFile(filename, fileContents, permissionsMap)   

        return clientFile


    def makeReadKey(self, userPublicKey, encryptionKey):
        rsakey = RSA.importKey(userPublicKey)
        rsakey = PKCS1_OAEP.new(rsakey)
        encrypted = rsakey.encrypt(encryptionKey)
        return encrypted

    def getReadKey(self, readKey):
        # use RSA keys to extract AES file encryption key from readKey
        rsakey = RSA.importKey(self.rsaPrivateKey)
        rsakey = PKCS1_OAEP.new(rsakey)
        decrypted = rsakey.decrypt(readKey)
        return decrypted


    def getOwnFile(self, filename):
        if filename not in self.fileKeysMap:
            raise Exception("File not owned, possibly shared.")

        # encrypt filename
        fileEncryptionKey = self.fileKeysMap[filename]
        
        global initVector
        cipher = AES.new(fileEncryptionKey, AES.MODE_CFB, initVector)
        encFileName = b64encode(initVector + cipher.encrypt(filename)).decode(encoding='utf-8')

        # call to server to get file contents
        global MockServer
        encFileContents, pickledMetadata = MockServer[encFileName]

        # unencrypt file contents
        fileContents = cipher.decrypt(b64decode(encFileContents[16:])).decode(encoding='utf-8')

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
        encryptFilename = encryptedFilename(filename)
        # call to server to delete for encryptedFileName
        # return response-type thing
        del self.fileHashesMap[fileName]

        return 

    def updateFile(self, clientFile):
        self.addFileHash(clientFile)
        contents = clientFile.contents
        filename = clientFile.name
        encryptFilename = encryptFilename(filename)
        encryptedFileContents = encryptFileContents(contents)

        # call to server to update
        # return response-type thing


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

    def decryptFileContents(encryptedFileContents):
        return fileContents

    def generateEncryptionKey():
        pass
        