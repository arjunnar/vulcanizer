## client-side interface

import hashlib
import Crypto.PublicKey.RSA as RSA
from Crypto.Cipher import AES
from Crypto import Random
import ClientFile


MockServer = {}
initVector = Random.new().read(AES.block_size)

class VulcanClient:
    def __init__(self, username):
	# maps unencrypted filenames to hash of file contents
        self.fileHashesMap = None
        self.fileKeysMap = None
        self.rsaPublicKey = None
        self.rsaPrivateKey = None
        self.username = username
        self.rsaKeyBits = 2048
        self.register(username)
    
    def register(self, username):
        self.fileHashesMap = {} # Convert this to a cache later
        self.fileKeysMap = {}
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

    def addFile(self, clientFile):
        self.addFileHash(clientFile)
        fileEncryptionKey = self.newFileEncryptionKey()
        self.fileKeysMap[clientFile.name] = fileEncryptionKey

        # encrypt fileName
        # encrypt fileContents
        global initVector
        cipher = AES.new(fileEncryptionKey, AES.MODE_CFB, initVector)

        encFileName = cipher.encrypt(clientFile.name)
        encFileContents = cipher.encrypt(clientFile.contents)

        # call to server to store file
        global MockServer
        MockServer[encFileName] = encFileContents

    def addFileHash(self, clientFile):
        filename = clientFile.name
        contentsHash = hashlib.sha1(clientFile.contents)
        self.fileHashesMap[filename] = contentsHash


    def getFile(self, filename):
        # encrypt filename
        fileEncryptionKey = self.fileKeysMap[filename]
        global initVector
        cipher = AES.new(fileEncryptionKey, AES.MODE_CFB, initVector)
        encFileName = cipher.encrypt(filename)

        # call to server to get file contents
        global MockServer
        encFileContents = MockServer[encFileName]

        # unencrypt file contents
        fileContents = cipher.decrypt(encFileContents)

        if not self.validContents(filename, fileContents):
            # raise warning - file may be corrupt.
            pass

        clientFile = ClientFile.ClientFile(filename, fileContents)    
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
        