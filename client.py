## client-side interface

import hashlib

class VulcanClient:
    def __init__(self):
	# maps unencrypted filenames to hash of file contents
        self.fileHashesMap = {} # Convert this to a cache later
    
    def addFile(self, clientFile):
        self.addFileHash(clientFile)
        # encrypt fileName
        # encrypt fileContents
        # call to server to store file

    def addFileHash(self, clientFile):
        filename = clientFile.name
        contentsHash = hashlib.sha1(clientFile.contents)
        self.fileHashesMap[filename, contentsHash]


    def getFile(self, filename):
        # encrypt filename
        # call to server to get file contents

        # unencrypt file contents
        if !self.validContents(filename, contents):
            # raise warning - file may be corrupt.

        clientFile = ClientFile(filename, contents)    
        return clientFile


    def validContents(self, filename, contents):
        contentsHash = hashlib.sha1(contents)
        previousHash = fileHashesMap[filename]
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