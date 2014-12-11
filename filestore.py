import os
import DropboxClient

class Filestore():
    def __init__(self):
        self.dropboxClient = DropboxClient.DropboxClient()

    # Does nothing if the file already exists 
    def addFile(self, encryptedFile):
        self.writeFileToDropbox(encryptedFile)

    # Returns None if file does not exist, return EncryptedFilename
    def getFile(self, encryptedFilename): 
        encryptedFilename, encryptedContents = self.dropboxClient.download(encryptedFilename)
        return EncryptedFile(encryptedFilename, encryptedContents)

    # Does nothing if file does not exist 
    def deleteFile(self, encryptedFilename):
        self.dropboxClient.delete(encryptedFilename)

    # Does nothing if the file doesn't already exist
    def updateFile(self, encryptedFilename, encryptedFile): 
        self.writeFileToDropbox(encryptedFile)

    # Does nothing if the file to rename does not exist 
    # or if the new file name is already used 
    def renameFile(self, encryptedFilename, newEncryptedFilename):
        pass 

    def writeFileToDropbox(self, encryptedFile): 
        filename = encryptedFile.encryptedName
        contents = encryptedFile.encryptedContents
        self.dropboxClient.upload(filename, contents)

class EncryptedFile():
    def __init__ (self, name, contents):
        self.encryptedName = name
        self.encryptedContents = contents


            
