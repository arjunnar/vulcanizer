class Filestore():
    def __init__(self):
        self.fileMap = {} # Convert this to a cache later

    def addFile(self, encryptedFile):
        encryptedFilename = encryptedFile.encryptedName
        if encryptedFilename in self.fileMap:
            raise Exception("File with that name already exists")
        if encryptedFilename not in self.fileMap:
            self.fileMap[encryptedFilename] = encryptedFile
        # Need to put the file contents on disk

    def getFile(self, encryptedFilename):
        if encryptedFilename not in self.fileMap:
            return None
        return self.fileMap[encryptedFilename]

    def deleteFile(self, encryptedFilename):
        if encryptedFilename in self.fileMap:
            del self.fileMap[encryptedFilename]

    def updateFile(self, encryptedFilename, encryptedFile):
        if encryptedFilename in self.fileMap:
            self.fileMap[encryptedFilename] = encryptedFile

    def renameFile(self, encryptedFilename, newEncryptedFilename):
        if encryptedFilename not in self.fileMap:
            raise Exception("File to rename does not exist")
        if newEncryptedFilename in self.fileMap:
            raise Exception("New filename already exists")
        fileObj = self.fileMap[encryptedFilename]
        self.fileMap[newEncryptedFilename] = fileObj
        
class EncryptedFile():
    def EncryptedFile(name, contents):
        self.encryptedName = name
        self.encryptedContents = contents
        
            
            
