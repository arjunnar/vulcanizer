import os

filestoreDirectory = "filestore/"

def writeFileToDisk(encryptedFile): 
    filename = filestoreDirectory + encryptedFile.encryptedName
    f = open(filename, 'w+')
    f.write(encryptedFile.encryptedContents)
    
def fileExists(encryptedFilename):
    return os.path.isfile(filestoreDirectory + encryptedFilename)

# assumes that file exists
# gets file with only read permission
# returns an instance of EncryptedFile class
def getFileFromDisk(encryptedFilename):
    f = open(filestoreDirectory + encryptedFilename, 'r') 
    encryptedContents = f.read()
    f.close()
    return EncryptedFile(encryptedFilename, encryptedContents)

# assumes that the file exists 
def deleteFileOnDisk(encryptedFilename):
    os.remove(filestoreDirectory + encryptedFilename)

# assumes that the file to rename exists
def renameFileOnDisk(oldName, newName): 
    os.rename(filestoreDirectory + oldName, filestoreDirectory + newName)

class Filestore():
    def __init__(self):
        self.fileMap = {} # Convert this to a cache later

    # Does nothing if the file already exists 
    def addFile(self, encryptedFile):
        encryptedFilename = encryptedFile.encryptedName 
        if not fileExists(encryptedFilename):
            writeFileToDisk(encryptedFile)

    # Returns None if file does not exist
    def getFile(self, encryptedFilename): 
        if not fileExists(encryptedFilename):
            return None 
        return getFileFromDisk(encryptedFilename)

    # Does nothing if file does not exist 
    def deleteFile(self, encryptedFilename):
        if not fileExists(encryptedFilename):
            return None
        deleteFileOnDisk(encryptedFilename)

    # Does nothing if the file doesn't already exist
    def updateFile(self, encryptedFilename, encryptedFile): 
        if not fileExists(encryptedFilename):
            return None
        self.deleteFile(encryptedFilename)
        self.addFile(encryptedFile)

    # Does nothing if the file to rename does not exist 
    # or if the new file name is already used 
    def renameFile(self, encryptedFilename, newEncryptedFilename):
        if not fileExists(encryptedFilename) or fileExists(newEncryptedFilename):
            return
        renameFile(encryptedFilename, newEncryptedFilename)

    """ OLD IN MEMORY CODE 
    def addFile(self, encryptedFile):
        encryptedFilename = encryptedFile.encryptedName
        if encryptedFilename in self.fileMap:
            raise Exception("File with that name already exists")
        if encryptedFilename not in self.fileMap:
            self.fileMap[encryptedFilename] = encryptedFile

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
    """
    


class EncryptedFile():
    def __init__ (self, name, contents):
        self.encryptedName = name
        self.encryptedContents = contents


            
