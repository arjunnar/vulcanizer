# client file object


class ClientFile:
    def __init__ (self, name, contents, metadata = None):
        self.name = name
        self.contents = contents
        self.metadata = ClientFileMetaData()
        if metadata != None:
            self.metadata = metadata

    def addPermission(self, username, readKey, writeKey):
    	# readKey and writeKey are userRSAKey encryptions of the AES fileEncryptionKey
    	self.metadata.addPermission(username, readKey, writeKey)

    def setPermissionsMap(self, permissionsMap):
    	self.metadata.setPermissionsMap(permissionsMap)

    def getPermission(self, username):
    	return self.metadata.getPermission(username)

    def setSignature(self, signature):
    	self.metadata.setSignature(signature)

    def setAccessKey(self, key):
    	self.metadata.setAccessKey(key)


class ClientFileMetaData:
    def __init__(self):
        # AES key for permissions.
        self.accessKey = None
        self.fileWriteKey = None
        self.permissionsMap = {}

    def addPermission(self, username, readKey, writeKey):
        # readKey and writeKey are userRSAKey encryptions of the fileRead and fileWrite keys
        self.permissionsMap[username] = (readKey, writeKey)

    def setPermissionsMap(self, permissionsMap):
    	self.permissionsMap = permissionsMap

    def getPermission(self, username):
    	return self.permissionsMap[username]

    def setAccessKey(self, key):
    	self.accessKey = key

    def setFileWriteKey(self, key):
        self.fileWriteKey = key



