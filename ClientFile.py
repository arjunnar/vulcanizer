# client file object


class ClientFile:
    def __init__ (self, name, contents, permissionsMap = None):
        self.name = name
        self.contents = contents
        self.permissionsMap = {} if permissionsMap == None else permissionsMap


    def addPermission(self, username, readKey, writeKey):
    	# readKey and writeKey are userRSAKey encryptions of the AES fileEncryptionKey
    	self.permissionsMap[username] = (readKey, writeKey)

    def userPermissionsMap(self, permissionsMap):
    	self.permissionsMap = permissionsMap

    def getPermission(self, username):
    	return self.permissionsMap[username]

