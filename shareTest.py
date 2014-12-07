### TEST FILE
'''
Testing sharing of file.
'''

from client import *
import ClientFile
import globalScope

print "Starting test..."
# create new clients
# arjun wants to share a file with yuta
vc1 = VulcanClient("dorayuta")
vc2 = VulcanClient("arjunnar")

print "Made clients."

dorayutaRSAPublicKey = vc1.rsaPublicKey
arjunnarRSAPublicKey = vc2.rsaPublicKey
globalScope.userPublicKeys["arjunnar"] = arjunnarRSAPublicKey
globalScope.userPublicKeys["dorayuta"] = dorayutaRSAPublicKey

testFileContents = "aaaabbbbccccdddd"
testFileName = "testFileName"
permissionMap = {"arjunnar": (True, None)}

cf = ClientFile.ClientFile(testFileName, testFileContents)
vc1.addFile(cf, permissionMap)# encrypt filename

# get encrypted file name
fileEncryptionKey = vc1.fileKeysMap[testFileName]
cipher = AES.new(fileEncryptionKey, AES.MODE_CFB, globalScope.initVector)
# encrypt testFileName
encFilename = b64encode(globalScope.initVector + cipher.encrypt(testFileName))

getCF = vc2.getSharedFile(testFileName, encFilename)

print "original file contents: " + testFileContents

print "shared file contents: " + getCF.contents

print "End of test."