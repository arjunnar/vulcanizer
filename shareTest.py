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
vc1 = VulcanClient()
vc1.register("dorayuta")
vc2 = VulcanClient()
vc2.register("arjunnar")

print "Made clients."

dorayutaRSAPublicKey = vc1.rsaPublicKey
arjunnarRSAPublicKey = vc2.rsaPublicKey
globalScope.userPublicKeys["arjunnar"] = arjunnarRSAPublicKey
globalScope.userPublicKeys["dorayuta"] = dorayutaRSAPublicKey

testFileContents = "aaaabbbbccccdddd this is the rest of the file contents."
testFilename = "testFileName"
permissionMap = {"arjunnar": (True, None)}

cf = ClientFile.ClientFile(testFilename, testFileContents)
vc1.addFile(cf, permissionMap)# encrypt filename

# get encrypted file name
encryptedFilename = vc1.encryptedFilenamesMap[testFilename]

sharedFile = vc2.getSharedFile(testFilename, encryptedFilename)

print "original file contents: " + testFileContents

print "shared file contents: " + sharedFile.contents

print "End of test."