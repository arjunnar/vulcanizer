### TEST FILE
'''
Testing sharing of file.
'''

from client import *
import ClientFile
import globalScope

print "Starting test..."
# create new clients
# yuta wants to share a file with arjun


vc1 = VulcanClient()
if not vc1.register("dorayuta"):
	vc1.login("dorayuta")
vc2 = VulcanClient()
if not vc2.register("arjunnar"):
	vc2.login("arjunnar")

print "Made clients."

dorayutaRSAPublicKey = vc1.rsaPublicKey
arjunnarRSAPublicKey = vc2.rsaPublicKey

globalScope.userPublicKeys["arjunnar"] = arjunnarRSAPublicKey
globalScope.userPublicKeys["dorayuta"] = dorayutaRSAPublicKey

arjunnarRSAPrivateKey = vc2.rsaPrivateKey

testFileContents = "aaaabbbbccccdddd this is the rest of the file contents."
testFilename = "testFileName"
permissionsMap = {"arjunnar": (True, None)}

print "original file contents: " + testFileContents

cf = ClientFile.ClientFile(testFilename, testFileContents)
vc1.addFile(cf, permissionsMap)

# get encrypted file name
encryptedFilename = vc1.encryptedFilenamesMap[testFilename]

sharedFile = vc2.getSharedFile(testFilename, encryptedFilename)

print "shared file contents: " + sharedFile.contents


print "End of test."