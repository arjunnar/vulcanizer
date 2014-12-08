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
permissionsMap = {"arjunnar": (True, True)}

print "original file contents: " + testFileContents

cf = ClientFile.ClientFile(testFilename, testFileContents)
vc1.addFile(cf, permissionsMap)

# get encrypted file name
encryptedFilename = vc1.encryptedFilenamesMap[testFilename]

sharedFile = vc2.getSharedFile(testFilename, encryptedFilename)

print "shared file contents: " + sharedFile.contents

print "shared contents are same as original: " + str(sharedFile.contents == testFileContents)

newFileContents = "aaaabbbbccccddd these are the new file contents."


print "Starting write to file...."



print "End of test."