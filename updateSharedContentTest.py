
### TEST FILE
# update owned file test

'''
Testing update of shared file.
'''

from client import *
import ClientFile
import globalScope

print "Starting test..."

vc1 = VulcanClient()
if not vc1.register("dorayuta"):
	vc1.login("dorayuta")

vc2 = VulcanClient()
if not vc2.register("arjunnar"):
	vc2.login("arjunnar")

arjunnarUserPublicKey = vc2.rsaPublicKey
globalScope.userPublicKeys["arjunnar"] = arjunnarUserPublicKey

print "Made clients."

testFileContents = "TEST FILE CONTENT TO BE UPDATED!"
testFilename = "File To Update"
permissionsMap = {"arjunnar": (True, True)}

print "original file contents: " + testFileContents

cf = ClientFile.ClientFile(testFilename, testFileContents)
vc1.addFile(cf, permissionsMap)

print "file added to EFS. Preparing for retrieve..."

print "getting shared file..."
encryptedTestFilename = vc1.getEncryptedFilename(testFilename)
getCF = vc2.getSharedFile(testFilename, encryptedTestFilename)


updatedFileContents = "This test file has been updated!"
updatedCF = ClientFile.ClientFile(testFilename, updatedFileContents)

print "Attempting to update file..."

vc2.updateFile(updatedCF)

print "File updated by arjunnar!"

getUCF = vc1.getFile(testFilename)

print "Updated file contents, as seen by dorayuta: " + getUCF.contents

print "End of test."