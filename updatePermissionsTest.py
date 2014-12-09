
### TEST FILE
# update owned file test

'''
Testing update of file. Create a new client, create a file, upload a file, and edit the file.
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
permissionsMap = {}

print "original file contents: " + testFileContents

cf = ClientFile.ClientFile(testFilename, testFileContents)
vc1.addFile(cf, permissionsMap)

print "file added to EFS. Preparing for retrieve..."

getFile = vc1.getFile(testFilename)

print "Retrieved file contents: " + getFile.contents

print "Still to update file..."

updatedFileContents = "This test file has been updated!"
updatedCF = ClientFile.ClientFile(testFilename, updatedFileContents)

newUserPerms = {"arjunnar": (True, False)}

try:
	vc1.addFile(cf, newUserPerms)

except Exception:
	print ">>> Trying to add file that exists"
	print ">>> Nevermind, we'll update the file!"

"Attempting to update file..."
vc1.updateFile(updatedCF, newUserPerms)

try:
	getUCF = vc2.getFile(testFilename)
except Exception:
	print ">>> arjunnar should not be able to just 'getFile'. He should 'getSharedFile'"

try:
	getUCF = vc2.getSharedFile(testFilename)
except Exception:
	print ">>> arjunnar can't get shared file without the encrypted name."

encryptedTestFilename = vc1.getEncryptedFilename(testFilename)
getUCF = vc2.getSharedFile(testFilename, encryptedTestFilename)

print "Updated file contents, as seen by arjunnar: " + getUCF.contents

print "End of test."