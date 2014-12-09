
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

print "Made client."

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

noUserPerms = None

try:
	vc1.addFile(cf, noUserPerms)

except Exception:
	print ">>> Trying to add file that exists"
	print ">>> Nevermind, we'll update the file!"

"Attempting to update file..."
vc1.updateFile(updatedCF)

getUCF = vc1.getFile(testFilename)

print "Updated file contents: " + getUCF.contents

print "End of test."