### Test FILE
'''
Test to 
1) create a new client
2) create a new file
3) store the file via the client
4) retrieve the file via the client
5) and verify the integrity of the retrieved file contents.
'''

from client import *
import ClientFile

print "Starting test..."
# create new client
vc = VulcanClient()
vc.register("dorayuta")

testFileContents = "This is the file contents for a test file."
testFileName = "testFileName"
cf = ClientFile.ClientFile(testFileName, testFileContents)
userPermissions = {}

vc.addFile(cf, userPermissions)

getCF = vc.getFile(testFileName)

print "original file contents: " + testFileContents

print "retrieved file contents: " + getCF.contents

print "End of test."