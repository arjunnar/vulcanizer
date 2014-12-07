### TESTING FILE

from client import *
import ClientFile

print "Starting test..."
# create new client
vc = VulcanClient("dorayuta")

testFileContents = "This is the file contents for a test file."
testFileName = "testFileName"
cf = ClientFile.ClientFile(testFileName, testFileContents)

vc.addFile(cf)

getCF = vc.getFile(testFileName)

print "original file contents: " + testFileContents

print "retrieved file contents: " + getCF.contents

print "End of test."