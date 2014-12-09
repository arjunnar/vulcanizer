# delete file test

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

testFileContents = "CONTENTS OF FILE TO BE DELETED!"
testFilename = "File To Delete"
permissionsMap = {"arjunnar": (True, True)}

cf = ClientFile.ClientFile(testFilename, testFileContents)
vc1.addFile(cf, permissionsMap)

# delete file
vc1.deleteFile(testFilename)

try:
	vc1.getFile(testFilename)

except Exception:
	print "File should no longer exist."


