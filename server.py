import string, cgi, time
from os import curdir, sep
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
from filestore import Filestore, EncryptedFile


fileStore = Filestore()
aNewFile = EncryptedFile("encryptedName", "encryptedCont")
fileStore.addFile(aNewFile)

class FileHandler(BaseHTTPRequestHandler):
    def __init__(self):
        super(FileHandler, self).__init__(self, request, client_address, server)
        self.fileSt ore = filestore.Filestore()

    def do_GET(self):
        try:
            global fileStore
            print fileStore.fileMap
            print "entering get."
            fileContents1 = "hahaha"
            # remove leading "/"
	    encFile = fileStore.getFile(self.path[1:])
	    print "AAAAAAAAAA"
	    print encFile
	    self.send_response(200)
	    self.send_header('title', "yay")
	    self.end_headers()
	    self.wfile.write(encFile.encryptedContents)	    
	    return

	except IOError:
	    self.send_error(404, "File Not Found: ")

    def do_POST(self):
	global rootnode
	try:
            global fileStore
	    ctype, pdict = cgi.parse_header(self.headers.getheader("content-type"))
	    self.send_response(301)
	    self.end_headers()
	    contentLength = int(self.headers.getheader('content-length', 0)) 
	    postBody = self.rfile.read(contentLength)
	    print "what's going on!?"
	    print postBody
	    # I don't knwo what query.get() is doing
	    # upFileContent = query.get("index.html")
	    newFile = EncryptedFile(self.path[1:], postBody)
	    fileStore.addFile(newFile)
	    self.wfile.write("<HTML>POST OK<BR><BR>");
	    self.wfile.write();
            return 
	except:
	    pass

def main(): 
    try:
	server = HTTPServer(('', 8000), FileHandler)
	print "Started fileserver..."
	server.serve_forever()
    
    except KeyboardInterrupt:
        print "^C received"
	server.socket.close()

if __name__ == "__main__":
    main()
