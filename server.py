import string, cgi, time
from os import curdir, sep
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer

class FileHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        try:
            fileContents = "hahaha"
	    # fileContents = FileStore.getFileContents(self.path)
	    self.send_response(200)
	    self.send_header('title', "yay")
	    self.end_headers()
	    self.wfile.write(fileContents)	    
	    return

	except IOError:
	    self.send_error(404, "File Not Found: ")

    def do_POST(self):
	global rootnode
	try:
	    ctype, pdict = cgi.parse_header(self.headers.getheader("content-type"))
	    self.send_response(301)
	    self.end_headers()
	    contentLength = int(self.headers.getheader('content-length', 0)) 
	    postBody = self.rfile.read(contentLength)
	    print "what's going on!?"
	    print postBody
	    # I don't knwo what query.get() is doing
	    upFileContent = query.get("index.html")
	    print postBody
	    # FileStore.store(fileName, upFileContents)
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
