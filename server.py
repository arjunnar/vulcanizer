import string, cgi, time
from os import curdir, sep
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer

class FileHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        try:
	    if self.path.endswith(".html"):
		print "reading html file"
	    f = open(curdir + sep + self.path)
	    print self.path
	    self.send_response(200)
	    self.send_header('title', "yay")
	    self.end_headers()
	    self.wfile.write(f.read())
	    f.close()
	    
	    return

	except IOError:
	    self.send_error(404, "File Not Found: ")

    def do_POST(self):
	global rootnode
	try:
	    ctype, pdict = cgi.parse_header(self.headers.getheader("content-type"))
	    self.send_response(301)
	    self.end_headers()
	    upfilecontent = query.get("index.html")
	    print "filecontent"
	    self.wfile.write("<HTML>POST OK<BR><BR>");
	    self.wfile.write(upfilecontent[0]);

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
