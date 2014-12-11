### CONNECT TO DROPBOX

# Include the Dropbox SDK
import dropbox
from Tkinter import Tk

class DropboxClient():
    def __init__(self):
        # DANGEROUS read dropbox access token
        f = open('dropbox.secret', 'r') 
        access_token = f.readline().strip()
        f.close()
        self.client = dropbox.client.DropboxClient(access_token)

    def upload(self, filename, contents):
        response = self.client.put_file(filename, contents, overwrite=True)

    def download(self, filename, read=True):
        f, metadata = self.client.get_file_and_metadata(filename)
        if read:
            contents = f.read()
        else:
            contents = f
        return filename, contents

    def replace(self, localName, remoteName):
        out = open(localName, 'wb')
        f, metadata = self.client.get_file_and_metadata(remoteName)
        out.write(f.read())
        out.close()

    def delete(self, filename):
        self.client.file_delete(filename)

    def rename(self, oldFilename, newFilename):
        pass
