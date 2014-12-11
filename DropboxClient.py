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

    def download(self, filename):
        f, metadata = self.client.get_file_and_metadata(filename)
        contents = f.read()
        return filename, contents

    def delete(self, filename):
        self.client.file_delete(filename)

    def rename(self, oldFilename, newFilename):
        pass
