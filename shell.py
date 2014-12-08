import cmd
import ClientFile
import os

# Files must be in client/[user] for them to be in the encrypted file system
class Shell(cmd.Cmd):
    
    def __init__(self):
        self.loggedIn = False
        self.username = None
        cmd.Cmd.__init__(self)
        cmd.Cmd.prompt = '$  '

    """ PUBLIC API """
    def do_greet(self, line):
        print "hello"

    def do_EOF(self, line):
        return True
    
    def do_login(self, username):
        if self.username == username:
            print 'That user is already logged in'
            return
        
        if not os.path.isdir('client/' + username):
            print 'Error: User does not exist. Use register instead'
            return
        
        self.username = username
        self.loggedIn = True

    def do_register(self, username):
        if os.path.isdir('client/' + username):
            print 'Error: User already exists. Use login instead'
            return
        
        self.username = username
        self.userDirectory = 'client/' + username + '/'
        os.mkdir(self.userDirectory)
        self.loggedIn = True
    
    def do_upload_file(self, f):
        if not self.loggedIn:
            print 'Must login or register'
            return
        
        if f == '':
            print 'Error: Must specify a file to upload. File must be in your EFS directory'
            return
            
        if not os.path.isfile(self.userDirectory + f):
            print 'File to upload does not exist in your EFS directory'
            return

        # Call client's upload code
        
    def do_update_file(self, f):
        if not self.loggedIn:
            print 'Must login or register'
            return

        if f == '':
            print 'Error: Must specify a file to update'
            return

        # Call client's update file code

    def do_delete_file(self, f)"
        if not self.loggedIn:
            print 'Must login or register'
            return
        
        if f == '':
            print 'Error: Must specify a file to delete'
            return

        # Call client's delete file code

    def do_get_file_from_server(self, f):
         if not self.loggedIn:
            print 'Must login or register'
            return

        if f == '':
            print 'Error: Must specify a file to get from the server'
            return

        # Call client's get_file code

    def do_rename_file(self, oldFileName, newFileName):
        if oldFileName == '' or newFileName == '':
            print 'Error: Usage is rename_file oldname.file newname.file'
            return

        # Call client's rename code
            
    """ HELPER METHODS """
    def extractFileContents(self, path):
        f = open(path, 'r')
        unencryptedContents = f.read()
        return unencryptedContents

if __name__ == '__main__':
    Shell().cmdloop()
