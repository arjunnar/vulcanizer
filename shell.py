import cmd
from ClientFile import ClientFile
import os
from ast import literal_eval as make_tuple
from client import VulcanClient
import subprocess
from Tkinter import Tk

class Shell(cmd.Cmd):
    
    def __init__(self):
        self.loggedIn = False
        self.username = None
        cmd.Cmd.__init__(self)
        cmd.Cmd.prompt = '~$ '
        self.clientObj = None
    
    """ PUBLIC API """
    # opens a new notepad with given filename
    def do_create_file(self, filename):
        if not self.checkLogin():
            return
        userDir = os.getcwd() + "\\client\\" + self.username + "\\"
        openFileCommand = ['notepad', filename]
        try:
            process = subprocess.Popen(openFileCommand, stdout=subprocess.PIPE, cwd=userDir)
            output = process.communicate()[0]
        except:
            print "Error opening file."
        return

    def do_list_users(self, line):
        if not self.checkLogin():
            return
        for username in self.clientObj.allUsers():
            print username

    def do_edit_file(self, filename):
        if not self.checkLogin():
            return
        self.do_create_file(filename)

    def do_greet(self, line):
        print "Welcome to our Encrypted File System"

    def do_EOF(self, line):
        return True
    def do_delete_file(self, f):
        if not self.loggedIn:
            print 'Must login or register'
            return
        
        if f == '':
            print 'Error: Must specify a file to delete'
            return

        filename = self.userDirectory + f
        try:
            os.remove(filename)
        except:
            print "No local file to remove, removing remote file..."
            
        # Call client's delete file code
        if self.clientObj.deleteFile(f):
            print "Delete was successful."
            return
        else:
            print "Delete was unsuccessful."
    
    def do_download_file(self, f):
        if not self.loggedIn:
            print 'Must login or register'
            return

        if f == '':
            print 'Error: Must specify a file to get from the server'
            return

        #clientFile = self.clientObj.downloadFile(f)
        args = f.split()
        f = args[0]
        hashed = None
        if len(args) == 2:
            hashed = args[1]

        if self.clientObj.isOwner(f):
            clientFile = self.clientObj.getFile(f)

        elif self.clientObj.isSharedFile(f):
            try:
                clientFile = self.clientObj.getSharedFile(f, hashed)
            except Exception:
                print"Permission denied"
                return

        else:
            eName = raw_input("To access a shared file, please enter the encrypted filename: ")
            eName = eName.strip()
            print eName
            
            try:
                clientFile = self.clientObj.getSharedFile(f, eName)
            
            except:
                print "Permission denied"
                return  

            if clientFile is None:
                print "file not shared."
                return

        if clientFile is None:
            print "Unable to retrieve file data."
            return

        self.writeFileToDisk(clientFile)        
    
    def do_exit(self, line):
        return True

    def do_get_eName(self, f):
        # clipboard help
        eName = self.clientObj.getEncryptedFilename(f)
        if eName == None:
            print "No such file."
        else:
            self.copyToClipboard(eName)
            print eName

    def do_list_files(self, line):
        if not self.checkLogin():
            return
        for f in self.clientObj.showAllFiles():
            print f
        return

    def do_login(self, username):
        if username == '':
            print 'Cannot have an empty username'
        
        if self.username == username:
            print 'That user is already logged in'
            return
        
        if not os.path.isdir('client/' + username):
            print 'Error: User does not exist. Use register instead'
            return
        
        self.username = username
        self.userDirectory = 'client/' + username + '/'
        self.loggedIn = True
        
        self.clientObj = VulcanClient()
        self.clientObj.login(username)
        
    def do_logout(self, line):
        if self.username == None:
            print 'No user logged in.'
            return
        self.username = None
        self.loggedIn = False
        print 'Successfully logged out.'
        return
    
    def do_ls(self, line):
        if not self.checkLogin():
            return

        userDir = os.getcwd() + '\\client\\' + self.username
        for filename in os.listdir(self.userDirectory):
            if filename != 'db':
                print filename
        return

    def do_register(self, username):
        if os.path.isdir('client/' + username):
            print 'Error: User already exists. Use login instead'
            return
        
        self.username = username
        self.userDirectory = 'client/' + username + '/'
        os.mkdir(self.userDirectory)
        self.loggedIn = True

        self.clientObj = VulcanClient()
        self.clientObj.register(username)

    def do_rename_file(self, line):
        if not self.checkLogin():
            return

        oldFilename, newFilename = line.split()

        if oldFilename == '' or newFilename == '':
            print 'Error: Usage is rename_file oldname.file newname.file'
            return
        
        # Call client's rename code
        if not self.clientObj.renameFile(oldFilename, newFilename):
            print 'Error renaming file.'
            return

        print 'Successfully renamed file.'
   
    def do_rm(self, f):
        filename = self.userDirectory + f
        os.remove(filename)
        return

    def do_status(self, line):
        if self.username:
            print "user: " + self.username
            self.do_ls(line)
        else:
            print "No user logged in."
    
    def do_update_file(self, f):
        if not self.loggedIn:
            print 'Must login or register'
            return

        if f == '':
            print 'Error: Must specify a file to update'
            return

        if not os.path.isfile(self.userDirectory + f):
            print 'File to upload does not exist in your EFS directory'
            return

        path = self.userDirectory + f
        fileContents = self.extractFileContents(path)

        # BUG - if user doesn't own the file, just pass along an Empty permissions map

        # Get the permissions for sharing the file
        # should try to change, not redo
        owner = self.clientObj.isOwner(f)
        permissionsMap = {}
        while (owner): 
            s = raw_input("Enter userToShareWith,permission. Type DONE when you are finished.\n-->  ")
            if s == 'DONE':
                break
            splitS = s.split(',')
            if len(splitS) != 2:
                print "Wrong number of args: enter 'username, permission'."
            else:
                sharedUser = splitS[0].strip()
                permission = splitS[1].strip()

                # Will replace existing permission for user
                permissionsMap[sharedUser] = permission

        # debugging
        print permissionsMap
        correctPermsMap = self.processPermsMap(permissionsMap)
            
        clientFile = ClientFile(f, fileContents)
        print 'File contents in shell before upload: ' + fileContents
        self.clientObj.updateFile(clientFile, correctPermsMap)        
    
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

        path = self.userDirectory + f
        fileContents = self.extractFileContents(path)

        if self.clientObj.fileExists(f):
            print "File already exists!"
            return
        
        # Get the permissions for sharing the file
        permissionsMap = {}
        while (True): 
            s = raw_input("Enter userToShareWith, permission. Type DONE when you are finished.\n-->  ")
            if s == 'DONE':
                break
            splitS = s.split(',')
            if len(splitS) != 2:
                print "Wrong number of args: enter 'username, permission'."
            else:
                sharedUser = splitS[0].strip()
                permission = splitS[1].strip()

                # Will replace existing permission for user
                permissionsMap[sharedUser] = permission

        # Just for debugging 
        print permissionsMap
        
        correctPermsMap = self.processPermsMap(permissionsMap)   
        clientFile = ClientFile(f, fileContents)
        print 'File contents in shell before upload: ' + fileContents
        self.clientObj.addFile(clientFile, correctPermsMap)

    """ HELPER METHODS """
    def checkLogin(self):
        if self.loggedIn:
            return True
        print 'Must login or register'
        return False

    def extractFileContents(self, path):
        f = open(path, 'r')
        unencryptedContents = f.read()
        f.close()
        return unencryptedContents

    def writeFileToDisk(self, clientFile):
        filename = self.userDirectory + clientFile.name

        if os.path.isfile(filename):
            os.remove(filename)
            
        f = open(filename, 'w+')
        f.write(clientFile.contents)

    def processPermsMap(self, permsMap):
        newPermsMap = {}
        for user in permsMap:
            perm = permsMap[user]
            if perm == 'R':
                newPermsMap[user] = (True, False)
            elif perm == 'W':
                newPermsMap[user] = (True, True)
        return newPermsMap

    def copyToClipboard(self, toCopy):
        tk = Tk()
        tk.withdraw()
        tk.clipboard_clear()
        tk.clipboard_append(toCopy)
        tk.destroy()

if __name__ == '__main__':
    Shell().cmdloop()
