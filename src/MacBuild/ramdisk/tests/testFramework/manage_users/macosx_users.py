"""
Cross platform user creation and management

Created for testing cross user testing for the ramdisk project, specifically
unionfs functionality.

@author: Roy Nielsen
"""
from __future__ import absolute_import

class MacOSXUsersTemplate(object):
    '''Class to manage user properties.
    
    @method findUniqueUid
    @method setUserShell
    @method setUserComment
    @method setUserUid
    @method setUserPriGid
    @method setUserHomeDir
    @method addUserToGroup
    @method rmUserFromGroup
    @method setUserPassword
    @method setUserLoginKeychainPassword
    @method createHomeDirectory
    @method rmUser
    @method rmUserHome
    
    @author: Roy Nielsen


    '''
    def __init__(self, logger, userName="", userShell="/bin/bash",
                       userComment="", userUid=0, userPriGid=20,
                       userHomeDir="/tmp"):
        self.dscl = "/usr/bin/dscl"

        if not userName:
            raise ""
        
        if not userUid or self.uidTaken():
            self.findUserUid()
        else:
            
        
        pass

    def findUniqueUid(self):
        '''We need to make sure to find an unused uid (unique ID) for the user,
           $ dscl . -list /Users UniqueID
        will list all the existing users, an unused number above 500 is good.
        
        @author: Roy Nielsen


        '''
        pass
    
    def uidTaken(self):
        '''See if the UID requested has been taken.  Only approve uid's over 1k
           $ dscl . -list /Users UniqueID
        
        @author: Roy Nielsen


        '''
        success = False
        cmd = [self.dscl, ".", "-list", "/Users", "UniqueID"]
        pass

    def setUserShell(self, user="", shell=""):
        '''dscl . -create /Users/luser UserShell /bin/bash
        
        @author: Roy Nielsen

        :param user:  (Default value = "")
        :param shell:  (Default value = "")

        '''
        pass

    def setUserComment(self, user="", comment=""):
        '''dscl . -create /Users/luser RealName "Lucius Q. User"
        
        @author: Roy Nielsen

        :param user:  (Default value = "")
        :param comment:  (Default value = "")

        '''
        pass

    def setUserUid(self, user="", uid=""):
        '''dscl . -create /Users/luser UniqueID "503"
        
        @author: Roy Nielsen

        :param user:  (Default value = "")
        :param uid:  (Default value = "")

        '''
        pass

    def setUserPriGid(self, user="", priGid=""):
        '''dscl . -create /Users/luser PrimaryGroupID 20
        
        @author: Roy Nielsen

        :param user:  (Default value = "")
        :param priGid:  (Default value = "")

        '''
        pass

    def setUserHomeDir(self, user="", userHome = ""):
        '''dscl . -create /Users/luser NFSHomeDirectory /Users/luser

        :param user:  (Default value = "")
        :param userHome:  (Default value = "")

        '''
        pass

    def addUserToGroup(self, user="", group=""):
        '''dscl . -append /Groups/admin GroupMembership luser
        
        @author: Roy Nielsen

        :param user:  (Default value = "")
        :param group:  (Default value = "")

        '''
        pass

    def rmUserFromGroup(self):
        ''' '''
        pass

    def setUserPassword(self, user="", password=""):
        '''dscl . -passwd /Users/luser password
        
        @author: Roy Nielsen

        :param user:  (Default value = "")
        :param password:  (Default value = "")

        '''
        pass

    def setUserLoginKeychainPassword(self, user="", password=""):
        '''Use the "security" command to set the login keychain.  If it has not
        been created, create the login keychain.
        
        @author: Roy Nielsen

        :param user:  (Default value = "")
        :param password:  (Default value = "")

        '''
        self.sec = "/usr/bin/security"

        #####
        # Input validation

        #####
        # Check if login keychain exists

        #####
        # if it does not exist, create it

        #####
        # else set the login keychain password

        pass

    def createHomeDirectory(self, user=""):
        '''createhomedir -c -u luser
        
        @author: Roy Nielsen

        :param user:  (Default value = "")

        '''
        pass

    def rmUser(self, user=""):
        '''

        :param user:  (Default value = "")

        '''
        pass

    def rmUserHome(self, user=""):
        '''

        :param user:  (Default value = "")

        '''
        pass
