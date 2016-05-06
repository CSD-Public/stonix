"""
Factory object that will instanciate the appropriate user management class for
the appropriate environment/OS.

@author: Roy Nielsen
"""
import sys

from src.tests.lib.logdispatcher_lite import LogDispatcher
from src.tests.lib.logdispatcher_lite import LogPriority as lp
from src.tests.lib.libHelperExceptions import UnsupportedOsError

class ManageUser(object):
    """
    """

    #----------------------------------------------------------------------

    def __init__(self, logger=False):
        """
        Class initialization method
        """
        self.logger = logger
        self.logger.log(lp.INFO, "Logger: " + str(self.logger))

        if sys.platform.lower() == "darwin":
            from src.tests.lib.manage_user.macos_user import MacOSUser
            self.userMgr = MacOSUser()
        else:
            raise UnsupportedOsError("This operating system is not supported...")

    #----------------------------------------------------------------------
    # Getters
    #----------------------------------------------------------------------

    def findUniqueUid(self):
        """
        Find an unused uid (unique ID) for the user, this method will list all
        the existing users, an unused number above 1000 is good.

        @author: Roy Nielsen
        """
        retval = False
        retval = self.userMgr.findUniqueUid()
        return retval

    #----------------------------------------------------------------------

    def uidTaken(self, uid):
        """
        See if the UID requested has been taken.  Only approve uid's over 1k

        @author: Roy Nielsen
        """
        retval = False
        retval = self.userMgr.uidTaken(uid)
        return retval

    #----------------------------------------------------------------------
    # Setters
    #----------------------------------------------------------------------

    def createStandardUser(self, userName, password):
        """
        Creates a user that has the "next" uid in line to be used, then puts
        in in a group of the same id.  Uses /bin/bash as the standard shell.
        The userComment is left empty.  Primary use is managing a user
        during test automation, when requiring a "user" context.

        It does not set a login keychain password as that is created on first
        login to the GUI.

        @author: Roy Nielsen
        """
        retval = False
        retval = self.userMgr.createStandardUser(userName, password)
        return retval

    #----------------------------------------------------------------------

    def getUser(self, userName=""):
        """
        Get information about the passed in user.
        """
        retval = False
        retval = self.userMgr.getUser(userName)
        return retval

    #----------------------------------------------------------------------

    def getUserShell(self, userName=""):
        """
        Retrieve the passed in user's shell.
        """
        retval = False
        retval = self.userMgr.getUserShell(userName)
        return retval

    #----------------------------------------------------------------------

    def getUserComment(self, userName=""):
        """
        Retrieve the passed in user's "user comment", or real name.
        """
        retval = False
        retval = self.userMgr.getUserComment(userName)
        return retval

    #----------------------------------------------------------------------

    def getUserUid(self, userName=""):
        """
        Retrieve the passed in user's UID.
        """
        retval = False
        retval = self.userMgr.getUserUid(userName)
        return retval

    #----------------------------------------------------------------------

    def getUserPriGid(self, userName=""):
        """
        Retrieve the passed in user's primary GID
        """
        retval = False
        retval = self.userMgr.getUserPriGid(userName)
        return retval

    #----------------------------------------------------------------------

    def getUserHomeDir(self, userName=""):
        """
        Retrieve the passed in user's home directory
        """
        retval = False
        retval = self.userMgr.getUserHomeDir(userName)
        return retval

    #----------------------------------------------------------------------

    def isUserInstalled(self, user=""):
        """
        Check if the user "user" is installed on the system.

        @author Roy Nielsen
        """
        retval = False
        retval = self.userMgr.isUserInstalled(user)
        return retval

    #----------------------------------------------------------------------

    def isUserInGroup(self, userName="", groupName=""):
        """
        Check if this user is in this group

        @author: Roy Nielsen
        """
        retval = False
        retval = self.userMgr.isUserInGroup(userName, groupName)
        return retval

    #----------------------------------------------------------------------

    def validateUser(self, userName=False, userShell=False, userComment=False,
                     userUid=False, userPriGid=False, userHomeDir=False):
        """
        Future functionality... validate that the passed in parameters to the
        class instanciation match.

        @author:
        """
        retval = False
        retval = self.userMgr.validateUser(userName, userShell, userComment,
                                           userUid, userPriGid, userHomeDir)
        return retval

    #----------------------------------------------------------------------
    # Setters
    #----------------------------------------------------------------------
    
    def createBasicUser(self, userName=""):
        """
        Create a username with just a moniker.  Allow the system to take care of
        the rest.

        Only allow usernames with letters and numbers.
        (see ParentManageUser regex for allowable characters)

        @author: Roy Nielsen
        """
        retval = False
        retval = self.userMgr.createBasicUser(userName)
        return retval

    #----------------------------------------------------------------------

    def setUserShell(self, user="", shell=""):
        """
        Set a user's shell

        (see ParentManageUser regex for allowable characters)

        @author: Roy Nielsen
        """
        retval = False
        retval = self.userMgr.setUserShell(user, shell)
        return retval

    #----------------------------------------------------------------------

    def setUserComment(self, user="", comment=""):
        """
        Set the "user comment" field that normally holds the user's real name

        (see ParentManageUser regex for allowable characters)

        @author: Roy Nielsen
        """
        retval = False
        retval = self.userMgr.setUserComment(user, comment)
        return retval

    #----------------------------------------------------------------------

    def setUserUid(self, user="", uid=""):
        """
        Set the user UID on the system.

        @author: Roy Nielsen
        """
        retval = False
        retval = self.userMgr.setUserUid(user, uid)
        return retval

    #----------------------------------------------------------------------

    def setUserPriGid(self, user="", priGid=""):
        """
        Set the user's primary group ID on the system.

        @author: Roy Nielsen
        """
        retval = False
        retval = self.userMgr.setUserPriGid(user, priGid)
        return retval

    #----------------------------------------------------------------------

    def setUserHomeDir(self, user="", userHome=""):
        """
        Create a "local" home directory.  This may or may not create the user's
        home directory from the system's user template/skel for standard user
        settings.

        @author: Roy Nielsen
        """
        retval = False
        retval = self.userMgr.setUserHomeDir(user, userHome)
        return retval

    #----------------------------------------------------------------------

    def createHomeDirectory(self, user=""):
        """
        Create a "local" home directory.

        This should use the system "User Template" or "/etc/skel" for standard
        system user settings.

        @author: Roy Nielsen
        """
        retval = False
        retval = self.userMgr.createHomeDirectory(user)
        return retval

    #----------------------------------------------------------------------

    def addUserToGroup(self, user="", group=""):
        """
        Add a user to a group, not their primary group.

        @author: Roy Nielsen
        """
        retval = False
        retval = self.userMgr.addUserToGroup(user, group)
        return retval

    #----------------------------------------------------------------------

    def setUserPassword(self, user="", password=""):
        """
        Set a user's password.

        @author: Roy Nielsen
        """
        retval = False
        retval = self.userMgr.setUserPassword(user, password)
        return retval

    #----------------------------------------------------------------------

    def rmUser(self, user=""):
        """
        Remove a user from the system.

        @author: Roy Nielsen
        """
        retval = False
        retval = self.userMgr.rmUser(user)
        return retval

    #----------------------------------------------------------------------

    def rmUserHome(self, user=""):
        """
        Remove the user home... right now only default location, but should
        look up the user home in the directory service and remove that
        specifically.

        @author: Roy Nielsen
        """
        retval = False
        retval = self.userMgr.rmUserHome(user)
        return retval

    #----------------------------------------------------------------------

    def rmUserFromGroup(self, user="", group=""):
        """
        Remove a user from a group, not their primary group.

        @author: Roy Nielsen
        """
        retval = False
        retval = self.userMgr.rmUserFromGroup(user, group)
        return retval

    #----------------------------------------------------------------------

    def fixUserHome(self, userName=""):
        """
        Get the user information from the local directory and fix the user
        ownership and group of the user's home directory to reflect
        what is in the local directory service.

        @author: Roy Nielsen
        """
        retval = False
        retval = self.userMgr.fixUserHome(userName)
        return retval

    #----------------------------------------------------------------------
