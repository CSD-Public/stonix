"""
Cross platform user creation and management

Created for testing cross user testing for the ramdisk project, specifically
unionfs functionality.

@author: Roy Nielsen
"""
from __future__ import absolute_import

class ManagerUsersTemplate(object):
    """
    Class to manage user properties.
    
    @author: Roy Nielsen
    """
    def __init__(self, logger, userName="", userShell="/bin/bash",
                       userComment="", userUid=10000, userPriGid=20,
                       userHomeDir="/tmp"):
        pass

    def setUserName(self):
        """
        """
        pass

    def setUserShell(self, user="", shell=""):
        """
        """
        pass

    def setUserComment(self, user="", comment=""):
        """
        """
        pass

    def setUserUid(self, user="", uid=""):
        """
        """
        pass

    def setUserPriGid(self, user="", priGid=""):
        """
        """
        pass

    def setUserHomeDir(self, user="", userHome = ""):
        """
        """
        pass

    def addUserToGroup(self, user="", group=""):
        """
        """
        pass

    def setUserPassword(self, user="", password=""):
        """
        """
        pass

