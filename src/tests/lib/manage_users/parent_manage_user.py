"""
Cross platform user creation and management

Created for testing cross user testing for the ramdisk project, specifically
unionfs functionality.

@author: Roy Nielsen
"""
#from __future__ import absolute_import
import re

from src.tests.lib.logdispatcher_lite import LogPriority as lp
from src.tests.lib.logdispatcher_lite import LogDispatcher
from src.stonix_resources.CommandHelper import CommandHelper

class BadUserInfoError(Exception):
    '''Meant for being thrown when an action/class being run/instanciated is not
    applicable for the running operating system.
    
    @author: Roy Nielsen


    '''
    def __init__(self, *args, **kwargs):
        Exception.__init__(self, *args, **kwargs)

class ManageUser(object):
    '''Class to manage user properties.
    
    @author: Roy Nielsen


    '''
    def __init__(self, userName="", userShell="/bin/bash",
                       userComment="", userUid=10000, userPriGid=20,
                       userHomeDir="/tmp", logger=False):
        self.module_version = '20160225.125554.540679'

        #####
        # Set up logging
        self.logger = LogDispatcher()
        #####
        # THIS IS A LIBRARY, SO LOGS SHOULD BE INITIALIZED ELSEWHERE...
        # self.logger.initializeLogs()
        self.logger.log(lp.INFO, "Logger: " + str(self.logger))
        """
        if self.isSaneUserName(userName):
            self.userName = userName
        else:
            raise BadUserInfoError("Need a valid user name...")

        if self.isSaneUserShell(userShell):
            self.userShell = userShell
        else:
            raise BadUserInfoError("Need a valid user shell...")

        if self.isSaneUserComment(userComment):
            self.userComment = userComment
        else:
            self.userComment=""

        if self.isSaneUserUid(str(userUid)):
            self.userUid = self.userUid
        else:
            raise BadUserInfoError("Need a valid user UID...")

        if self.isSaneUserPriGid(str(userPriGid)):
            self.userUid = userUid
        else:
            raise BadUserInfoError("Need a valid user Primary GID...")

        if self.isSaneUserHomeDir(userHomeDir):
            self.userHomeDir = userHomeDir
        else:
            raise BadUserInfoError("Need a user Home Directory...")
        """

    def isSaneUserName(self, userName=""):
        '''

        :param userName:  (Default value = "")

        '''
        sane = False
        if userName and isinstance(userName, str):
            if re.match("^[A-Za-z][A-Za-z0-9]*", userName):
                sane = True
        return sane

    def isSaneGroupName(self, groupName=""):
        '''

        :param groupName:  (Default value = "")

        '''
        sane = False
        if groupName and isinstance(groupName, str):
            if re.match("^[A-Za-z][A-Za-z0-9]*", groupName):
                sane = True
        return sane

    def isSaneUserShell(self, userShell=""):
        '''

        :param userShell:  (Default value = "")

        '''
        sane = False
        if userShell and isinstance(userShell, str):
            if re.match("^[A-Za-z/][A-Za-z0-9/]*", userShell):
                sane = True
        return sane

    def isSaneUserComment(self, userComment=""):
        '''

        :param userComment:  (Default value = "")

        '''
        sane = False
        if userComment and isinstance(userComment, str):
            if re.match("^[A-Za-z][A-Za-z0-9]*", userComment):
                sane = True
        return sane

 
    def isSaneUserUid(self, userUid=""):
        '''

        :param userUid:  (Default value = "")

        '''
        sane = False
        if userUid and isinstance(userUid, [str, int]):
            if re.match("^\d+", str(userUid)):
                sane = True
        return sane

    def isSaneUserPriGid(self, userPriGid=1000):
        '''

        :param userPriGid:  (Default value = 1000)

        '''
        sane = False
        if userPriGid and isinstance(userPriGid, [str, int]):
            if re.match("^\d+", str(userPriGid)):
                sane = True
        return sane

    def isSaneUserHomeDir(self, userHomeDir=""):
        '''

        :param userHomeDir:  (Default value = "")

        '''
        sane = False
        if userHomeDir and isinstance(userHomeDir, str):
            if re.match("^[A-Za-z/][A-Za-z0-9/]*", userHomeDir):
                sane = True
        return sane


    def setUserName(self, userName=""):
        '''

        :param userName:  (Default value = "")

        '''
        sane = False
        if self.isSaneUserName(userName):
            sane = True
            self.userName = userName
        return sane

    def setUserShell(self, user="", shell=""):
        '''

        :param user:  (Default value = "")
        :param shell:  (Default value = "")

        '''
        pass

    def setUserComment(self, user="", comment=""):
        '''

        :param user:  (Default value = "")
        :param comment:  (Default value = "")

        '''
        pass

    def setUserUid(self, user="", uid=""):
        '''

        :param user:  (Default value = "")
        :param uid:  (Default value = "")

        '''
        pass

    def setUserPriGid(self, user="", priGid=""):
        '''

        :param user:  (Default value = "")
        :param priGid:  (Default value = "")

        '''
        pass

    def setUserHomeDir(self, user="", userHome = ""):
        '''

        :param user:  (Default value = "")
        :param userHome:  (Default value = "")

        '''
        pass

    def addUserToGroup(self, user="", group=""):
        '''

        :param user:  (Default value = "")
        :param group:  (Default value = "")

        '''
        pass

    def setUserPassword(self, user="", password=""):
        '''

        :param user:  (Default value = "")
        :param password:  (Default value = "")

        '''
        pass

