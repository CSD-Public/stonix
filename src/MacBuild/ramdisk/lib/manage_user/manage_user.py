"""
Factory object that will instanciate the appropriate user management class for
the appropriate environment/OS.

@author: Roy Nielsen
"""
from __future__ import absolute_import
import os
import sys
import inspect
import traceback

from .. loggers import LogPriority as lp
from .. loggers import CyLogger
from .. libHelperExceptions import UnsupportedOSError, NotACyLoggerError


class ManageUser(object):
    ''' '''

    #----------------------------------------------------------------------

    def __init__(self, logger):
        """
        Class initialization method
        """
        #####
        # Set up logging
        if isinstance(logger, CyLogger):
            self.logger = logger
        else:
            raise NotACyLoggerError("Passed in value for logger is invalid, try again.")
        self.logger.log(lp.INFO, "Logger: " + str(self.logger))

        if sys.platform.lower() == "darwin":
            from .macos_user import MacOSUser 
            # import lib.manage_user.macos_user
            self.userMgr = MacOSUser(logDispatcher=self.logger)
        else:
            raise UnsupportedOSError("This operating system is not supported...")

    #----------------------------------------------------------------------
    # helper Methods
    #----------------------------------------------------------------------
    def getSpecificManager(self):
        '''Getter to acqure the specific keychain manager'''
        return self.userMgr

    #----------------------------------------------------------------------

    def __calledBy(self):
        """
        Log the caller of the method that calls this method
        
        @author: Roy Nielsen
        """
        try:
            filename = inspect.stack()[2][1]
            functionName = str(inspect.stack()[2][3])
            lineNumber = str(inspect.stack()[2][2])
        except Exception, err:
            self.logger.log(lp.WARNING, traceback.format_exc())
            self.logger.log(lp.WARNING, str(err))
            raise err
        else:
            self.logger.log(lp.DEBUG, "called by: " + \
                                      filename + ": " + \
                                      functionName + " (" + \
                                      lineNumber + ")")

    #----------------------------------------------------------------------
    # Defined Interface methods
    #----------------------------------------------------------------------

    #----------------------------------------------------------------------
    # Getters
    #----------------------------------------------------------------------

    def findUniqueUid(self):
        '''Find an unused uid (unique ID) for the user, this method will list all
        the existing users, an unused number above 1000 is good.
        
        @author: Roy Nielsen


        '''
        success = False
        #####
        # Preprocess logging
        self.logger.log(lp.DEBUG, "processing:" + "")
        self.__calledBy()
        #####
        # Call factory created object's mirror method
        success = self.userMgr.findUniqueUid()
        #####
        # Postprocess logging
        self.logger.log(lp.DEBUG, "processing complete with success: " + str(success))
        return success

    #----------------------------------------------------------------------

    def uidTaken(self, uid):
        '''See if the UID requested has been taken.  Only approve uid's over 1k
        
        @author: Roy Nielsen

        :param uid: 

        '''
        success = False
        #####
        # Preprocess logging
        self.logger.log(lp.DEBUG, "processing:" + "")
        self.__calledBy()
        #####
        # Call factory created object's mirror method
        success = self.userMgr.uidTaken(uid)
        #####
        # Postprocess logging
        self.logger.log(lp.DEBUG, "processing complete with success: " + str(success))
        return success

    #----------------------------------------------------------------------

    def getUser(self, userName=""):
        '''Get information about the passed in user.

        :param userName:  (Default value = "")

        '''
        success = False
        #####
        # Preprocess logging
        self.logger.log(lp.DEBUG, "processing:" + "")
        self.__calledBy()
        #####
        # Call factory created object's mirror method
        success = self.userMgr.getUser(userName)
        #####
        # Postprocess logging
        self.logger.log(lp.DEBUG, "processing complete with success: " + str(success))
        return success

    #----------------------------------------------------------------------

    def getUserProperties(self, userName=""):
        '''Get information about the passed in user.

        :param userName:  (Default value = "")

        '''
        success = False
        properties = {}
        #####
        # Preprocess logging
        self.logger.log(lp.DEBUG, "processing:" + "")
        self.__calledBy()
        #####
        # Call factory created object's mirror method
        success, properties = self.userMgr.getUserProperties(userName)
        #####
        # Postprocess logging
        self.logger.log(lp.DEBUG, "processing complete with success: " + str(success))
        return success, properties

    #----------------------------------------------------------------------

    def getUserShell(self, userName=""):
        '''Retrieve the passed in user's shell.

        :param userName:  (Default value = "")

        '''
        success = False
        #####
        # Preprocess logging
        self.logger.log(lp.DEBUG, "processing:" + "")
        self.__calledBy()
        #####
        # Call factory created object's mirror method
        success = self.userMgr.getUserShell(userName)
        #####
        # Postprocess logging
        self.logger.log(lp.DEBUG, "processing complete with success: " + str(success))
        return success

    #----------------------------------------------------------------------

    def getUserComment(self, userName=""):
        '''Retrieve the passed in user's "user comment", or real name.

        :param userName:  (Default value = "")

        '''
        success = False
        #####
        # Preprocess logging
        self.logger.log(lp.DEBUG, "processing:" + "")
        self.__calledBy()
        #####
        # Call factory created object's mirror method
        success = self.userMgr.getUserComment(userName)
        #####
        # Postprocess logging
        self.logger.log(lp.DEBUG, "processing complete with success: " + str(success))
        return success

    #----------------------------------------------------------------------

    def getUserUid(self, userName=""):
        '''Retrieve the passed in user's UID.

        :param userName:  (Default value = "")

        '''
        success = False
        #####
        # Preprocess logging
        self.logger.log(lp.DEBUG, "processing:" + "")
        self.__calledBy()
        #####
        # Call factory created object's mirror method
        success = self.userMgr.getUserUid(userName)
        #####
        # Postprocess logging
        self.logger.log(lp.DEBUG, "processing complete with success: " + str(success))
        return success

    #----------------------------------------------------------------------

    def getUserPriGid(self, userName=""):
        '''Retrieve the passed in user's primary GID

        :param userName:  (Default value = "")

        '''
        success = False
        #####
        # Preprocess logging
        self.logger.log(lp.DEBUG, "processing:" + "")
        self.__calledBy()
        #####
        # Call factory created object's mirror method
        success = self.userMgr.getUserPriGid(userName)
        #####
        # Postprocess logging
        self.logger.log(lp.DEBUG, "processing complete with success: " + str(success))
        return success

    #----------------------------------------------------------------------

    def getUserHomeDir(self, userName=""):
        '''Retrieve the passed in user's home directory

        :param userName:  (Default value = "")

        '''
        success = False
        #####
        # Preprocess logging
        self.logger.log(lp.DEBUG, "processing:" + "")
        self.__calledBy()
        #####
        # Call factory created object's mirror method
        success = self.userMgr.getUserHomeDir(userName)
        #####
        # Postprocess logging
        self.logger.log(lp.DEBUG, "processing complete with success: " + str(success))
        return success

    #----------------------------------------------------------------------

    def isUserInstalled(self, user=""):
        '''Check if the user "user" is installed on the system.
        
        @author Roy Nielsen

        :param user:  (Default value = "")

        '''
        success = False
        #####
        # Preprocess logging
        self.logger.log(lp.DEBUG, "processing:" + "")
        self.__calledBy()
        #####
        # Call factory created object's mirror method
        success = self.userMgr.isUserInstalled(user)
        #####
        # Postprocess logging
        self.logger.log(lp.DEBUG, "processing complete with success: " + str(success))
        return success

    #----------------------------------------------------------------------

    def isUserInGroup(self, userName="", groupName=""):
        '''Check if this user is in this group
        
        @author: Roy Nielsen

        :param userName:  (Default value = "")
        :param groupName:  (Default value = "")

        '''
        success = False
        #####
        # Preprocess logging
        self.logger.log(lp.DEBUG, "processing:" + "")
        self.__calledBy()
        #####
        # Call factory created object's mirror method
        success = self.userMgr.isUserInGroup(userName, groupName)
        #####
        # Postprocess logging
        self.logger.log(lp.DEBUG, "processing complete with success: " + str(success))
        return success

    #----------------------------------------------------------------------

    def isUserInSudoers(self, userName=""):
        '''Check if this user is in the sudoers file - requires root access to run.
        
        @author: Roy Nielsen

        :param userName:  (Default value = "")

        '''
        success = False
        #####
        # Preprocess logging
        self.logger.log(lp.DEBUG, "processing:" + "")
        self.__calledBy()
        #####
        # Call factory created object's mirror method
        success = self.userMgr.isUserInSudoers(userName)
        #####
        # Postprocess logging
        self.logger.log(lp.DEBUG, "processing complete with success: " + str(success))
        return success

    #----------------------------------------------------------------------

    def validateUser(self, userName=False, userShell=False, userComment=False,
                     userUid=False, userPriGid=False, userHomeDir=False):
        '''Future functionality... validate that the passed in parameters to the
        class instanciation match.
        
        @author:

        :param userName:  (Default value = False)
        :param userShell:  (Default value = False)
        :param userComment:  (Default value = False)
        :param userUid:  (Default value = False)
        :param userPriGid:  (Default value = False)
        :param userHomeDir:  (Default value = False)

        '''
        success = False
        #####
        # Preprocess logging
        self.logger.log(lp.DEBUG, "processing:" + "")
        self.__calledBy()
        #####
        # Call factory created object's mirror method
        success = self.userMgr.validateUser(userName, userShell, userComment,
                                           userUid, userPriGid, userHomeDir)
        #####
        # Postprocess logging
        self.logger.log(lp.DEBUG, "processing complete with success: " + str(success))
        return success


    #----------------------------------------------------------------------

    def isQualifiedLiftAttendant(self, userName=""):
        '''Check if this user is in the sudoers file - requires root access to run.
        
        @author: Roy Nielsen

        :param userName:  (Default value = "")

        '''
        success = False
        #####
        # Preprocess logging
        self.logger.log(lp.DEBUG, "processing:" + "")
        self.__calledBy()
        #####
        # Call factory created object's mirror method
        success = self.userMgr.isQualifiedLiftAttendant(userName)
        #####
        # Postprocess logging
        self.logger.log(lp.DEBUG, "processing complete with success: " + str(success))
        return success

    #----------------------------------------------------------------------
    # Setters
    #----------------------------------------------------------------------

    def createStandardUser(self, userName, password):
        '''Creates a user that has the "next" uid in line to be used, then puts
        in in a group of the same id.  Uses /bin/bash as the standard shell.
        The userComment is left empty.  Primary use is managing a user
        during test automation, when requiring a "user" context.
        
        It does not set a login keychain password as that is created on first
        login to the GUI.
        
        @author: Roy Nielsen

        :param userName: 
        :param password: 

        '''
        success = False
        #####
        # Preprocess logging
        self.logger.log(lp.DEBUG, "processing:" + "")
        self.__calledBy()
        #####
        # Call factory created object's mirror method
        success = self.userMgr.createStandardUser(userName, password)
        #####
        # Postprocess logging
        self.logger.log(lp.DEBUG, "processing complete with success: " + str(success))
        return success

    
    def createBasicUser(self, userName=""):
        '''Create a username with just a moniker.  Allow the system to take care of
        the rest.
        
        Only allow usernames with letters and numbers.
        (see ParentManageUser regex for allowable characters)
        
        @author: Roy Nielsen

        :param userName:  (Default value = "")

        '''
        success = False
        #####
        # Preprocess logging
        self.logger.log(lp.DEBUG, "processing:" + "")
        self.__calledBy()
        #####
        # Call factory created object's mirror method
        success = self.userMgr.createBasicUser(userName)
        #####
        # Postprocess logging
        self.logger.log(lp.DEBUG, "processing complete with success: " + str(success))
        return success

    #----------------------------------------------------------------------

    def setUserName(self, user):
        '''Setter for the class variable userName
        
        @author: Roy Nielsen

        :param user: 

        '''
        success = False
        if self.userMgr.isSaneUserName(user):
            success = self.userMgr.setUserName(user)
        return success

    #----------------------------------------------------------------------

    def setUserShell(self, user="", shell=""):
        '''Set a user's shell
        
        (see ParentManageUser regex for allowable characters)
        
        @author: Roy Nielsen

        :param user:  (Default value = "")
        :param shell:  (Default value = "")

        '''
        success = False
        #####
        # Preprocess logging
        self.logger.log(lp.DEBUG, "processing:" + "")
        self.__calledBy()
        #####
        # Call factory created object's mirror method
        success = self.userMgr.setUserShell(user, shell)
        #####
        # Postprocess logging
        self.logger.log(lp.DEBUG, "processing complete with success: " + str(success))
        return success

    #----------------------------------------------------------------------

    def setUserComment(self, user="", comment=""):
        '''Set the "user comment" field that normally holds the user's real name
        
        (see ParentManageUser regex for allowable characters)
        
        @author: Roy Nielsen

        :param user:  (Default value = "")
        :param comment:  (Default value = "")

        '''
        success = False
        #####
        # Preprocess logging
        self.logger.log(lp.DEBUG, "processing:" + "")
        self.__calledBy()
        #####
        # Call factory created object's mirror method
        success = self.userMgr.setUserComment(user, comment)
        #####
        # Postprocess logging
        self.logger.log(lp.DEBUG, "processing complete with success: " + str(success))
        return success

    #----------------------------------------------------------------------

    def setUserUid(self, user="", uid=""):
        '''Set the user UID on the system.
        
        @author: Roy Nielsen

        :param user:  (Default value = "")
        :param uid:  (Default value = "")

        '''
        success = False
        #####
        # Preprocess logging
        self.logger.log(lp.DEBUG, "processing:" + "")
        self.__calledBy()
        #####
        # Call factory created object's mirror method
        success = self.userMgr.setUserUid(user, uid)
        #####
        # Postprocess logging
        self.logger.log(lp.DEBUG, "processing complete with success: " + str(success))
        return success

    #----------------------------------------------------------------------

    def setUserPriGid(self, user="", priGid=""):
        '''Set the user's primary group ID on the system.
        
        @author: Roy Nielsen

        :param user:  (Default value = "")
        :param priGid:  (Default value = "")

        '''
        success = False
        #####
        # Preprocess logging
        self.logger.log(lp.DEBUG, "processing:" + "")
        self.__calledBy()
        #####
        # Call factory created object's mirror method
        success = self.userMgr.setUserPriGid(user, priGid)
        #####
        # Postprocess logging
        self.logger.log(lp.DEBUG, "processing complete with success: " + str(success))
        return success

    #----------------------------------------------------------------------

    def setUserHomeDir(self, user="", userHome=""):
        '''Create a "local" home directory.  This may or may not create the user's
        home directory from the system's user template/skel for standard user
        settings.
        
        @author: Roy Nielsen

        :param user:  (Default value = "")
        :param userHome:  (Default value = "")

        '''
        success = False
        #####
        # Preprocess logging
        self.logger.log(lp.DEBUG, "processing:" + "")
        self.__calledBy()
        #####
        # Call factory created object's mirror method
        success = self.userMgr.setUserHomeDir(user, userHome)
        #####
        # Postprocess logging
        self.logger.log(lp.DEBUG, "processing complete with success: " + str(success))
        return success

    #----------------------------------------------------------------------

    def createHomeDirectory(self, user=""):
        '''Create a "local" home directory.
        
        This should use the system "User Template" or "/etc/skel" for standard
        system user settings.
        
        @author: Roy Nielsen

        :param user:  (Default value = "")

        '''
        success = False
        #####
        # Preprocess logging
        self.logger.log(lp.DEBUG, "processing:" + "")
        self.__calledBy()
        #####
        # Call factory created object's mirror method
        success = self.userMgr.createHomeDirectory(user)
        #####
        # Postprocess logging
        self.logger.log(lp.DEBUG, "processing complete with success: " + str(success))
        return success

    #----------------------------------------------------------------------

    def addUserToGroup(self, user="", group=""):
        '''Add a user to a group, not their primary group.
        
        @author: Roy Nielsen

        :param user:  (Default value = "")
        :param group:  (Default value = "")

        '''
        success = False
        #####
        # Preprocess logging
        self.logger.log(lp.DEBUG, "processing:" + "")
        self.__calledBy()
        #####
        # Call factory created object's mirror method
        success = self.userMgr.addUserToGroup(user, group)
        #####
        # Postprocess logging
        self.logger.log(lp.DEBUG, "processing complete with success: " + str(success))
        return success

    #----------------------------------------------------------------------

    def setUserPassword(self, user="", password="", oldPassword=""):
        '''Set a user's password.
        
        @author: Roy Nielsen

        :param user:  (Default value = "")
        :param password:  (Default value = "")
        :param oldPassword:  (Default value = "")

        '''
        success = False
        #####
        # Preprocess logging
        self.logger.log(lp.DEBUG, "processing:" + "")
        self.__calledBy()
        #####
        # Call factory created object's mirror method
        success = self.userMgr.setUserPassword(user, password, oldPassword)
        #####
        # Postprocess logging
        self.logger.log(lp.DEBUG, "processing complete with success: " + str(success))
        return success

    #----------------------------------------------------------------------

    def rmUser(self, user=""):
        '''Remove a user from the system.
        
        @author: Roy Nielsen

        :param user:  (Default value = "")

        '''
        success = False
        #####
        # Preprocess logging
        self.logger.log(lp.DEBUG, "processing:" + "")
        self.__calledBy()
        #####
        # Call factory created object's mirror method
        success = self.userMgr.rmUser(user)
        #####
        # Postprocess logging
        self.logger.log(lp.DEBUG, "processing complete with success: " + str(success))
        return success

    #----------------------------------------------------------------------

    def rmUserHome(self, user=""):
        '''Remove the user home... right now only default location, but should
        look up the user home in the directory service and remove that
        specifically.
        
        @author: Roy Nielsen

        :param user:  (Default value = "")

        '''
        success = False
        #####
        # Preprocess logging
        self.logger.log(lp.DEBUG, "processing:" + "")
        self.__calledBy()
        #####
        # Call factory created object's mirror method
        success = self.userMgr.rmUserHome(user)
        #####
        # Postprocess logging
        self.logger.log(lp.DEBUG, "processing complete with success: " + str(success))
        return success

    #----------------------------------------------------------------------

    def rmUserFromGroup(self, user="", group=""):
        '''Remove a user from a group, not their primary group.
        
        @author: Roy Nielsen

        :param user:  (Default value = "")
        :param group:  (Default value = "")

        '''
        success = False
        #####
        # Preprocess logging
        self.logger.log(lp.DEBUG, "processing:" + "")
        self.__calledBy()
        #####
        # Call factory created object's mirror method
        success = self.userMgr.rmUserFromGroup(user, group)
        #####
        # Postprocess logging
        self.logger.log(lp.DEBUG, "processing complete with success: " + str(success))
        return success

    #----------------------------------------------------------------------

    def fixUserHome(self, userName=""):
        '''Get the user information from the local directory and fix the user
        ownership and group of the user's home directory to reflect
        what is in the local directory service.
        
        @author: Roy Nielsen

        :param userName:  (Default value = "")

        '''
        success = False
        #####
        # Preprocess logging
        self.logger.log(lp.DEBUG, "processing:" + "")
        self.__calledBy()
        #####
        # Call factory created object's mirror method
        success = self.userMgr.fixUserHome(userName)
        #####
        # Postprocess logging
        self.logger.log(lp.DEBUG, "processing complete with success: " + str(success))
        return success

    #----------------------------------------------------------------------

    def authenticate(self, user="", password=""):
        '''

        :param user:  (Default value = "")
        :param password:  (Default value = "")

        '''
        success = False
        #####
        # Preprocess logging
        self.logger.log(lp.DEBUG, "processing:" + "")
        self.__calledBy()
        #####
        # Call factory created object's mirror method
        success = self.userMgr.authenticate(user, password)
        #####
        # Postprocess logging
        self.logger.log(lp.DEBUG, "processing complete with success: " + str(success))
        return success
