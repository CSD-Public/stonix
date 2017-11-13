"""
Cross platform user creation and management

Created for testing cross user testing for the ramdisk project, specifically
unionfs functionality.

@author: Roy Nielsen
"""
from __future__ import absolute_import

import re
import os
import pty
import pwd
import sys
import time
import shutil
from subprocess import Popen

########## 
# local app libraries
from .parent_manage_user import ParentManageUser
from .parent_manage_user import BadUserInfoError
from ..run_commands import RunWith
from ..loggers import CyLogger
from ..loggers import LogPriority as lp
from ..libHelperFunctions import waitnoecho


class DsclError(Exception):
    """
    Meant for being thrown when an action/class being run/instanciated is not
    applicable for the running operating system.

    @author: Roy Nielsen
    """
    def __init__(self, *args, **kwargs):
        Exception.__init__(self, *args, **kwargs)


class CreateHomeDirError(Exception):
    """
    Meant for being thrown when an action/class being run/instanciated is not
    applicable for the running operating system.

    @author: Roy Nielsen
    """
    def __init__(self, *args, **kwargs):
        Exception.__init__(self, *args, **kwargs)


class MacOSUser(ParentManageUser):
    """
    Class to manage users on Mac OS.

    #----- Acquire user (pwd) map
    @method getUsers
    #----- Getters
    @method findUniqueUid
    @method uidTaken
    @method getUser
    @method getUserShell
    @method getUserComment
    @method getUserUid
    @method getUserPriGid
    @method getUserHomeDir
    @method isUserInstalled
    @method isUserInGroup
    @method authenticate
    #----- Setters
    @method createStandardUser
    @method createBasicUser
    @method setUserShell
    @method setUserComment
    @method setUserUid
    @method setUserPriGid
    @method setUserHomeDir
    @method createHomeDirectory
    @method addUserToGroup
    @method setUserPassword
    @method fixUserHome
    #----- User removal
    @method rmUser
    @method rmUserFromGroup
    @method rmUserHome

    @author: Roy Nielsen
    """
    def __init__(self, **kwargs):
        """
        Variables that can be passed in:
        logger
        userName
        userShell
        userComment
        userUid
        userPriGid
        userHomeDir
        """
        if 'logDispatcher' not in kwargs:
            raise ValueError("Variable 'logDispatcher' a required parameter for " + str(self.__class__.__name__))
        super(MacOSUser, self).__init__(**kwargs)

        self.module_version = '20160225.125554.540679'

        self.dscl = "/usr/bin/dscl"
        self.runner = RunWith(self.logger)

        self.users = self.getUsers()

    #----------------------------------------------------------------------
    # Getters
    #----------------------------------------------------------------------

    def getUsers(self):
        """
        Return a list of users, from pwd.
        
        Password database entries are reported as a tuple-like object, whose 
        attributes correspond to the members of the passwd structure (Attribute
        field below, see <pwd.h>):
        
        Index    Attribute    Meaning
        0    pw_name    Login name
        1    pw_passwd    Optional encrypted password
        2    pw_uid    Numerical user ID
        3    pw_gid    Numerical group ID
        4    pw_gecos    User name or comment field
        5    pw_dir    User home directory
        6    pw_shell    User command interpreter

        The uid and gid items are integers, all others are strings. KeyError
        is raised if the entry asked for cannot be found. 
        """
        self.users = pwd.getpwall()
        return self.users
        
    #----------------------------------------------------------------------
    # Getters
    #----------------------------------------------------------------------

    def findUniqueUid(self):
        """
        We need to make sure to find an unused uid (unique ID) for the user,
           $ dscl . -list /Users UniqueID
        will list all the existing users, an unused number above 500 is good.

        @author: Roy Nielsen
        """
        success = False
        maxUserID = 0
        newUserID = 0
        userList = self.getDscl(".", "-list", "/Users", "UniqueID")

        #####
        # Sort the list, add one to the highest value and return that
        # value
        for user in str(userList).split("\n"):
            if int(user.split()[1]) > maxUserID:
                maxUserID = int(user.split()[1])

        newUserID = str(int(maxUserID + 1))

        return newUserID

    #----------------------------------------------------------------------

    def uidTaken(self, uid):
        """
        See if the UID requested has been taken.  Only approve uid's over 1k
           $ dscl . -list /Users UniqueID

        @author: Roy Nielsen
        """
        uidList = []
        success = False
        userList = self.getDscl(".", "-list", "/Users", "UniqueID")

        #####
        # Sort the list, add one to the highest value and return that
        # value
        for user in str(userList).split("\n"):
            uidList.append(str(user.split()[1]))

        if str(uid) in uidList:
            success = True

        return success

    #----------------------------------------------------------------------

    def getUser(self, userName=""):
        """
        """
        userInfo = False
        if self.isSaneUserName(userName):
            output = self.getDscl(".", "read", "/Users/" + str(userName), "RecordName")
            try:
                userInfo = output.split()[1]
            except (KeyError, IndexError), err:
                self.logger.log(lp.INFO, "Error attempting to find user" + \
                                         str(userName) + " in the " + \
                                         "directory service.")
        else:
            raise BadUserInfoError("Need a valid user name...")

        return userInfo

    #----------------------------------------------------------------------

    def getUserShell(self, userName=""):
        """
        """
        userShell = False
        if self.isSaneUserName(userName):
            output = self.getDscl(".", "read", "/Users/" + str(userName), "UserShell")
            try:
                userShell = output.split()[1]
            except (KeyError, IndexError), err:
                self.logger.log(lp.INFO, "Error attempting to find user" + \
                                         str(userName) + " in the " + \
                                         "directory service.")
        else:
            raise BadUserInfoError("Need a valid user name...")

        return userShell

    #----------------------------------------------------------------------

    def getUserComment(self, userName=""):
        """
        """
        userComment = False
        if self.isSaneUserName(userName):
            #####
            # Need to process the output to get the right information due to a
            # spurrious "\n" in the output
            output = self.getDscl(".", "read", "/Users/" + str(userName), "RealName")
            try:
                userComment = output[1]
            except (KeyError, IndexError), err:
                self.logger.log(lp.INFO, "Error attempting to find user" + \
                                         str(userName) + " in the " + \
                                         "directory service.")
        else:
            raise BadUserInfoError("Need a valid user name...")

        return userComment

    #----------------------------------------------------------------------

    def getUserUid(self, userName=""):
        """
        """
        userUid = False
        if self.isSaneUserName(userName):
            output = self.getDscl(".", "read", "/Users/" + str(userName), "UniqueID")
            #####
            # Process to get out the right information....
            try:
                userUid = output.split()[1]
            except (KeyError, IndexError), err:
                self.logger.log(lp.INFO, "Error attempting to find user" + \
                                         str(userName) + " in the " + \
                                         "directory service.")
        else:
            raise BadUserInfoError("Need a valid user name...")

        return userUid

    #----------------------------------------------------------------------

    def getUserPriGid(self, userName=""):
        """
        """
        userPriGid = False
        if self.isSaneUserName(userName):
            output = self.getDscl(".", "read", "/Users/" + str(userName), "PrimaryGroupID")
            #####
            # Process to get out the right information....
            try:
                userPriGid = output.split()[1]
            except (KeyError, IndexError), err:
                self.logger.log(lp.INFO, "Error attempting to find user" + \
                                         str(userName) + " in the " + \
                                         "directory service.")
        else:
            raise BadUserInfoError("Need a valid user name...")

        return userPriGid

    #----------------------------------------------------------------------

    def getUserHomeDir(self, userName=""):
        """
        """
        userHomeDir = False
        if self.isSaneUserName(userName):
            output = self.getDscl(".", "read", "/Users/" + str(userName), "NFSHomeDirectory")
            #####
            # Process to get out the right information....
            try:
                userHomeDir = output.split()[1]
            except (KeyError, IndexError), err:
                self.logger.log(lp.INFO, "Error attempting to find user" + \
                                         str(userName) + " in the " + \
                                         "directory service.")
        else:
            raise BadUserInfoError("Need a valid user name...")

        return userHomeDir

    #----------------------------------------------------------------------

    def isUserInstalled(self, user=""):
        """
        Check if the user "user" is installed

        @author Roy Nielsen
        """
        success = False
        if self.isSaneUserName(user):
            cmd = [self.dscl, ".", "-read", "/Users/" + str(user)]
            self.runner.setCommand(cmd)
            self.runner.communicate()
            retval, reterr, retcode = self.runner.getNlogReturns()

            if not reterr:
                success = True

        return success

    #----------------------------------------------------------------------

    def isUserInGroup(self, userName="", groupName=""):
        """
        Check if this user is in this group
        
        @author: Roy Nielsen
        """
        self.logger.log(lp.DEBUG, "U: " + str(userName))
        self.logger.log(lp.DEBUG, "G: " + str(groupName))

        success = False
        if self.isSaneUserName(userName) and self.isSaneGroupName(groupName):
            output = self.getDscl(".", "-read", "/Groups/" + groupName, "users")
            self.logger.log(lp.CRITICAL, "Output: " + str(output))
            users = output[1:]
            self.logger.log(lp.CRITICAL, "Users: " + str(users))
            if userName in users:
                success = True
        return success

    #----------------------------------------------------------------------

    def accountCreationTime(self, userName=""):
        """
        """
        userInfo = False
        if self.isSaneUserName(userName):
            output = self.getDscl(".", "-readpl", "/Users/" + str(userName), 
                                  "accountPolicyData", "creationTime")
            try:
                userInfo = output.split()[1]
            except (KeyError, IndexError), err:
                self.logger.log(lp.INFO, "Error attempting to find user" + \
                                         str(userName) + " in the " + \
                                         "directory service.")
            else:
                epochtime = userInfo
                timestring = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(epochtime))
                userInfo = [epochtime, timestring]
        else:
            raise BadUserInfoError("Need a valid user name...")

        return userInfo

    #----------------------------------------------------------------------

    def failedLoginCount(self, userName=""):
        """
        """
        userInfo = False
        if self.isSaneUserName(userName):
            output = self.getDscl(".", "-readpl", "/Users/" + str(userName), 
                                  "accountPolicyData", "failedLoginCount")
            try:
                userInfo = output.split()[1]
            except (KeyError, IndexError), err:
                self.logger.log(lp.INFO, "Error attempting to find user" + \
                                         str(userName) + " in the " + \
                                         "directory service.")
        else:
            raise BadUserInfoError("Need a valid user name...")

        return userInfo

    #----------------------------------------------------------------------

    def failedLoginTimestamp(self, userName=""):
        """
        """
        userInfo = False
        if self.isSaneUserName(userName):
            output = self.getDscl(".", "-readpl", "/Users/" + str(userName), 
                                  "accountPolicyData", "failedLoginTimestamp")
            try:
                userInfo = output.split()[1]
            except (KeyError, IndexError), err:
                self.logger.log(lp.INFO, "Error attempting to find user" + \
                                         str(userName) + " in the " + \
                                         "directory service.")
            else:
                epochtime = userInfo
                timestring = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(epochtime))
                userInfo = [epochtime, timestring]
        else:
            raise BadUserInfoError("Need a valid user name...")

        return userInfo

    #----------------------------------------------------------------------

    def passwordLastSetTime(self, userName=""):
        """
        """
        userInfo = False
        
        if self.isSaneUserName(userName):
            output = self.getDscl(".", "-readpl", "/Users/" + str(userName), 
                                  "accountPolicyData", "passwordLastSetTime")
            try:
                userInfo = output.split()[1]
            except (KeyError, IndexError), err:
                self.logger.log(lp.INFO, "Error attempting to find user" + \
                                         str(userName) + " in the " + \
                                         "directory service.")
            else:
                epochtime = userInfo
                timestring = time.strftime('%Y-%m-%d %H:%M:%S', 
                                           time.localtime(epochtime))
                userInfo = [epochtime, timestring]
        else:
            raise BadUserInfoError("Need a valid user name...")

        return userInfo

    #----------------------------------------------------------------------

    def isAuthenticationAllowed(self, userName=""):
        """
        """
        userInfo = False
        
        if self.isSaneUserName(userName):
            self.runner.setCommand(["/usr/bin/pwpolicy", "-u", str(userName),
                                     "-authentication-allowed"])
            output, error, retcode = self.runner.communicate()
            
            self.logger.log(lp.DEBUG, "Output: " + str(output.strip()))
            
            userInfo = output
        else:
            raise BadUserInfoError("Need a valid user name...")
            
        return userInfo

    #----------------------------------------------------------------------

    def validateUser(self, userName=False, userShell=False, userComment=False,
                     userUid=False, userPriGid=False, userHomeDir=False):
        """
        Future functionality... validate that the passed in parameters to the
        class instanciation match.

        @author:
        """
        sane = False
        #####
        # Look up all user attributes and check that they are accurate.
        # Only check the "SANE" parameters passed in.
        if self.isSaneUserName(userName):
            self.userName = userName
            sane = True
        else:
            raise BadUserInfoError("Need a valid user name...")

        if self.isSaneUserShell(userShell) and sane:
            self.userShell = userShell
        elif not userShell:
            pass
        else:
            sane = False

        if self.isSaneUserComment(userComment) and sane:
            self.userComment = userComment
        elif not userComment:
            pass
        else:
            sane = False

        if self.isSaneUserUid(str(userUid)) and sane:
            self.userUid = self.userUid
        elif not userUid:
            pass
        else:
            sane = False

        if self.isSaneUserPriGid(str(userPriGid)) and sane:
            self.userUid = userUid
        elif not userPriGid:
            pass
        else:
            sane = False

        if self.isSaneUserHomeDir(userHomeDir) and sane:
            self.userHomeDir = userHomeDir
        elif not userHomeDir:
            pass
        else:
            sane = False

        return sane

    #----------------------------------------------------------------------

    def authenticate(self, user="", password=""):
        """
        Open a pty to run "su" to see if the password is correct...

        @param: user - name of a user to check
        @param: password - to check if the password is correct for this user

        @author: Roy Nielsen
        """
        authenticated = False
        output = ""
        error = ""

        if not self.isSaneUserName(user) or \
           re.match("^\s+$", password) or not password:
            self.logger.log(lp.INFO, "Cannot pass in empty or bad parameters...")
            self.logger.log(lp.INFO, "user = \"" + str(user) + "\"")
            self.logger.log(lp.INFO, "check password...")
        else:
            
            self.runner.setCommand(['/bin/echo', 'HelloWorld'])
            output, error, retcode = self.runner.runAs(user.strip(), password.strip())
            
            #self.logger.log(lp.DEBUG, "Output: " + str(output.strip()))
            
            if not retcode:
                authenticated = True

        self.logger.log(lp.DEBUG, "output: " + str(output))
        self.logger.log(lp.DEBUG, "error: " + str(error))
        self.logger.log(lp.DEBUG, "retcode: " + str(retcode))
        self.logger.log(lp.DEBUG, "authenticated: " + str(authenticated))
        return authenticated

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
        self.createBasicUser(userName)
        newUserID = self.findUniqueUid()
        newUserGID = newUserID
        self.setUserUid(userName, newUserID)
        self.setUserPriGid(userName, newUserID)
        self.setUserHomeDir(userName)
        self.setUserShell(userName, "/bin/bash")
        self.setUserPassword(userName, password)
        #####
        # Don't need to set the user login keychain password as it should be
        # created on first login.

    #----------------------------------------------------------------------

    def createBasicUser(self, userName=""):
        """
        Create a username with just a moniker.  Allow the system to take care of
        the rest.

        Only allow usernames with letters and numbers.

        On the MacOS platform, all other steps must also be done.

        @author: Roy Nielsen
        """
        success = False
        reterr = ""
        if isinstance(userName, basestring)\
           and re.match("^[A-Za-z][A-Za-z0-9]*$", userName):
            cmd = [self.dscl, ".", "-create", "/Users/" + str(userName)]
            self.runner.setCommand(cmd)
            self.runner.communicate()
            retval, reterr, retcode = self.runner.getNlogReturns()

            if not reterr:
                success = True
            else:
                raise DsclError("Error trying to set a value with dscl (" + \
                                str(reterr).strip() + ")")
        return success
            
    #----------------------------------------------------------------------

    def setUserShell(self, user="", shell=""):
        """
        dscl . -create /Users/luser UserShell /bin/bash

        @author: Roy Nielsen
        """
        success = False
        if self.isSaneUserName(user) and self.isSaneUserShell(shell):
            isSetDSL = self.setDscl(".", "-create", "/Users/" + str(user),
                                    "UserShell", str(shell))
            if isSetDSL:
                success = True

        return success

    #----------------------------------------------------------------------

    def setUserComment(self, user="", comment=""):
        """
        dscl . -create /Users/luser RealName "Real A. Name"

        @author: Roy Nielsen
        """
        success = False

        if self.isSaneUserName(user) and comment:
            isSetDSL = self.setDscl(".", "-create", "/Users/" + str(user),
                                    "RealName", str(comment))
            if isSetDSL:
                success = True

        return success

    #----------------------------------------------------------------------

    def setUserUid(self, user="", uid=""):
        """
        dscl . -create /Users/luser UniqueID "503"

        @author: Roy Nielsen
        """
        success = False

        if self.isSaneUserName(user) and uid:
            isSetDSL = self.setDscl(".", "-create", "/Users/" + str(user),
                                    "UniqueID", str(uid))

            if isSetDSL:
                success = True

        return success

    #----------------------------------------------------------------------

    def setUserPriGid(self, user="", priGid=""):
        """
        dscl . -create /Users/luser PrimaryGroupID 20

        @author: Roy Nielsen
        """
        success = False

        if self.isSaneUserName(user) and priGid:
            isSetDSL = self.setDscl(".", "-create", "/Users/" + str(user),
                                    "PrimaryGroupID", str(priGid))

            if isSetDSL:
                success = True

        return success

    #----------------------------------------------------------------------

    def setUserHomeDir(self, user="", userHome=""):
        """
        Create a "local" home directory

        dscl . -create /Users/luser NFSHomeDirectory /Users/luser

        better yet:

        createhomedir -l -u <username>

        @author: Roy Nielsen
        """
        success = False
        #####
        # Creating a non-standard userHome is not currently permitted
        #if self.saneUserName(user) and self.saneUserHomeDir(userHome):
        if self.isSaneUserName(user):
            isSetDSCL = self.setDscl(".", "-create", "/Users/" + str(user),
                                     "NFSHomeDirectory", str("/Users/" + str(user)))
            if isSetDSCL:
                success = True

        return success

    #----------------------------------------------------------------------

    def createHomeDirectory(self, user=""):
        """
        createhomedir -c -u luser

        This should use the system "User Template" for standard system user
        settings.

        @author: Roy Nielsen
        """
        success = False
        reterr = ""
        if user:
            cmd = ["/usr/sbin/createhomedir", "-c", " -u", + str(user)]
            self.runner.setCommand(cmd)
            self.runner.communicate()
            retval, reterr, retcode = self.runner.getNlogReturns()

            if not reterr:
                success = True
            else:
                raise CreateHomeDirError("Error trying to create user home (" + \
                                         str(reterr).strip() + ")")
        return success

    #----------------------------------------------------------------------

    def addUserToGroup(self, user="", group=""):
        """
        dscl . -append /Groups/admin GroupMembership luser

        @author: Roy Nielsen
        """
        success = False

        if self.isSaneUserName(user) and self.isSaneGroupName(group):
            isSetDSCL = self.setDscl(".", "-append", "/Groups/" + str(group),
                                     "GroupMembership", str(user))
        if isSetDSCL:
            success = True

        return success

    #----------------------------------------------------------------------

    def setUserPassword(self, user="", password="", oldPassword=""):
        """
        dscl . -passwd /Users/luser password
        -- or --
        dscl . -passwd /Users/luser oldPassword password

        @author: Roy Nielsen
        """
        success = False

        if self.isSaneUserName(user):
            if oldPassword:
                isSetDSCL = self.setDscl(".", "-passwd", "/Users/" + str(user),
                                         '%s'%oldPassword, '%s'%password)
            else:
                isSetDSCL = self.setDscl(".", "-passwd", "/Users/" + str(user),
                                         '%s'%password)
            self.logger.log(lp.DEBUG, "isSetDSCL: " + str(isSetDSCL))
        else:
            self.logger.log(lp.DEBUG, "Tribbles in the bulkhead Jim!")

        if not isSetDSCL:
            success = False
        else:
            success = True

        return success

    #----------------------------------------------------------------------

    def fixUserHome(self, userName=""):
        """
        Get the user information from the local directory and fix the user
        ownership and group of the user's home directory to reflect
        what is in the local directory service.

        @author: Roy Nielsen
        """
        success = False
        if self.isSaneUserName(userName):
            #####
            # Acquire the user data based on the username first.
            try:
                userUid = self.getUserUid(userName)
                userPriGid = self.getUserPriGid(userName)
                userHomeDir = self.getUserHomeDir(userName)
            except BadUserInfoError, err:
                self.logger.log(lp.INFO, "Exception trying to find: \"" + \
                                         str(userName) + "\" user information")
                self.logger.log(lp.INFO, "err: " + str(err))
            else:
                success = True

        if success:
            try:
                for root, dirs, files in os.walk(userHomeDir):
                    for d in dirs:
                        os.chown(os.path.join(root, d), userUid, userPriGid)
                    for f in files:
                        os.chown(os.path.join(root, d, f), userUid, userPriGid)
            except:
                success = False
                self.logger.log(lp.INFO, "Exception attempting to chown...")
                raise err
            else:
                success = True
        return success

    #----------------------------------------------------------------------
    # User Property Removal
    #----------------------------------------------------------------------

    def rmUser(self, user=""):
        """
        dscl . delete /Users/<user>

        @author: Roy Nielsen
        """
        success = False

        if self.isSaneUserName(user):
            cmd = [self.dscl, ".", "-delete", "/Users/" + str(user)]
            self.runner.setCommand(cmd)
            self.runner.communicate()
            retval, reterr, retcode = self.runner.getNlogReturns()

            if not reterr:
                success = True
            else:
                raise Exception("Error trying to remove a user (" + \
                                str(reterr).strip() + ")")

            return success

    #----------------------------------------------------------------------

    def rmUserHome(self, user=""):
        """
        Remove the user home... right now only default location, but should
        look up the user home in the directory service and remove that
        specifically.

        @author: Roy Nielsen
        """
        success = False
        if self.isSaneUserName(user):

            #####
            #
            # ***** WARNING WILL ROBINSON *****
            #
            # Please refactor to do a lookup of the user in the directory
            # service, and use the home directory specified there..
            #
            try:
                shutil.rmtree("/Users/" + str(user))
            except IOError or OSError, err:
                self.logger.log(lp.INFO, "Exception trying to remove user home...")
                self.logger.log(lp.INFO, "Exception: " + str(err))
                raise err
            else:
                success = True

        return success

    #----------------------------------------------------------------------

    def rmUserFromGroup(self, user="", group=""):
        """
        """
        success = False

        if self.isSaneUserName(user) and self.isSaneGroupName(group):
            isSetDSCL = self.setDscl(".", "-delete", "/Groups/" + str(group),
                                     "GroupMembership", str(user))
        if isSetDSCL:
            success = True

        return success

    #----------------------------------------------------------------------
    # Mac OS Specific Methods
    #----------------------------------------------------------------------

    def setDscl(self, directory=".", action="", dirObject="", dirProperty="", value=""):
        """
        Using dscl to set a value in a directory...

        @author: Roy Nielsen
        """
        success = False
        reterr = ""
        retval = ""
        #####
        # If elevated, use the liftDown runner method to run the command as
        # a regular user.
        if directory and action and object and property:
            if directory and action and object and property and value:
                cmd = [self.dscl, directory, action, dirObject, dirProperty, value]
            else:
                cmd = [self.dscl, directory, action, dirObject, dirProperty]

            self.runner.setCommand(cmd)
            if re.match("^%0$", str(os.getuid()).strip()):
                passfound = False
                for arg in cmd:
                    if re.match('password', arg):
                        passfound = True
                        break
    
                if not '-P' in cmd and not passfound:
                    self.logger.log(lp.DEBUG, "dscl-cmd: " + str(cmd))

                #####
                # Run the command, lift down...
                self.runner.liftDown(self.userName)
                self.logger.log(lp.INFO, "Took the lift down...")
                retval, reterr, retcode = self.runner.getNlogReturns()
                if not reterr:
                    success = True
            else:
                #####
                # Run the command
                retval, reterr, retcode = self.runner.communicate()

                if not reterr:
                    success = True

            retval, reterr, retcode = self.runner.getNlogReturns()

        return success

    #----------------------------------------------------------------------

    def getDscl(self, directory="", action="", dirobj="", dirprop="", subprop=""):
        """
        Using dscl to retrieve a value from the directory

        @author: Roy Nielsen
        """
        success = False
        reterr = ""
        retval = ""

        #####
        # FIRST VALIDATE INPUT!!
        if isinstance(directory, basestring) and re.match("^[/\.][A-Za-z0-9/]*", directory):
            success = True
        else:
            success = False
        if isinstance(action, basestring) and re.match("^[-]*[a-z]+", action) and success:
            success = True
        else:
            success = False
        if isinstance(dirobj, basestring) and re.match("^[A-Za-z0=9/]+", dirobj) and success:
            success = True
        else:
            success = False
        if isinstance(dirprop, basestring) and re.match("^[A-Za-z0-9]+", dirprop) and success:
            success = True
        else:
            success = False
        self.logger.log(lp.CRITICAL, "SUCCESS: " + str(success))
        #####
        # Now do the directory lookup.
        if success:
            if directory and action and dirobj and dirprop and subprop:
                cmd = [self.dscl, directory, action, dirobj, dirprop, subprop]
            else:
                cmd = [self.dscl, directory, action, dirobj, dirprop]

            self.runner.setCommand(cmd)
            self.runner.communicate()
            retval, reterr, retcode = self.runner.getNlogReturns()

            if not reterr:
                success = True
            else:
                raise DsclError("Error trying to get a value with dscl (" + \
                                str(reterr).strip() + ")")
        return retval

    #----------------------------------------------------------------------

    def isUserAnAdmin(self, userName=""):
        """
        Check if this user is in this group
        
        @author: Roy Nielsen
        """
        success = False
        if self.isSaneUserName(userName):
            success = self.isUserInGroup(userName, "admin")
        return success

    #----------------------------------------------------------------------

    def acquireUserData(self):
        """
        Acquire user data for local user lookup information.
        
        @author: Roy Nielsen
        """
        pass
        
