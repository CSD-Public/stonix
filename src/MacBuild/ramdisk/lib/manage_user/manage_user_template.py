"""
Cross platform user creation and management

Created for testing cross user testing for the ramdisk project, specifically
unionfs functionality.

@author: Roy Nielsen
"""
from __future__ import absolute_import
import os
import re
import inspect

from ..run_commands import RunWith
from ..loggers import CyLogger
from ..loggers import LogPriority as lp
from ..CheckApplicable import CheckApplicable
from ..environment import Environment


class BadUserInfoError(Exception):
    """
    Meant for being thrown when an action/class being run/instanciated is not
    applicable for the running operating system.

    @author: Roy Nielsen
    """
    def __init__(self, *args, **kwargs):
        Exception.__init__(self, *args, **kwargs)


class DsclError(Exception):
    """
    Meant for being thrown when an action/class being run/instanciated is not
    applicable for the running operating system.

    @author: Roy Nielsen
    """
    def __init__(self, *args, **kwargs):
        Exception.__init__(self, *args, **kwargs)


class RootAccessRequired(Exception):
    """
    Meant for being thrown when a uid is not zero.

    @author: Roy Nielsen
    """
    def __init__(self, *args, **kwargs):
        Exception.__init__(self, *args, **kwargs)


class ManageUserTemplate(object):
    """
    Class to manage user properties.

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
        else:
            self.logger = kwargs.get('logDispatcher')

        if 'userName' not in kwargs:
            self.userName = ""
        else:
            self.userName = kwargs.get('userName')

        if 'userShell' not in kwargs:
            self.userShell = "/bin/bash"
        else:
            userShell = kwargs.get('userShell')

        if 'userComment' not in kwargs:
            self.userComment = ""
        else:
            self.userComment = kwargs.get('userComment')

        if 'userUid' not in kwargs:
            self.userUid = 10000
        else:
            self.userUid = kwargs.get('userUid')

        if 'userPriGid' not in kwargs:
            self.userPriGid = 20
        else:
            self.userPriGid = kwargs.get('userPriGid')

        if 'userHomeDir' not in kwargs:
            self.userHomeDir = ""
        else:
            self.userHomeDir = kwargs.get('userHomeDir')

        self.module_version = '20160225.125554.540679'


        #####
        # Template for data to acquire for a user. Cross-platform data.
        userData = {'userName' : "",
                    'userShell' : "",
                    'userComment' : "",
                    'userUid' : "",
                    'userPriGid' : "",
                    'userGroups' : "",
                    'userHomeDir' : ""}

        #####
        # Acqure the environment
        self.environ = Environment()

        #####
        # THIS IS A LIBRARY, SO LOGS SHOULD BE INITIALIZED ELSEWHERE...
        # self.logger.initializeLogs()
        self.logger.log(lp.INFO, "Logger: " + str(self.logger))

        #####
        # Initialize the RunWith helper for executing shelled out commands.
        self.runWith = RunWith(self.logger)

    #----------------------------------------------------------------------

    def isSaneFilePath(self, filepath):
        """
        Check for a good file path in the passed in string.
        
        @author: Roy Nielsen
        """
        sane = False
        if isinstance(filepath, basestring):
            if re.match("^[A-Za-z/\.][A-Za-z0-9/\.]*", filepath):
                sane = True
        return sane

    #----------------------------------------------------------------------

    def isSaneUserName(self, userName=""):
        """
        Check to make sure the username fits this specific definition/specification
        for a username.
        
        @author: Roy Nielsen
        """
        sane = False
        if userName and isinstance(userName, basestring):
            if re.match("^[A-Za-z][A-Za-z0-9]*", userName):
                sane = True
        return sane

    #----------------------------------------------------------------------

    def isSaneGroupName(self, groupName=""):
        """
        Check to make sure the groupName fits this specific
        definition/specification for a username.
        
        @author: Roy Nielsen
        """
        sane = False
        if groupName and isinstance(groupName, basestring):
            if re.match("^[A-Za-z][A-Za-z0-9]*", groupName):
                sane = True
        return sane

    #----------------------------------------------------------------------

    def isSaneUserShell(self, userShell=""):
        """
        Check to make sure that the "userShell" variable is a valid file path
        
        @author: Roy Nielsen
        """
        sane = False
        if self.isSaneFilePath(userShell):
            sane = True
        return sane

    #----------------------------------------------------------------------

    def isSaneUserComment(self, userComment=""):
        """
        User Comment field, usually for a user's "Long" or full name.
        
        @author: Roy Nielsen
        """
        sane = False
        if userComment and isinstance(userComment, basestring):
            if re.match("^[A-Za-z][A-Za-z0-9]*", userComment):
                sane = True
        return sane

    #----------------------------------------------------------------------

    def isSaneUserUid(self, userUid=""):
        """
        Check to make sure the userUid is a string or a number.
        
        @author: Roy Nielsen
        """
        sane = False
        if userUid and isinstance(userUid, [basestring, int]):
            if re.match("^\d+", str(userUid)):
                sane = True
        return sane

    #----------------------------------------------------------------------

    def isSaneUserPriGid(self, userPriGid=1000):
        """
        Check to make sure the user's primary group ID is valid.
        
        @author: Roy Nielsen
        """
        sane = False
        if userPriGid and isinstance(userPriGid, [basestring, int]):
            if re.match("^\d+", str(userPriGid)):
                sane = True
        return sane

    #----------------------------------------------------------------------

    def isSaneUserHomeDir(self, userHomeDir=""):
        """
        Check to make sure the user's home directory is a valid file path.
        
        @author: Roy Nielsen
        """
        sane = False
        if self.isSaneFilePath(userHomeDir):
            sane = True
        return sane

    #----------------------------------------------------------------------

    def setUserName(self, userName=""):
        """
        Setter for the user's username.
        
        @author: Roy Nielsen
        """
        sane = False
        if self.isSaneUserName(userName):
            sane = True
            self.userName = userName
        return sane

    #----------------------------------------------------------------------

    def setPasswordCompliance(self, complianceType=0):
        """
        Set type type of compliance that user's password needs to be validated
        with.

        @param: complianceType: must be a number, in the validation list.

        @note: Valid numbers and their meanings are:
               0: Must be eight characters long, any combination of letters,
                  numbers and special characters

               1: Must have three of: Upper case, Lower case letters, numbers,
                  and special characters, and be eight characters long, and
                  be in the 0 compliance set.  Must be a minimum of ten
                  characters long.

               2: Must have a minimum of one of each of Upper case, Lower case
                  letters, numbers and special characters.  Must be a minimum of
                  14 characters long, and all characters be in the 0 compliance
                  set.

        @author: Roy Nielsen
        """
        success = False
        validCompliance = [0, 1, 2]

        if complianceType in validCompliance:
            self.complianceType = complianceType
            success = True

        return success

    #----------------------------------------------------------------------

    def isPasswordCompliant(self, password=""):
        """
        Check if the password is compliant with the set password policy.
        
        @Note: this is for ASCII text only.
        
        @param: password - password to check for compliance
        
        @returns: a list of which compliant types succeed.  The index of the
                  list is the compliance type.

        @author: Roy Nielsen
        """
        #####
        # From the ASCII character map:
        NUMLOWER    = 48  # 48 = 0
        NUMUPPER    = 57  # 57 = 9
        LOWERBOUND  = 65  # 65 = A
        UPPERBOUND  = 90  # 90 = Z
        LOWERBOUND1 = 97  # 97 = a
        UPPERBOUND1 = 122 # 122 = z
        SYMLOWER    = 33  # 33 = !
        SYMUPPER    = 46  # 46 = .
        # These ranges are used to ensure that someone isn't trying to use
        # control characters for the password to try to exploit an
        # authentication mechanism.
        #####

        types = 0
        checkZero = False
        checkOne = False
        checkTwo = False
        if len(str(password)) >= 8:
            #####
            # Iterate over the string and make sure all of the characters
            # are allowed for a password
            for char in str(password):
                ascii_char = ord(char)
                if char in range(NUMLOWER, NUMUPPER) or \
                   ascii_char in range(LOWERBOUND, UPPERBOUND) or \
                   ascii_char in range(LOWERBOUND1, UPPERBOUND1) or \
                   ascii_char in range(SYMLOWER, SYMUPPER):
                    checkZero = True
                else:
                    checkZero = False
                    break

        if checkOne:
            #####
            # Count variable categories
            for char in str(password):
                ascii_char = ord(char)
                if ascii_char in range(NUMLOWER, NUMUPPER):
                    num = 1
                if ascii_char in range(LOWERBOUND, UPPERBOUND):
                    upperChar = 1
                if ascii_char in range(LOWERBOUND1, LOWERBOUND1):
                    lowerChar = 1
                if ascii_char in range(SYMLOWER, SYMUPPER):
                    special = 1
            #####
            # Add up the types to see for the compliance check below
            types = num + upperChar + lowerChar + special
            #####
            # Check if compliance type 1 or 2 are met
            if types >= 3 and len(str(password)) >= 10:
                #####
                # Check for compliance type one
                checkOne = True
            elif types == 4 and len(str(password)) >= 14:
                #####
                # Check for compliance type two
                checkTwo = True
            else:
                checkOne = False
                checkTwo = False

        return [checkZero, checkOne, checkTwo]

    #----------------------------------------------------------------------

    def isUserInSudoers(self, userName=""):
        """
        Check if user can sudo.

        @author: Roy Nielsen
        """
        success = False
        users = []
        groups = []
        
        #####
        # Check the UID of the user
        if not os.getuid() == 0:
            raise RootAccessRequired("Must be root to use this method...")
        
        #####
        # Acquire data from the sudoers file
        try:
            sudoers = os.open("/etc/sudoers", "r")
        except OSError:
            print "Problem trying to open the sudoers file for reading..."
        else:
            lines = sudoers.readlines()
            #####
            # Set up an array of patterns to skip
            skippers = [ re.compile(p) for p in [ '^#', '^Default', "^\s"]]
            for line in lines:
                #####
                # Check for lines to skip first
                for regex in skippers:
                    if regex.match(line):
                        continue
                #####
                # Set up for a username match check
                usr = re.compile("^([A-Za-z][A-Za-z0-9]+)\s+ALL=\(ALL\)\s+ALL.*")
                #####
                # Set up for a groupname match check
                grp = re.compile("^[\%]([A-Za-z][A-Za-z0-9]+)\s+ALL=\(ALL\)\s+ALL.*")
                #####
                # Try to acquire a username and put it in the users list
                try:
                    user = usr.match(line).group(1)
                except TypeError:
                    pass
                except AttributeError:
                    pass
                else:
                    users.append(user)
                #####
                # Try to catch a group name and put it in the groups list
                try:
                    group = grp.match(line).group(1)
                except TypeError:
                    pass
                except AttributeError:
                    pass
                else:
                    groups.append(group)

        #####
        # Check if the user is in the user list        
        if userName in users:
            success = True
        #####
        # Check if the user is in one of the groups in the groups list
        if not success:
            for group in groups:
                if self.isUserInGroup(userName):
                    success = True
                    break
        return success

    def isQualifiedLiftAttendant(self, userName=""):
        """
        Will return true if the user running the script is in a default
        operating system group that can elevate privilege.  Traditionally 
        'wheel' on Linux and 'admin' on Mac.
        
        A 'lift attendant' is an elevator operator in fancy hotels.
        
        @author: Roy Nielsen
        """
        success = False

        if self.isSaneUserName(userName):
    
            checkApplicable = CheckApplicable(self.environ, self.logger)
            #####
            # Set the isapplicable parameters for checking if the current OS
            # is applicable to this code.
            macApplicable = {'type': 'white',
                             'family': ['darwin'],
                             'os': {'Mac OS X': ['10.9', 'r', '10.11.10']}}
            #####
            # Set the isapplicable parameters for checking if the current OS
            # is applicable to this code.
            linuxApplicable = {'type': 'white',
                               'family': ['linux']}
            #####
            # perform the isapplicable check
            if checkApplicable.isApplicable(macApplicable):
                #####
                # If in the correct group, success = True
                if self.isUserInGroup(userName="", groupName="admin"):
                    success = True
            elif checkApplicable.isApplicable(linuxApplicable):
                #####
                # If in the correct group, success = True
                if self.isUserInGroup(userName="", groupName="wheel"):
                    success = True

        return success

    #----------------------------------------------------------------------
    # Getters
    #----------------------------------------------------------------------

    def findUniqueUid(self):
        """
        """
        pass

    #----------------------------------------------------------------------

    def uidTaken(self, uid):
        """
        """
        pass

    #----------------------------------------------------------------------

    def getUser(self, userName=""):
        """
        """
        pass

    #----------------------------------------------------------------------

    def getUserShell(self, userName=""):
        """
        """
        pass

    #----------------------------------------------------------------------

    def getUserComment(self, userName=""):
        """
        """
        pass

    #----------------------------------------------------------------------

    def getUserUid(self, userName=""):
        """
        """
        pass

    #----------------------------------------------------------------------

    def getUserPriGid(self, userName=""):
        """
        """
        pass

    #----------------------------------------------------------------------

    def getUserHomeDir(self, userName=""):
        """
        """
        pass

    #----------------------------------------------------------------------

    def isUserInstalled(self, user=""):
        """
        """
        pass

    #----------------------------------------------------------------------

    def isUserInGroup(self, userName="", groupName=""):
        """
        """
        pass

    #----------------------------------------------------------------------

    def authenticate(self, user="", password=""):
        """
        """
        pass

    #----------------------------------------------------------------------
    # Setters
    #----------------------------------------------------------------------

    def createStandardUser(self, userName, password):
        """
        Creates a user that has the "next" uid in line to be used, then puts
        in in a group of the same id.  Uses /bin/bash as the standard shell.
        The userComment is left empty.  Primary use is managing a user
        during test automation, when requiring a "user" context.

        @author: Roy Nielsen
        """
        pass

    #----------------------------------------------------------------------

    def createBasicUser(self, userName=""):
        """
        Create a username with just a moniker.  Allow the system to take care of
        the rest.

        Only allow usernames with letters and numbers.

        @author: Roy Nielsen
        """
        pass

    #----------------------------------------------------------------------

    def setUserShell(self, user="", shell=""):
        """
        """
        pass

    #----------------------------------------------------------------------

    def setUserComment(self, user="", comment=""):
        """
        """
        pass

    #----------------------------------------------------------------------

    def setUserUid(self, user="", uid=""):
        """
        """
        pass

    #----------------------------------------------------------------------

    def setUserPriGid(self, user="", priGid=""):
        """
        """
        pass

    #----------------------------------------------------------------------

    def setUserHomeDir(self, user="", userHome=""):
        """
        """
        pass

    #----------------------------------------------------------------------

    def addUserToGroup(self, user="", group=""):
        """
        """
        pass

    #----------------------------------------------------------------------

    def rmUserFromGroup(self, user="", group=""):
        """
        """
        pass

    #----------------------------------------------------------------------

    def setUserPassword(self, user="", password=""):
        """
        """
        pass

    #----------------------------------------------------------------------

    def fixUserHome(self, userName=""):
        """
        Get the user information from the local directory and fix the user
        ownership and group of the user's home directory to reflect
        what is in the local directory service.

        @author: Roy Nielsen
        """
        pass

    #----------------------------------------------------------------------
    # User Property Removal
    #----------------------------------------------------------------------

    def rmUser(self, user=""):
        """
        """
        pass

    #----------------------------------------------------------------------

    def rmUserHome(self, user=""):
        """
        Get the user information from the local directory and fix the user
        ownership and group of the user's home directory to reflect
        what is in the local directory service.

        @author: Roy Nielsen
        """
        pass
