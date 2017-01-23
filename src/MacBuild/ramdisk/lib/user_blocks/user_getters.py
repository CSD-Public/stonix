import re

from ..Environment import Environment
from ..CheckApplicable import CheckApplicable
from ..loggers import LogPriority as lp

class UserGetters(object):
    '''
    '''
    def __init__(self, *args, **kwargs):
        '''
        Initialization method
        '''
        self.logger = logger
        self.macApplicable = {'type': 'white', 'os': {'Mac OS X': ['10.9', 'r', '10.12.10']}}
        self.nixApplicable = {'type': 'white', 'family': ['linux', 'solaris', 'freebsd']}

        chkApp = CheckApplicable(self.logger)

        chkApp.setApplicable(macApplicable)
        self.macApplicable = chkApp.isapplicable()
        
        chkApp.setApplicable(nixApplicable)
        self.nixApplicable = chkApp.isapplicable()
        
        self.userGetters = getUserObject()
        
    def getUserObject(directoryIdentifier="local"):
        '''
        Return an appropriate getter, either matching a user directory or 
        OS or both.
        
        @param: directoryIdentifier - Where to look for user info.  Initial only
                                      on the local system.  Later LDAP and AD
                                      directory support may be added.

        @author: Roy Nielsen
        '''
        userGetters = None

        #####
        # Validate expected required input        
        if isinstance(directoryIdentifier, basestring) and \
           re.match("^local$", directoryIdentifier):

            if self.macApplicable or self.nixApplicable:
                from .local_pwd_getters import LocalPwdGetters
                user_getters = LocalPwdGetters(self.loggers)
        return user_getters

    """
    """
    def getAllLocalUsersInfo(self):
        '''
        Return the pwd.getpwall() dictionary

        @author: Roy Nielsen
        '''
        return self.userGetters.getAllUsers()
        
    def getUserInfo(self, userName="", uid=NOBODY):
        '''
        Collect all information available about a user.  Currently only what is
        available via either pwd.getpwuid or pwd.getpwnam.

        @param: userName - Name of the local user to querry
        @param: uid - UID of the local user to querry

        @note: Defaults to trying userName first, if that isn't valid or
               available, it will try the uid.

        @author: Roy Nielsen
        '''
        userInfo = False
        if userName:
            userInfo = self.userGetters.getUserInfo(userName=userName)
        else:
            userInfo = self.userGetters.getUserInfo(uid=uid)
            
        return userInfo

    def getLoginName(self, uid=NOBODY):
        '''
        @param: uid - UID of the local user to querry

        @author: Roy Nielsen
        '''
        return self.userGetters.getLoginName(uid=uid)

    def getUid(self, userName=""):
        '''
        @param: userName - Name of the local user to querry

        @author: Roy Nielsen
        '''
        return self.userGetters.getUid(userName=userName)

    def getGid(self, userName="", uid=NOBODY):
        '''
        @param: userName - Name of the local user to querry
        @param: uid - UID of the local user to querry

        @note: Defaults to trying userName first, if that isn't valid or
               available, it will try the uid.

        @author: Roy Nielsen
        '''
        userGid = False
        if userName:
            userGid = self.userGetters.getGid(userName=userName)
        else:
            userGid = self.userGetters.getGid(uid=uid)
            
        return userGid

    def getGecos(self, userName="", uid=NOBODY):
        '''
        @param: userName - Name of the local user to querry
        @param: uid - UID of the local user to querry

        @note: Defaults to trying userName first, if that isn't valid or
               available, it will try the uid.

        @author: Roy Nielsen
        '''
        userGecos = False
        if userName:
            userGecos = self.userGetters.getGecos(userName=userName)
        else:
            userGecos = self.userGetters.getGecos(uid=uid)
            
        return userGecos

    def getHomeDir(self, userName="", uid=NOBODY):
        '''
        @param: userName - Name of the local user to querry
        @param: uid - UID of the local user to querry

        @note: Defaults to trying userName first, if that isn't valid or
               available, it will try the uid.

        @author: Roy Nielsen
        '''
        userHome = False
        if userName:
            userHome = self.userGetters.getHomeDir(userName=userName)
        else:
            userHome = self.userGetters.getHomeDir(uid=uid)
            
        return userHome

    def getShell(self, userName="", uid=NOBODY):
        '''
        @param: userName - Name of the local user to querry
        @param: uid - UID of the local user to querry

        @note: Defaults to trying userName first, if that isn't valid or
               available, it will try the uid.

        @author: Roy Nielsen
        '''
        userShell = False
        if userName:
            userShell = self.userGetters.getShell(userName=userName)
        else:
            userShell = self.userGetters.getShell(uid=uid)
            
        return userShell

    def findUniqueUid(self):
        """
        We need to make sure to find an unused uid (unique ID) for the user,
           $ dscl . -list /Users UniqueID
        will list all the existing users, an unused number above 500 is good.

        @author: Roy Nielsen
        """
    def uidTaken(self, uid):
        """
        See if the UID requested has been taken.  Only approve uid's over 1k
           $ dscl . -list /Users UniqueID

        @author: Roy Nielsen
        """
        taken = True
        try:
            self.getLoginName(uid)
        except (KeyError, IndexError):
            taken = False
        return taken

    def isUserInstalled(self, userName=""):
        """
        Check if the user "user" is installed

        @author Roy Nielsen
        """
        userExists = True
        try:
            self.getLoginName(userName)
        except (KeyError, IndexError):
            userExists = False
        return userExists

    def authenticate(self, user="", password=""):
        """
        Attempt an authentication event, will return either True for succes,
        or False for failed attempted login.

        Use the RunWith class's runAs method to attempt to use su -m <user>
        to try to print "hello world".  If it gets printed, we have success,
        otherwise, we have an authentication failure.

        @param: user - name of a user to check
        @param: password - to check if the password is correct for this user

        @author: Roy Nielsen
        """
        authenticated = False

        if not self.isSaneUserName(user) or \
           re.match("^\s+$", password) or not password:
            self.logger.log(lp.INFO, "Cannot pass in empty or bad parameters...")
            self.logger.log(lp.INFO, "user = \"" + str(user) + "\"")
            self.logger.log(lp.INFO, "check password...")
        else:
            
            self.runWith.setCommand(['/bin/echo', 'hello world'])
            
            output, error, retcode = self.runWith.runAs(user, password)
            
            self.logger.log(lp.DEBUG, "Output: " + str(output.strip()))
            
            if re.match("^hello world$", output.strip()):
                authenticated = True

        return authenticated
