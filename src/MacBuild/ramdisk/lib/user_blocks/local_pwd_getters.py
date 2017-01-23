from __future__ import absolute_import
import pwd

from lib.CheckApplicable import CheckApplicable
from lib.environment import Environment
from lib.loggers import CyLogger

environ = Environment()
mylogger = CyLogger(debug_mode=True)
mylogger.initializeLogs()
chkApp = CheckApplicable(environ, mylogger)

macApplicable = {'type': 'white', 'os': {'Mac OS X': ['10.9', 'r', '10.12.10']}}
nixApplicable = {'type': 'white', 'family': ['linux', 'solaris', 'freebsd']}

#####
# For macOS, initialize nobody to -2 if pw_uid returns an unsigned 32 bit value
# greater than 0x7fffffff
chkApp.setApplicable(macApplicable)
if chkApp.isapplicable():
    NOBODY_UNSIGNED = pwd.getpwnam("nobody").pw_uid
    if NOBODY_UNSIGNED > 0x7fffffff:
        NOBODY = NOBODY_UNSIGNED - 4294967296

#####
# for Linux and other *nix xyxtems, assign
# nobody's uid appropriately
chkApp.setApplicable(nixApplicable)
if chkApp.isapplicable():
    NOBODY = pwd.getpwnam("nobody").pw_uid


class LocalPwdInfo(object):
    '''
    User object that uses the python 'pwd' native library to querry information
    about local users on the system.  Cross platform *nix.

    @author: Roy Nielsen
    '''
    def __init__(self, logger):
        '''
        Class initializer

        @param: logger - a pre-defined instance of CyLogger
a
        @author: Roy Nielsen
        '''
        self.logger = logger
        self.userDb = pwd.getpwall()
        self.userInfo = {}
        self.loginName = ""
        self.uid = NOBODY
        self.userGid = NOBODY
        self.userGecos = ""
        self.userHomeDir = ""
        self.userShell = ""

    def getAllLocalUsersInfo(self):
        '''
        Return the pwd.getpwall() dictionary

        @author: Roy Nielsen
        '''
        return pwd.getpwall()

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
        success = False

        if userName and isinstance(userName, basestring):
            self.userInfo = pwd.getpwnam(userName)
            success = True
        elif isinstance(uid, int) and not uid == NOBODY:
            self.userInfo = pwd.getpwuid(uid)
            success = True

        return success

    def getLoginName(self, uid=NOBODY):
        '''
        @param: uid - UID of the local user to querry

        @author: Roy Nielsen
        '''
        success = False
        if isinstance(uid, int):
            self.loginName = pwd.getpwuid(uid).pw_name
            success = True
        return success

    def getUid(self, userName=""):
        '''
        @param: userName - Name of the local user to querry

        @author: Roy Nielsen
        '''
        success = False
        if userName and isinstance(userName, basestring):
            self.uid = pwd.getpwnam()
            success = True
        return success

    def getGid(self, userName="", uid=NOBODY):
        '''
        @param: userName - Name of the local user to querry
        @param: uid - UID of the local user to querry

        @note: Defaults to trying userName first, if that isn't valid or
               available, it will try the uid.

        @author: Roy Nielsen
        '''
        success = False

        if userName and isinstance(userName, basestring):
            self.userGid = pwd.getpwnam(userName).pw_gid
            success = True
        elif isinstance(uid, int) and not uid == NOBODY:
            self.userGid = pwd.getpwuid(uid).pw_gid
            success = True

        return success

    def getGecos(self, userName="", uid=NOBODY):
        '''
        @param: userName - Name of the local user to querry
        @param: uid - UID of the local user to querry

        @note: Defaults to trying userName first, if that isn't valid or
               available, it will try the uid.

        @author: Roy Nielsen
        '''
        success = False

        if userName and isinstance(userName, basestring):
            self.userGecos = pwd.getpwnam(userName).pw_gecos
            success = True
        elif isinstance(uid, int) and not uid == NOBODY:
            self.userGecos = pwd.getpwuid(uid).pw_gecos
            success = True

        return success

    def getHomeDir(self, userName="", uid=NOBODY):
        '''
        @param: userName - Name of the local user to querry
        @param: uid - UID of the local user to querry

        @note: Defaults to trying userName first, if that isn't valid or
               available, it will try the uid.

        @author: Roy Nielsen
        '''
        success = False

        if userName and isinstance(userName, basestring):
            self.userHomeDir = pwd.getpwnam(userName).pw_dir
            success = True
        elif isinstance(uid, int) and not uid == NOBODY:
            self.userHomeDir = pwd.getpwuid(uid).pw_dir
            success = True

        return success

    def getShell(self, userName="", uid=NOBODY):
        '''
        @param: userName - Name of the local user to querry
        @param: uid - UID of the local user to querry

        @note: Defaults to trying userName first, if that isn't valid or
               available, it will try the uid.

        @author: Roy Nielsen
        '''
        success = False

        if userName and isinstance(userName, basestring):
            self.userInfo = pwd.getpwnam(userName).pw_shell
            success = True
        elif isinstance(uid, int) and not uid == NOBODY:
            self.userInfo = pwd.getpwuid(uid).pw_shell
            success = True

        return success
