###############################################################################
#                                                                             #
# Copyright 2019. Triad National Security, LLC. All rights reserved.          #
# This program was produced under U.S. Government contract 89233218CNA000001  #
# for Los Alamos National Laboratory (LANL), which is operated by Triad       #
# National Security, LLC for the U.S. Department of Energy/National Nuclear   #
# Security Administration.                                                    #
#                                                                             #
# All rights in the program are reserved by Triad National Security, LLC, and #
# the U.S. Department of Energy/National Nuclear Security Administration. The #
# Government is granted for itself and others acting on its behalf a          #
# nonexclusive, paid-up, irrevocable worldwide license in this material to    #
# reproduce, prepare derivative works, distribute copies to the public,       #
# perform publicly and display publicly, and to permit others to do so.       #
#                                                                             #
###############################################################################

'''
Created on May 20, 2013

@author: Derek Walker
@change: 02/16/2014 ekkehard Implemented self.detailedresults flow
@change: 02/16/2014 ekkehard Implemented isapplicable
@change: 04/21/2014 dkennel Updated CI invocation
@change: 2014/10/17 ekkehard OS X Yosemite 10.10 Update
@change: 2015/04/17 dkennel updated for new isApplicable
@change: 2017/07/17 ekkehard - make eligible for macOS High Sierra 10.13
@change: 2017/11/13 ekkehard - make eligible for OS X El Capitan 10.11+
@change: 2018/06/08 ekkehard - make eligible for macOS Mojave 10.14
@change: 2019/03/12 ekkehard - make eligible for macOS Sierra 10.12+
@change: 2018/06/28 Breen Malmberg - re-wrote much of the rule; added doc strings
        to some existing methods
@change: 2019/08/07 ekkehard - enable for macOS Catalina 10.15 only
'''



import traceback
import os
import stat
import re
import pwd

from stonixutilityfunctions import readFile
from rule import Rule
from logdispatcher import LogPriority
from CommandHelper import CommandHelper


class SecureHomeDir(Rule):
    '''classdocs'''

    def __init__(self, config, environ, logger, statechglogger):
        '''

        @param config:
        @param environ:
        @param logger:
        @param statechglogger:
        '''

        Rule.__init__(self, config, environ, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 45
        self.rulename = "SecureHomeDir"
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.rootrequired = False
        datatype = 'bool'
        key = 'SECUREHOME'
        instructions = '''To disable this rule set the value of SECUREHOME to False.'''
        default = True
        self.ci = self.initCi(datatype, key, instructions, default)
        self.guidance = ['NSA 2.3.4.2']
        self.applicable = {'type': 'white',
                           'family': ['linux', 'solaris', 'freebsd'],
                           'os': {'Mac OS X': ['10.15', 'r', '10.15.10']}}
        self.sethelptext()

    def report(self):
        '''report the compliance status of the permissions on all local user
        home directories


        :returns: self.compliant

        :rtype: bool
@author: Derek Walker

        '''

        self.detailedresults = ""
        self.compliant = True
        self.cmdhelper = CommandHelper(self.logger)
        self.WRHomeDirs = []
        self.GWHomeDirs = []

        try:

            if self.environ.getostype() == "Mac OS X":
                self.compliant = self.reportMac()
            else:
                self.compliant = self.reportLinux()

            if not self.WRHomeDirs:
                self.detailedresults += "\nNo world readable home directories found."
            if not self.GWHomeDirs:
                self.detailedresults += "\nNo group writeable home directories found."

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.compliant = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

    def reportMac(self):
        '''check all user local home directories, on Mac OS X, for correct permissions


        :returns: compliant

        :rtype: bool
@author: Derek Walker
@change: Breen Malmberg - 10/13/2015 - moved grpvals variable up to top where it should be; fixed logging;
                                        will no longer report on /var/empty or /dev/null permissions

        '''

        compliant = True

        try:

            if self.environ.geteuid() == 0:
                # running as root/admin
                homedirs = self.getMacHomeDirs()

                if homedirs:

                    self.logger.log(LogPriority.DEBUG, "Scanning home directories...")
                    for hd in homedirs:
                        if not os.path.exists(hd):
                            self.logger.log(LogPriority.DEBUG, "Skipping directory " + hd + " because it does not exist...")
                            continue

                        self.logger.log(LogPriority.DEBUG, "Checking " + hd)
                        if self.isGW(hd):
                            compliant = False
                            self.detailedresults += "\nThe home directory: " + str(hd) + " is group-writeable"
                            self.GWHomeDirs.append(hd)
                        if self.isWR(hd):
                            compliant = False
                            self.detailedresults += "\nThe home directory: " + str(hd) + " is world-readable"
                            self.WRHomeDirs.append(hd)
                else:
                    self.logger.log(LogPriority.DEBUG, "No home directories found!")
            else:
                # running as a normal user
                homedir = self.getMyHomeDir()
                if os.path.exists(homedir):
                    if self.isGW(homedir):
                        compliant = False
                        self.detailedresults += "\nThe home directory: " + str(homedir) + " is group-writeable"
                        self.GWHomeDirs.append(homedir)
                    if self.isWR(homedir):
                        compliant = False
                        self.detailedresults += "\nThe home directory: " + str(homedir) + " is world-readable"
                        self.WRHomeDirs.append(homedir)
                else:
                    self.logger.log(LogPriority.DEBUG, "Skipping directory " + homedir + " because it does not exist...")

        except Exception:
            raise

        return compliant

    def isGW(self, path):
        '''determine if a given path is group writeable

        :param path: string; absolute file path to scan
        :returns: groupwriteable
        :rtype: bool
@author: Breen Malmberg

        '''

        groupwriteable = False

        try:

            mode = os.stat(path).st_mode
            groupwriteable = bool(mode & stat.S_IWGRP)

        except Exception:
            raise

        return groupwriteable

    def isWR(self, path):
        '''determine if a given path is world readable

        :param path: string; absolute file path to scan
        :returns: worldreadable
        :rtype: bool
@author: Breen Malmberg

        '''

        worldreadable = False

        try:

            mode = os.stat(path).st_mode
            worldreadable = bool(mode & stat.S_IROTH)

        except Exception:
            raise

        return worldreadable

    def getMacHomeDirs(self):
        '''get a list of user home directories on the Mac


        :returns: homedirs

        :rtype: list
@author: Breen Malmberg

        '''

        self.logger.log(LogPriority.DEBUG, "Building list of Mac local user home directories...")

        HomeDirs = []
        getAccountsList = ["/usr/bin/dscl", ".", "list", "/Users"]
        UsersList = []

        try:

            self.cmdhelper.executeCommand(getAccountsList)

            retcode = self.cmdhelper.getReturnCode()
            if retcode != 0:
                errstr = self.cmdhelper.getErrorString()
                self.logger.log(LogPriority.DEBUG, errstr)
                return HomeDirs

            AccountsList = self.cmdhelper.getOutput()

            # filter out any system accounts
            # (we want only user accounts)
            if AccountsList:
                for acc in AccountsList:
                    if not re.search("^_", acc, re.IGNORECASE) and not re.search("^root", acc, re.IGNORECASE):
                        UsersList.append(acc)

            if UsersList:
                for u in UsersList:
                    try:
                        currpwd = pwd.getpwnam(u)
                    except KeyError:
                        UsersList.remove(u)
                        continue
                    HomeDirs.append(currpwd[5])

            if not HomeDirs:
                self.logger.log(LogPriority.DEBUG, "No home directories found")
            else:
                HomeDirs = self.validateHomedirs(HomeDirs)

        except Exception:
            raise

        return HomeDirs

    def getLinuxHomeDirs(self):
        '''get a list of user home directories on Linux platforms


        :returns: homedirs

        :rtype: list
@author: Breen Malmberg

        '''

        self.logger.log(LogPriority.DEBUG, "Building list of Linux user home directories...")

        HomeDirs = []
        awk = "/usr/bin/awk"
        passwd = "/etc/passwd"
        invalidshells = ["/sbin/nologin", "/sbin/halt", "/sbin/shutdown", "/dev/null", "/bin/sync"]
        getacctscmd = awk + " -F: '{ print $1 }' " + passwd
        acctnames = []
        usernames = []

        try:

            # establish the minimum user id on this system
            uid_min = self.getUIDMIN()
            if not uid_min:
                uid_min = "500"

            if os.path.exists(awk):
                # build a list of user (non-system) account names
                self.cmdhelper.executeCommand(getacctscmd)
                acctnames = self.cmdhelper.getOutput()
            else:
                self.logger.log(LogPriority.DEBUG, "awk utility not installed! What kind of Linux are you running??")
                # alternate method of getting account names in case system
                # does not have the awk utility installed..
                f = open(passwd, 'r')
                contents = f.readlines()
                f.close()

                for line in contents:
                    sline = line.split(':')
                    if len(sline) > 1:
                        acctnames.append(sline[0])

            if acctnames:
                for an in acctnames:
                    if int(pwd.getpwnam(an).pw_uid) >= int(uid_min):
                        usernames.append(an)
            else:
                self.logger.log(LogPriority.DEBUG, "Could not find any accounts on this system!")
                return HomeDirs

            # further check to see if this might still be a system account
            # which just got added in the user id range somehow (by checking
            # the shell)
            for un in usernames:
                if pwd.getpwnam(un).pw_shell in invalidshells:
                    usernames.remove(un)

            for un in usernames:
                HomeDirs.append(pwd.getpwnam(un).pw_dir)
            # now we should be reasonably certain that the list we have are all
            # valid users (and not system accounts) but let's do one more check
            # to make sure they weren't assigned a home directory some where that
            # we don't want to modify (ex. etc or /root)
            HomeDirs = self.validateHomedirs(HomeDirs)

            if not HomeDirs:
                self.logger.log(LogPriority.DEBUG, "No home directories found")
            else:
                HomeDirs = self.validateHomedirs(HomeDirs)

        except Exception:
            raise

        return HomeDirs

    def validateHomedirs(self, dirs):
        '''strip out common system (and non-existent) directories from the given list of dirs
        and return the resultant list

        :param dirs: list; list of strings containing directories to search
        and modify
        :returns: validateddirs
        :rtype: list

@author: Breen Malmberg

        '''

        validateddirs = []
        systemdirs = ['/tmp', '/var', '/temp', '/', '/bin', '/sbin', '/etc', '/dev', '/root']

        self.logger.log(LogPriority.DEBUG, "Validating list of user home directories...")

        # if the base directory of a given path matches any of the above system directories, then we discard it
        for d in dirs:
            if os.path.exists(d):
                basepath = self.getBasePath(d)
                if basepath not in systemdirs:
                    validateddirs.append(d)
                else:
                    self.logger.log(LogPriority.DEBUG, "An account with a uid in the non-system range had a strange home directory: " + d)
                    self.logger.log(LogPriority.DEBUG, "Excluding this home directory from the list...")
            else:
                self.logger.log(LogPriority.DEBUG, "Home directory: " + d + " does not exist. Excluding it...")

        return validateddirs

    def getBasePath(self, path):
        '''get only the first (base) part of a given path

        :param path: string; full path to get base of
        :returns: basepath
        :rtype: string

@author: Breen Malmberg

        '''

        basepath = "/"

        # break path into list of characters
        pathchars = list(path)

        # remove the first '/' if it is there, to make
        # the list iteration easier
        if pathchars[0] == "/":
            del pathchars[0]

        # iterate over list of characters, adding all characters
        # before the next '/' path divider, to the basepath
        for c in pathchars:
            if c == "/":
                break
            else:
                basepath += c

        return basepath

    def getUIDMIN(self):
        '''return this system's minimum user ID start value, if configured


        :returns: uid_min

        :rtype: string
@author: Breen Malmberg

        '''

        uid_min = ""
        logindefs = "/etc/login.defs"

        try:

            # get normal user uid start value
            logindefscontents = readFile(logindefs, self.logger)
            if logindefscontents:
                for line in logindefscontents:
                    if re.search("^UID_MIN", line, re.IGNORECASE):
                        sline = line.split()
                        uid_min = sline[1]

            if not uid_min:
                self.logger.log(LogPriority.DEBUG, "Unable to determine UID_MIN")

        except Exception:
            raise

        return uid_min

    def reportLinux(self):
        '''check all user local home directories, on Linux platforms, for correct permissions


        :returns: compliant

        :rtype: bool

@author: Derek Walker
@change: Breen Malmberg - 06/28/2018 - re-wrote method

        '''

        compliant = True
        passwd = "/etc/passwd"

        try:

            if not os.path.exists(passwd):
                self.logger.log(LogPriority.DEBUG, "You have no passwd file! Cannot get lits of user home directories! Aborting.")
                compliant = False
                return compliant

            if self.environ.geteuid() == 0:
                # running as root/admin
                homedirs = self.getLinuxHomeDirs()

                if homedirs:

                    self.logger.log(LogPriority.DEBUG, "Scanning home directory permissions...")
                    for hd in homedirs:
                        if not os.path.exists(hd):
                            self.logger.log(LogPriority.DEBUG, "Skipping directory " + hd + " because it does not exist...")
                            continue

                        self.logger.log(LogPriority.DEBUG, "Checking " + hd)
                        if self.isGW(hd):
                            compliant = False
                            self.detailedresults += "\nThe home directory: " + str(hd) + " is group-writeable"
                            self.GWHomeDirs.append(hd)
                        if self.isWR(hd):
                            compliant = False
                            self.detailedresults += "\nThe home directory: " + str(hd) + " is world-readable"
                            self.WRHomeDirs.append(hd)
                else:
                    self.logger.log(LogPriority.DEBUG, "No home directories found!")
            else:
                # running as a normal user
                homedir = self.getMyHomeDir()
                if os.path.exists(homedir):
                    self.logger.log(LogPriority.DEBUG, "Checking " + homedir)
                    if self.isGW(homedir):
                        compliant = False
                        self.detailedresults += "\nThe home directory: " + str(homedir) + " is group-writeable"
                        self.GWHomeDirs.append(homedir)
                    if self.isWR(homedir):
                        compliant = False
                        self.detailedresults += "\nThe home directory: " + str(homedir) + " is world-readable"
                        self.WRHomeDirs.append(homedir)
                else:
                    self.logger.log(LogPriority.DEBUG, "Skipping directory " + homedir + " because it does not exist...")

        except Exception:
            raise

        return compliant

    def getMyHomeDir(self):
        '''return the home directory for the currently logged-in user


        :returns: HomeDir

        :rtype: string
@author: Breen Malmberg

        '''

        HomeDir = ""
        findHomeDir = "echo $HOME"
        uuid = self.environ.geteuid()

        try:

            # precautionary check
            if uuid <= 100:
                self.logger.log(LogPriority.DEBUG, "This method should only be run by non-system, user accounts!")
                return HomeDir

            self.cmdhelper.executeCommand(findHomeDir)
            retcode = self.cmdhelper.getReturnCode()
            if retcode != 0:
                errstr = self.cmdhelper.getErrorString()
                self.logger.log(LogPriority.DEBUG, errstr)
                return HomeDir

            HomeDir = self.cmdhelper.getOutputString()

            # backup method (if the $HOME env is not set for the current user)
            if not HomeDir:
                HomeDir = pwd.getpwuid(uuid).pw_dir

        except Exception:
            raise

        return HomeDir

    def fix(self):
        '''remove group-write and other-read permissions on all local user home directories


        :returns: self.rulesuccess

        :rtype: bool
@author: Derek Walker
@change: Breen Malmberg - 10/13/2015 - will now fix /dev/null permissions when run;
                                        will no longer modify /var/empty or /dev/null

        '''

        self.iditerator = 0
        self.rulesuccess = True
        self.detailedresults = ""

        try:

            if not self.ci.getcurrvalue():
                self.detailedresults += "\nRule was not enabled. Nothing was done."
                return self.rulesuccess

            if self.environ.geteuid() == 0:
                eventlist = self.statechglogger.findrulechanges(self.rulenumber)
                for event in eventlist:
                    self.statechglogger.deleteentry(event)

            if self.GWHomeDirs:
                for hd in self.GWHomeDirs:
                    self.logger.log(LogPriority.DEBUG, "Removing group-write permission on directory: " + hd)
                    self.cmdhelper.executeCommand("/bin/chmod g-w " + hd)
                    retcode = self.cmdhelper.getReturnCode()
                    if retcode != 0:
                        errstr = self.cmdhelper.getErrorString()
                        self.logger.log(LogPriority.DEBUG, errstr)
                        self.rulesuccess = False
                        self.detailedresults += "\nUnable to remove group write permission on directory: " + hd

            if self.WRHomeDirs:
                for hd in self.WRHomeDirs:
                    self.logger.log(LogPriority.DEBUG, "Removing world read permission on directory: " + hd)
                    self.cmdhelper.executeCommand("/bin/chmod o-r " + hd)
                    retcode = self.cmdhelper.getReturnCode()
                    if retcode != 0:
                        errstr = self.cmdhelper.getErrorString()
                        self.logger.log(LogPriority.DEBUG, errstr)
                        self.rulesuccess = False
                        self.detailedresults += "\nUnable to remove world read permission on directory: " + hd
                    self.logger.log(LogPriority.DEBUG, "Also ensuring no world write permission on directory: " + hd)
                    self.cmdhelper.executeCommand("/bin/chmod o-w " + hd)
                    retcode = self.cmdhelper.getReturnCode()
                    if retcode != 0:
                        errstr = self.cmdhelper.getErrorString()
                        self.logger.log(LogPriority.DEBUG, errstr)
                        self.rulesuccess = False

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.rulesuccess
