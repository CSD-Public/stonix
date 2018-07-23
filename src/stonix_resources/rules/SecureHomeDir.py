###############################################################################
#                                                                             #
# Copyright 2015-2018.  Los Alamos National Security, LLC. This material was  #
# produced under U.S. Government contract DE-AC52-06NA25396 for Los Alamos    #
# National Laboratory (LANL), which is operated by Los Alamos National        #
# Security, LLC for the U.S. Department of Energy. The U.S. Government has    #
# rights to use, reproduce, and distribute this software.  NEITHER THE        #
# GOVERNMENT NOR LOS ALAMOS NATIONAL SECURITY, LLC MAKES ANY WARRANTY,        #
# EXPRESS OR IMPLIED, OR ASSUMES ANY LIABILITY FOR THE USE OF THIS SOFTWARE.  #
# If software is modified to produce derivative works, such modified software #
# should be clearly marked, so as not to confuse it with the version          #
# available from LANL.                                                        #
#                                                                             #
# Additionally, this program is free software; you can redistribute it and/or #
# modify it under the terms of the GNU General Public License as published by #
# the Free Software Foundation; either version 2 of the License, or (at your  #
# option) any later version. Accordingly, this program is distributed in the  #
# hope that it will be useful, but WITHOUT ANY WARRANTY; without even the     #
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.    #
# See the GNU General Public License for more details.                        #
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
@change: 2018/06/28 Breen Malmberg - re-wrote much of the rule; added doc strings
        to some existing methods
'''

from __future__ import absolute_import

import traceback
import os
import stat
import re
import pwd

from ..stonixutilityfunctions import iterate, readFile
from ..rule import Rule
from ..logdispatcher import LogPriority
from ..CommandHelper import CommandHelper


class SecureHomeDir(Rule):
    '''
    classdocs
    '''

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
                           'os': {'Mac OS X': ['10.11', 'r', '10.14.10']}}
        self.sethelptext()

    def report(self):
        '''
        report the compliance status of the permissions on all local user
        home directories

        @return: self.compliant
        @rtype: bool
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
        '''
        check all user local home directories, on Mac OS X, for correct permissions

        @return: compliant
        @rtype: bool
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
        '''
        determine if a given path is group writeable

        @param path: string; absolute file path to scan
        @return: groupwriteable
        @rtype: bool
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
        '''
        determine if a given path is world readable

        @param path: string; absolute file path to scan
        @return: worldreadable
        @rtype: bool
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
        '''
        get a list of user home directories on the Mac

        @return: homedirs
        @rtype: list
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
                    currpwd = pwd.getpwnam(u)
                    HomeDirs.append(currpwd[5])

            if HomeDirs:
                for hd in HomeDirs:
                    if not os.path.exists(hd):
                        HomeDirs.remove(hd)
                    elif re.search('\/var\/empty', hd):
                        HomeDirs.remove(hd)
                    # skip homedir if it is /dev/null
                    elif re.search('\/dev\/null', hd):
                        HomeDirs.remove(hd)
            else:
                self.logger.log(LogPriority.DEBUG, "No Mac user local home directories found")

        except Exception:
            raise

        return HomeDirs

    def getLinuxHomeDirs(self):
        '''
        get a list of user home directories on Linux platforms

        @return: homedirs
        @rtype: list
        @author: Breen Malmberg
        '''

        self.logger.log(LogPriority.DEBUG, "Building list of Linux local user home directories...")

        HomeDirs = []
        passwd = "/etc/passwd"

        try:

            uid_min = self.getUIDMIN()

            if not uid_min:
                uid_min = "500"

            self.logger.log(LogPriority.DEBUG, "Reading contents of " + passwd + " ...")
            # read in /etc/passwd
            passwdcontents = readFile(passwd, self.logger)

            # get list of home directories
            if passwdcontents:
                for line in passwdcontents:
                    sline = line.split(":")
                    if int(sline[2]) >= int(uid_min):
                        HomeDirs.append(sline[5])
            else:
                self.logger.log(LogPriority.DEBUG, passwd + " was blank!")

            if not HomeDirs:
                self.logger.log(LogPriority.DEBUG, "No Mac user local home directories found")

        except Exception:
            raise

        return HomeDirs

    def getUIDMIN(self):
        '''
        return this system's minimum user ID start value, if configured

        @return: uid_min
        @rtype: string
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
            else:
                self.logger.log(LogPriority.DEBUG, "Unable to determine UID_MIN")

        except Exception:
            raise

        return uid_min

    def reportLinux(self):
        '''
        check all user local home directories, on Linux platforms, for correct permissions

        @return: compliant
        @rtype: bool
        @author: Derek Walker
        @change: Breen Malmberg - 06/28/2018 - re-wrote method
        '''

        compliant = True

        try:

            if self.environ.geteuid() == 0:
                # running as root/admin
                homedirs = self.getLinuxHomeDirs()

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
        '''
        return the home directory for the currently logged-in user

        @return: HomeDir
        @rtype: string
        @author: Breen Malmberg
        '''

        HomeDir = ""
        findHomeDir = "echo $HOME"

        try:

            # precautionary check
            if self.environ.geteuid() <= 100:
                self.logger.log(LogPriority.DEBUG, "This method should only be run by non-system, user accounts!")
                return HomeDir

            self.cmdhelper.executeCommand(findHomeDir)
            retcode = self.cmdhelper.getReturnCode()
            if retcode != 0:
                errstr = self.cmdhelper.getErrorString()
                self.logger.log(LogPriority.DEBUG, errstr)
                return HomeDir

            HomeDir = self.cmdhelper.getOutputString()

        except Exception:
            raise

        return HomeDir

    def fix(self):
        '''
        remove group-write and other-read permissions on all local user home directories

        @return: self.rulesuccess
        @rtype: bool
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
