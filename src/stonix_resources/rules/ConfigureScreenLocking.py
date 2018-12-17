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
#from deb_build_script import line
#from __builtin__ import False
'''
Created on Jul 11, 2013

@author: dwalker
@change: 2014-03-26 ekkehard changed rule to ruleKVEditor rule add mac support
@change: 2014-04-08 ekkehard fix OS X issue with with configuration item
@change: 2014-04-21 dkennel Updated to use new CI invocation
@change: 2014-07-21 ekkehard fix OS X Mavericks reporting issues
@change: 2014-07-29 ekkehard refix OS X Mavericks issues
@change: 2014/10/17 ekkehard OS X Yosemite 10.10 Update
@change: 2015/04/14 dkennel update for new isApplicable
@change: 2015/07/28 eball Fixed path validation problems in fixKde
@change: 2015/07/28 eball Fixed return value and statechglogging in correctFile
@change: 2015/08/26 ekkehard - Artifact artf37282 : ConfigureScreenLocking(74)
                             - askForPasswordDelay not set to 0
@change: 2015/10/07 eball Help text/PEP8 cleanup
@change: 2016/06/22 eball Added gsettings report and fix for RHEL 7 compat
@change: 2016/10/18 eball Added lock-delay key to special check in reportGnome
    for values that come back with "uint32 [int val]". Also added two single
    quotes to picture-uri value, since a blank value cannot be "set".
@change: 2016/11/22 eball Changed gsettings times from 300 to 900.
@change: 2017/11/13 ekkehard - make eligible for OS X El Capitan 10.11+
@change 2017/11/15 bgonz12 - changed fixGnome to unlock the dconf
    stonix-settings before trying to configure them
@change: 2017/11/30 bgonz12 - changed fixGnome to use a conf file
    for configuring dconf settings on rpm systems
@change: 2018/02/14 bgonz12 - changed fixGnome to set dconf settings with conf
    files instead of gsettings
@change: 2018/06/08 ekkehard - make eligible for macOS Mojave 10.14
@change: 2018/10/26 dwalker - major refactor to reportGnome and fixGnome
    methods.  Code was unecessarily repeated. Also updated methods to 
    configure both gsettings and gconftool-2 whereas before were 
    mutually exclusive and only configured one or the other.  Configuring
    both seems to cause no issues and can easily be converted back if
    need be. Added additional comments for walkthrough of rule.
'''
from __future__ import absolute_import
from ..stonixutilityfunctions import iterate, checkPerms, setPerms, createFile
from ..stonixutilityfunctions import readFile, resetsecon, getOctalPerms, writeFile
from ..ruleKVEditor import RuleKVEditor
from ..logdispatcher import LogPriority
from ..pkghelper import Pkghelper
from subprocess import PIPE, Popen
from ..KVEditorStonix import KVEditorStonix
from ..CommandHelper import CommandHelper
import os
import traceback
import re
from glob import glob
from pwd import getpwnam


class ConfigureScreenLocking(RuleKVEditor):

    def __init__(self, config, environ, logdispatcher, statechglogger):
        RuleKVEditor.__init__(self, config, environ, logdispatcher,
                              statechglogger)
        self.logger = logdispatcher
        self.rulenumber = 74
        self.rulename = "ConfigureScreenLocking"
        self.mandatory = True
        self.rootrequired = False
        self.applicable = {'type': 'white',
                           'family': ['linux', 'solaris', 'freebsd'],
                           'os': {'Mac OS X': ['10.11', 'r', '10.14.10']}}
        self.effectiveUserID = self.environ.geteuid()
        self.sethelptext()
        self.formatDetailedResults("initialize")
        self.guidance = ["NSA 2.3.5.6.1"]
        if self.environ.getosfamily() == "darwin":
            if self.effectiveUserID == 0:
                self.addKVEditor("SystemAskForPasswordSystem",
                                 "defaults",
                                 "/Library/Preferences/com.apple.screensaver",
                                 "",
                                 {"askForPassword": ["1", "-int 1"]},
                                 "present",
                                 "",
                                 "Ask for password when system wide " +
                                 "screen saver is on.",
                                 None,
                                 False,
                                 {"askForPassword": ["0", "-int 0"]})
                self.addKVEditor("SystemSetScreenSaverIdleTime",
                                 "defaults",
                                 "/Library/Preferences/com.apple.screensaver",
                                 "",
                                 {"idleTime": ["840", "-int 840"]},
                                 "present",
                                 "",
                                 "Sets system the screen saver to " +
                                 "activate after 14 minutes of idleTime.",
                                 None,
                                 False,
                                 {"idleTime":
                                  ["The domain/default pair of ( .+" +
                                   "com\.apple\.screensaver, " +
                                   "idleTime) does not " +
                                   "exist",
                                   None]})
                self.addKVEditor("SystemLoginWindowIdleTime",
                                 "defaults",
                                 "/Library/Preferences/com.apple.screensaver",
                                 "",
                                 {"loginWindowIdleTime": ["840", "-int 840"]},
                                 "present",
                                 "",
                                 "Sets system LoginWindowIdleTime to " +
                                 "14 minutes.",
                                 None,
                                 False,
                                 {"loginWindowIdleTime":
                                  ["The domain/default pair of ( .+" +
                                   "com\.apple\.screensaver, " +
                                   "loginWindowIdleTime) does not " +
                                   "exist",
                                   None]})
            else:
                self.addKVEditor("AskForPassword",
                                 "defaults",
                                 "~/Library/Preferences/com.apple.screensaver",
                                 "",
                                 {"askForPassword": ["1", "-int 1"]},
                                 "present",
                                 "",
                                 "Ask for password when screen saver is on.",
                                 None,
                                 False,
                                 {"askForPassword": ["0", "-int 0"]})
                self.addKVEditor("AskForPasswordDelay",
                                 "defaults",
                                 "~/Library/Preferences/com.apple.screensaver",
                                 "",
                                 {"askForPasswordDelay": ["0", "-int 0"]},
                                 "present",
                                 "",
                                 "Delay asking for password by 0 seconds.",
                                 None,
                                 False,
                                 {"askForPasswordDelay":
                                  ["The domain/default pair of ( .+" +
                                   "com\.apple\.screensaver, " +
                                   "askForPassword) does not " +
                                   "exist",
                                   None]})
        else:

            datatype = 'bool'
            key = 'CONFIGURESCREENLOCKING'
            instructions = "To prevent the configuration of idle screen locking, set the value of CONFIGURESCREENLOCKING to False."
            default = True
            self.ci = self.initCi(datatype, key, instructions, default)

    def report(self):
        '''
        ConfigureScreenLocking.report() method to report whether system
        is configured to screen locking NSA standards.  If the system is linux,
        although many desktops are available, this rule will only check the
        two most popular desktops, KDE, and Gnome.
        @author: dwalker
        @param self - essential if you override this definition
        @return: bool - True if system is compliant, False if it isn't
        '''

        self.detailedresults = ""
        self.compliant = True
        self.ch = CommandHelper(self.logger)

        try:

            if self.environ.getosfamily() == "darwin":
                if not self.reportMac():
                    self.compliant = False
            elif self.environ.getosfamily() == "linux":

                # cannot make the necessary per-user configuration changes properly as root
                if self.effectiveUserID == 0:
                    self.compliant = False
                    self.detailedresults += "\nCannot properly report on user configurations of idle screen locking while running as root. Please run this rule without elevated privileges."
                    self.formatDetailedResults("report", self.compliant, self.detailedresults)
                    self.logdispatch.log(LogPriority.INFO, self.detailedresults)
                    return self.compliant
    
                if os.path.exists("/usr/bin/dconf"):
                    if not self.reportgnome3():
                        self.compliant = False
                if os.path.exists("/usr/bin/gconftool-2"):
                    if not self.reportgnome2():
                        self.compliant = False
                if os.path.exists("/usr/bin/kwriteconfig"):
                    if not self.reportKde():
                        self.compliant = False

        except(KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.detailedresults += traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)

        return self.compliant

    def reportMac(self):
        '''
        Mac osx specific report submethod

        @author: dwalker
        @param self - essential if you override this definition
        @return: bool - True if system is compliant, False if it isn't
        '''
        success = RuleKVEditor.report(self, True)
        return success

    def reportgnome2(self):
        '''
        determines if gnome is installed, if so, checks to see if the
        return value strings from running the gconftool-2 command are
        correct.  Gconftool-2 command only works in root mode so if not root
        do not audit gnome and just return true

        @author: dwalker
        @param self - essential if you override this definition
        @return: bool
        @change: dwalker - mass refactor, added comments
        '''

        compliant = True
        gconf = "/usr/bin/gconftool-2"
        confDict = {"--get /apps/gnome-screensaver/idle_activation_enabled": "true",
                    "--get /apps/gnome-screensaver/idle_delay": "14",
                    "--get /apps/gnome-screensaver/lock_delay": "1",
                    "--get /apps/gnome-screensaver/lock_enabled": "true",
                    "--get /apps/gnome-screensaver/mode": "blank-only",
                    "--get /desktop/gnome/session/idle_delay": "15"}

        gconfcommands = []
        for item in confDict:
            gconfcommands.append(gconf + " " + item)

        self.logger.log(LogPriority.DEBUG, "Checking gconf screen locking configurations")

        try:

            for gcmd in gconfcommands:
                self.ch.executeCommand(gcmd)
                retcode = self.ch.getReturnCode()
                if retcode != 0:
                    errstr = self.ch.getErrorString()
                    self.logger.log(LogPriority.DEBUG, errstr)
                    self.detailedresults += "\nFailed to read the value of " + gcmd.split()[2]
                    compliant = False
                else:
                    outputstr = self.ch.getOutputString()
                    if not re.search(confDict[gcmd.split()[1] + " " + gcmd.split()[2]], outputstr, re.IGNORECASE):
                        compliant = False
                        self.detailedresults += "\nThe value of configuration option " + gcmd.split()[2] + " is incorrect"

        except Exception:
            raise
        return compliant

    def reportgnome3(self):
        '''

        @return:
        '''

        compliant = True

        dconf = "/usr/bin/dconf"
        confDict = {"/org/gnome/desktop/screensaver/lock-enabled": "true",
                    "/org/gnome/desktop/screensaver/lock-delay": "60",
                    "/org/gnome/desktop/session/idle-delay": "840",
                    "/org/gnome/desktop/screensaver/picture-uri": ""}
        dconfcommands = []
        for item in confDict:
            dconfcommands.append(dconf + " read " + item)

        self.logger.log(LogPriority.DEBUG, "Checking dconf screen locking configurations")

        try:

            for dcmd in dconfcommands:
                self.ch.executeCommand(dcmd)
                retcode = self.ch.getReturnCode()
                if retcode != 0:
                    errstr = self.ch.getErrorString()
                    self.logger.log(LogPriority.DEBUG, errstr)
                    self.detailedresults += "\nFailed to configure option " + dcmd.split()[2]
                    compliant = False
                else:
                    outputstr = self.ch.getOutputString()
                    if dcmd.split()[2] == "/org/gnome/desktop/screensaver/picture-uri":
                        if outputstr.strip() != confDict[dcmd.split()[2]]:
                            compliant = False
                            self.detailedresults += "\nConfiguration value for option " + dcmd.split()[2] + " is incorrect"
                    else:
                        if not re.search(confDict[dcmd.split()[2]], outputstr):
                            compliant = False
                            self.detailedresults += "\nConfiguration value for option " + dcmd.split()[2] + " is incorrect"

        except Exception:
            raise
        return compliant

    def reportKde(self):
        '''
        determines if kde is installed, if so, ensures kde is configured
        by enabling screenlocking, automatically going black after 14 minutes
        and if inactivity ensues after 14 minutes, screen fully locks after 1
        additional minute of inactivity for a total of 15 minutes activity

        @author: dwalker
        @param self - essential if you override this definition
        @return: bool
        '''

        compliant = True

        foundList = []

        self.logger.log(LogPriority.DEBUG, "Checking kde screen locking configurations")

        try:

            confFile = os.path.expandvars("$HOME") + "/.config/kscreenlockerrc"
            confDict = {"Autolock": "true",
                        "LockGrace": "60",
                        "LockOnResume": "true",
                        "Timeout": "14"}

            if not os.path.exists(confFile):
                compliant = False
                self.detailedresults += "\nMissing configuration file: " + confFile
                return compliant

            f = open(confFile, "r")
            contentlines = f.readlines()
            f.close()

            for line in contentlines:
                for item in confDict:
                    if re.search("^" + item + "=" + confDict[item], line):
                        foundList.append(item)

            if not foundList:
                compliant = False
                self.detailedresults += "\nAll configuration options are missing"

            for fl in foundList:
                if fl not in confDict:
                    self.detailedresults += "\nMissing configuration option: " + fl + " in " + confFile
                    compliant = False

        except Exception:
            raise
        return compliant

    def fix(self):
        '''
        ConfigureScreenLocking.fix() method to correct screen locking

        @author: dwalker
        @param self - essential if you override this definition
        @return: bool - True if fix is successful, False if it isn't
        '''

        self.detailedresults = ""
        self.rulesuccess = True
        self.iditerator = 0

        try:

            if self.environ.getosfamily() == "darwin":

                if not self.fixMac():
                    self.rulesuccess = False

            elif self.environ.getosfamily() == "linux":

                # if the ci is not enabled, do not run fix
                if not self.ci.getcurrvalue():
                    self.detailedresults += "\nRule was not enabled so nothing was done"
                    self.formatDetailedResults("fix", self.rulesuccess, self.detailedresults)
                    self.logdispatch.log(LogPriority.INFO, self.detailedresults)
                    return self.rulesuccess

                # cannot make the necessary per-user configuration changes properly as root
                if self.effectiveUserID == 0:

                    self.rulesuccess = False
                    self.detailedresults += "\nCannot properly fix user configurations of idle screen locking while running as root. Please run this rule without elevated privileges first."
                    self.formatDetailedResults("fix", self.rulesuccess, self.detailedresults)
                    self.logdispatch.log(LogPriority.INFO, self.detailedresults)
                    return self.rulesuccess
    
                if os.path.exists("/usr/bin/dconf"):
                    if not self.fixgnome3():
                        self.rulesuccess = False
                if os.path.exists("/usr/bin/gconftool-2"):
                    if not self.fixgnome2():
                        self.rulesuccess = False
                if os.path.exists("/usr/bin/kwriteconfig"):
                    if not self.fixKde():
                        self.rulesuccess = False

        except(KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.detailedresults += "\n" + traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)

        return self.rulesuccess

    def fixKde(self):
        '''

        @return:
        '''

        success = True
        kwriteconfig = ""
        kwritelocs = ["/usr/bin/kwriteconfig", "/usr/bin/kwriteconfig5"]
        reloadconfig = "/usr/bin/qdbus org.freedesktop.ScreenSaver /ScreenSaver configure"
        for loc in kwritelocs:
            if os.path.exists(loc):
                kwriteconfig = loc
                break

        self.logger.log(LogPriority.DEBUG, "Writing kde screen locking configurations")

        try:

            confFile = os.path.expandvars("$HOME") + "/.config/kscreenlockerrc"
            confDict = {"Autolock": "true",
                        "LockGrace": "60",
                        "LockOnResume": "true",
                        "Timeout": "14"}

            kwritecommands = []
            for item in confDict:
                kwritecommands.append(kwriteconfig + " --file " + confFile + " --group Daemon --key " + item + " " + confDict[item])

            for kcmd in kwritecommands:
                self.detailedresults += "\n\nRunning command:\n" + kcmd
                self.ch.executeCommand(kcmd)
                retcode = self.ch.getReturnCode()
                if retcode != 0:
                    errstr = self.ch.getErrorString()
                    self.logger.log(LogPriority.DEBUG, errstr)
                    self.detailedresults += "\nFailed to configure option " + kcmd.split()[6]
                    success = False

            self.ch.executeCommand(reloadconfig)
            retcode = self.ch.getReturnCode()
            if retcode != 0:
                errstr = self.ch.getErrorString()
                success = False
                self.detailedresults += "\nFailed to load new configuration settings"
                self.logger.log(LogPriority.DEBUG, errstr)

        except Exception:
            raise
        return success

    def fixgnome2(self):
        '''

        @return:
        '''

        success = True
        gconf = "/usr/bin/gconftool-2"
        confDict = {"--type bool --set /apps/gnome-screensaver/idle_activation_enabled": "true",
                    "--type int --set /apps/gnome-screensaver/idle_delay": "14",
                    "--type int --set /apps/gnome-screensaver/lock_delay": "1",
                    "--type bool --set /apps/gnome-screensaver/lock_enabled": "true",
                    "--type string --set /apps/gnome-screensaver/mode": "blank-only",
                    "--type int --set /desktop/gnome/session/idle_delay": "15"}
        gconfcommands = []
        for item in confDict:
            gconfcommands.append(gconf + " " + item + " " + confDict[item])

        self.logger.log(LogPriority.DEBUG, "Writing gconf screen locking configurations")

        try:

            for gcmd in gconfcommands:
                self.ch.executeCommand(gcmd)
                retcode = self.ch.getReturnCode()
                if retcode != 0:
                    errstr = self.ch.getErrorString()
                    self.logger.log(LogPriority.DEBUG, errstr)
                    self.detailedresults += "\nFailed to configure option " + gcmd.split()[4]
                    success = False

        except Exception:
            raise
        return success

    def fixgnome3(self):
        '''

        @return:
        '''

        success = True
        dconf = "/usr/bin/dconf"
        confDict = {"/org/gnome/desktop/screensaver/lock-enabled": "true",
                    "/org/gnome/desktop/screensaver/lock-delay": "60",
                    "/org/gnome/desktop/session/idle-delay": "840",
                    "/org/gnome/desktop/screensaver/picture-uri": ""}
        dconfcommands = []
        for item in confDict:
            dconfcommands.append(dconf + " write " + item + " " + confDict[item])

        self.logger.log(LogPriority.DEBUG, "Writing dconf screen locking configurations")

        try:

            for dcmd in dconfcommands:
                self.ch.executeCommand(dcmd)
                retcode = self.ch.getReturnCode()
                if retcode != 0:
                    errstr = self.ch.getErrorString()
                    self.logger.log(LogPriority.DEBUG, errstr)
                    self.detailedresults += "\nFailed to configure option " + dcmd.split()[2]
                    success = False

        except Exception:
            raise
        return success

    def fixMac(self):
        '''
        Mac osx specific fix submethod

        @author: dwalker
        @param self - essential if you override this definition
        @return: bool - True if system is successfully fix, False if it isn't
        '''

        success = RuleKVEditor.fix(self, True)
        return success
