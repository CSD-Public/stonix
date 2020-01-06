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

#from deb_build_script import line
#from __builtin__ import False
"""
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
@change: 2019/1/28 Brandon R. Gonzales - Move rule enabled ci check from the
    beginning of fix() to the beginning of the fix linux path
@change: 2019/03/12 ekkehard - make eligible for macOS Sierra 10.12+
@change: 2019/08/07 ekkehard - enable for macOS Catalina 10.15 only
"""

from stonixutilityfunctions import createFile
from stonixutilityfunctions import readFile, resetsecon, writeFile
from ruleKVEditor import RuleKVEditor
from logdispatcher import LogPriority
from pkghelper import Pkghelper
from KVEditorStonix import KVEditorStonix
from CommandHelper import CommandHelper
import os
import traceback
import re
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
                           'os': {'Mac OS X': ['10.15', 'r', '10.15.10']}}
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

            #self.gnomeInst variable determines in the fixGnome method
            #at the beginning if we even proceed.  If False we don't proceed
            #and is fine.  Gets set to True in reportGnome method if
            #either gconftool-2 or gsettings binaries exist.
            self.gnomeInst = False
            self.useGconf = True
            self.iditerator = 0
            self.cmdhelper = CommandHelper(self.logger)
            self.ph = Pkghelper(self.logger, self.environ)
            self.ch = CommandHelper(self.logger)

            self.euid = self.environ.geteuid()

    def report(self):
        """ConfigureScreenLocking.report() method to report whether system
        is configured to screen locking NSA standards.  If the system is linux,
        although many desktops are available, this rule will only check the
        two most popular desktops, KDE, and Gnome.
        @author: dwalker

        :param self: essential if you override this definition
        :return: self.compliant
        :rtype: bool
        """

        self.detailedresults = ""
        self.compliant = True

        try:

            compliant = True
            self.detailedresults = ""
            if self.environ.osfamily == 'linux':
                if not self.check_package():
                    compliant = False
                    if self.euid != 0:
                        self.detailedresults += "\nThis is expected if not running with elevated privileges since STONIX " \
                                                "requires elevated privileges to install packages. Please run STONIX with elevated privileges " \
                                                "and run the fix for this rule again, to fix this issue."

                if self.ph.check("gdm") or self.ph.check("gdm3"):
                    self.gnomeInstalled = True
                    if not self.reportGnome():
                        self.detailedresults += "\nGnome GUI environment " + \
                                                "does not appear to be correctly configured " + \
                                                "for screen locking parameters."
                        compliant = False
                    else:
                        self.detailedresults += "\nGnome GUI environment " + \
                                                "appears to be correctly configured for " + \
                                                "screen locking parameters."
                else:
                    self.gnomeInstalled = False
                    self.detailedresults += "\nGnome not installed.  No need to configure for gnome."

                if self.ph.check("kdm") or self.ph.check("kde-workspace") or \
                                      self.ph.check("sddm") or self.ph.check("patterns-kde-kde_yast"):
                    self.kdeInstalled = True
                    if not self.reportKde():
                        self.detailedresults += "\nKDE GUI environment " + \
                                                "does not appear to be correctly configured " + \
                                                "for screen locking parameters."
                        compliant = False
                    else:
                        self.detailedresults += "\nKDE GUI environment " + \
                                                "appears to be correctly configured for " + \
                                                "screen locking parameters."
                else:
                    self.kdeInstalled = False
                    self.detailedresults += "\nKDE not installed.  No need to configure for kde."

            elif self.environ.getosfamily() == "darwin":
                compliant = self.reportMac()

            self.compliant = compliant

        except(KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.compliant = False
            self.detailedresults += traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)

        return self.compliant

    def check_package(self):
        """
        for rhel 7 and similar generation linux rpm-based systems, the
        'screen' package is required by the STIG
        for rhel 8 and beyond (and similar), the 'tmux' package
        is required.

        :return: installed
        :rtype: bool
        """

        self.screen_pkg = ""
        installed = True

        if self.ph.checkAvailable("tmux"):
            self.screen_pkg = "tmux"
        elif self.ph.check("tmux"):
            self.screen_pkg = "tmux"
        else:
            self.screen_pkg = "screen"

        if not self.ph.check(self.screen_pkg):
            self.detailedresults += "\nThe required package: " + str(self.screen_pkg) + " is not installed"
            installed = False
        else:
            self.detailedresults += "\nThe required package: " + str(self.screen_pkg) + " is installed"

        return installed

    def reportMac(self):
        """Mac osx specific report submethod
        
        @author: dwalker

        :param self: essential if you override this definition
        :returns: bool - True if system is compliant, False if it isn't

        """
        success = RuleKVEditor.report(self, True)
        return success

    def reportGnome(self):
        """determines if gnome is installed, if so, checks to see if the
        return value strings from running the gconftool-2 command are
        correct.  Gconftool-2 command only works in root mode so if not root
        do not audit gnome and just return true
        
        @author: dwalker

        :param self: essential if you override this definition
        :returns: bool
        @change: dwalker - mass refactor, added comments

        """

        compliant = True
        gsettings = "/usr/bin/gsettings"
        gconf = "/usr/bin/gconftool-2"
        self.gesttingsidletime = ""
        self.gconfidletime = ""
        self.setcmds = ""
        #may need to change code in the future to make gconf and
        #gsettings mutually exclusive with if elif else self.gnomeInstalled = False
        #if they are found to conflict with each other
        if os.path.exists(gconf):
            getcmds = {"/apps/gnome-screensaver/idle_activation_enabled":
                       "true",
                       "/apps/gnome-screensaver/lock_enabled": "true",
                       "/apps/gnome-screensaver/mode": "blank-only",
                       "/desktop/gnome/session/idle_delay": "15"}
            #make a copy of the getcmds dictionary
            tempdict = dict(getcmds)
            #check each value using the gconftool-2 command
            for cmd in getcmds:
                #set the get command for each value
                cmd2 = gconf +  " --get " + cmd
                #execute the command
                self.cmdhelper.executeCommand(cmd2)
                #get output and error output
                output = self.cmdhelper.getOutput()
                error = self.cmdhelper.getError()
                #the value is set
                if output:
                    #check this one separately since the value is
                    #also able to be less than 15 mins and be compliant
                    if cmd == "/desktop/gnome/session/idle_delay":
                        if int(output[0].strip()) > 15:
                            self.detailedresults += "Idle delay value " + \
                                "is not 15 or lower (value: " + \
                                output[0].strip() + ")\n"
                        #if they have a value less than 15 mins this is ok
                        #and we set the self.gconfidletime variable which is
                        #used during setting gconf values in the fixGnome method
                        elif int(output[0].strip()) < 15:
                            self.gconfidletime = output[0].strip()
                            del tempdict[cmd]
                        #value is correct so remove it from the tempdic
                        else:
                            del tempdict[cmd]
                    #check if value is correct with associated key
                    elif output[0].strip() != getcmds[cmd]:
                        self.detailedresults += cmd2 + " didn't produce the " + \
                            "desired value after being run which is " + \
                            getcmds[cmd] + "\n"
                    #value is correct so remove it from the tempdict
                    else:
                        del tempdict[cmd]
                #else the value isn't set
                elif error:
                    self.detailedresults += "There is no value set for:\n" + \
                                            cmd2 + "\n"
            #if tempdict still has leftover values then
            #there were values that weren't correctly set
            #and is non compliant
            if tempdict:
                compliant = False
                #set self.setcmds variable to be a copy of tempdict which
                #we use later in the fix to determine if we fix this portion
                #of the rule or not
                self.setcmds = tempdict
        if os.path.exists(gsettings):
            self.gnomeInst = True
            #use gsettings command to see if the correct values are set
            #for each key in getcmds dictionary
            getcmds = {" get org.gnome.desktop.screensaver " +
                       "idle-activation-enabled": "true",
                       " get org.gnome.desktop.screensaver lock-enabled":
                       "true",
                       " get org.gnome.desktop.screensaver lock-delay":
                       "0",
                       " get org.gnome.desktop.screensaver picture-opacity":
                       "100",
                       " get org.gnome.desktop.screensaver picture-uri": "''",
                       " get org.gnome.desktop.session idle-delay": "900"}
            #run each gsettings get command for each key and get value
            for cmd in getcmds:
                cmd2 = gsettings + cmd
                self.cmdhelper.executeCommand(cmd2)
                output = self.cmdhelper.getOutput()
                error = self.cmdhelper.getError()
                if output:
                    #check this one separately since the value is
                    #also able to be less than 900 secs and be compliant
                    if cmd == " get org.gnome.desktop.session idle-delay":
                        try:
                            splitOut = output[0].split()
                            if len(splitOut) > 1:
                                num = splitOut[1]
                            else:
                                num = splitOut[0]
                            if int(num) > 900:
                                compliant = False
                                self.detailedresults += "Idle delay value " + \
                                    "is not 900 seconds (value: " +\
                                    num + ")\n"
                            #if they have a value less than 900 secs this is ok
                            #and we set the self.gsettingsidletime variable which is
                            #used during setting gsettings values in the fixGnome method
                            # elif int(num) < 900:
                            #     self.gsettingsidletime = num
                            elif int(num) == 0:
                                compliant = False
                                self.detailedresults += "Idle delay set  " + \
                                    "to 0, meaning it is disabled.\n"
                            else:
                                self.gsettingsidletime = "900"
                        except ValueError:
                            self.detailedresults += "Unexpected result: " + \
                                '"' + cmd2 + '" output was not a number\n'
                            compliant = False
                    elif cmd == " get org.gnome.desktop.screensaver lock-delay":
                        try:
                            splitOut = output[0].split()
                            if len(splitOut) > 1:
                                num = splitOut[1]
                            else:
                                num = splitOut[0]
                            if int(num) != 0:
                                compliant = False
                                self.detailedresults += "Lock delay is not " + \
                                    "set to 0\n"
                        except ValueError:
                            self.detailedresults += "Unexpected result: " + \
                                '"' + cmd2 + '" output was not a number\n'
                            compliant = False
                    elif output[0].strip() != getcmds[cmd]:
                        self.detailedresults += '"' + cmd2 + \
                        "\" produced value: " + output[0].strip() + \
                        " instead of the desired value: " + getcmds[cmd] + "\n"
                        compliant = False
                elif error:
                    if re.search("No such key", error[0], re.I):
                        continue
                    self.detailedresults += "There is no value set for:" + \
                        cmd2 + "\n"
                    compliant = False
            if self.environ.geteuid() == 0:
                # instantiate a kveditor to ensure self.dconfsettings file
                # contains correct contents
                self.dconfsettings = "/etc/dconf/db/local.d/local.key"
                if os.path.exists(self.dconfsettings):
                    self.dconfdata = {"org/gnome/desktop/screensaver": {
                        "idle-activation-enabled": "true",
                        "lock-enabled": "true",
                        "lock-delay": "0",
                        "picture-opacity": "100",
                        "picture-uri": "\'\'"},
                        "org/gnome/desktop/session": {
                            "idle-delay": "uint32 900"}}
                    self.kveditordconf = KVEditorStonix(self.statechglogger,
                                                        self.logger,
                                                        "tagconf",
                                                        self.dconfsettings,
                                                        self.dconfsettings + ".tmp",
                                                        self.dconfdata, "present",
                                                        "closedeq")
                    if not self.kveditordconf.report():
                        self.detailedresults += self.dconfsettings + \
                                                " doesn't cotain correct contents\n"
                        compliant = False
                else:
                    compliant = False
                    self.detailedresults += self.dconfsettings + " not found\n"

                # check self.dconfuserprofile file to ensure existence
                # and/or correct contents
                self.dconfuserprofile = "/etc/dconf/profile/user"
                self.userprofilecontent = "user-db:user\n" + \
                                          "system-db:local"
                if os.path.exists(self.dconfuserprofile):
                    contents = readFile(self.dconfuserprofile, self.logger)
                    contentstring = ""
                    for line in contents:
                        contentstring += line
                    if not re.search(self.userprofilecontent, contentstring):
                        compliant = False
                        self.detailedresults += "Correct contents weren't " + \
                                                "found in " + self.dconfuserprofile + "\n"
                else:
                    compliant = False
                    self.detailedresults += self.dconfuserprofile + " not " + \
                                            "found\n"

                # the following file locks the settings we earlier set with the
                # gsettings command so that they don't default upon logout and/or
                # reboot.  Check the file for the correct contents
                self.dconfsettingslock = "/etc/dconf/db/local.d/locks/stonix-settings.conf"
                self.dconflockdata = ["/org/gnome/desktop/session/idle-delay",
                                      "/org/gnome/desktop/screensaver/idle-activation-enabled",
                                      "/org/gnome/desktop/screensaver/lock-enabled",
                                      "/org/gnome/desktop/screensaver/lock-delay",
                                      "/org/gnome/desktop/screensaver/picture-uri"]

                locks_missing = []
                if os.path.exists(self.dconfsettingslock):
                    contents = readFile(self.dconfsettingslock, self.logger)
                    for line in contents:
                        if line.strip() not in self.dconflockdata:
                            locks_missing.append(line.strip())

                    if locks_missing:
                        self.detailedresults += "\nThe following settings should be locked from changes by the user but aren't:\n" + "\n".join(locks_missing)
                        compliant = False
                else:
                    compliant = False
                    self.detailedresults += "\nGnome settings lock file not found"

        return compliant

    def reportKde(self):
        """determines if kde is installed, if so, ensures kde is configured
        by enabling screenlocking, automatically going black after 14 minutes
        and if inactivity ensues after 14 minutes, screen fully locks after 1
        additional minute of inactivity for a total of 15 minutes activity
        
        @author: dwalker

        :param self: essential if you override this definition
        :returns: bool

        """
        self.kdefix = {}
        if self.ph.manager == "apt-get" or self.ph.manager == "zypper":
            self.rcpath = ".config/kscreenlockerrc"
            self.kdeprops = {"Daemon": {"Autolock": "true",
                                        "LockGrace": "60",
                                        "LockOnResume": "true",
                                        "Timeout": "14"}}
        else:
            self.rcpath = ".kde/share/config/kscreensaverrc"
            self.kdeprops = {"ScreenSaver": {"Enabled": "true",
                                             "Lock": "true",
                                             "LockGrace": "60000",
                                             "Timeout": "840"}}
        if self.environ.geteuid() == 0:
            contents = readFile("/etc/passwd", self.logger)
            for line in contents:
                temp = line.split(":")
                try:
                    username = temp[0]
                    homepath = temp[5]
                except IndexError:
                    self.logdispatch.log(LogPriority.DEBUG,
                                         ['ConfigureScreenLocking',
                                           'IndexError processing ' + str(temp)])
                    continue
                kdeparent1 = os.path.join(homepath, ".kde")
                kdeparent2 = os.path.join(homepath, ".kde4")
                kdefile = os.path.join(homepath, self.rcpath)
                if not os.path.exists(kdeparent1) and not os.path.exists(kdeparent2):
                    # User does not user KDE
                    continue
                elif not os.path.exists(kdefile):
                    self.kdefix[username] = homepath
                    self.detailedresults += kdefile + " not found for " + \
                        str(username) + "\n"
                    self.logger.log(LogPriority.DEBUG, self.detailedresults)
                    continue
                elif not self.searchFile(kdefile):
                    self.detailedresults += "Did not find " + \
                        "required contents " + "in " + username + \
                        "'s " + kdefile + "\n"
                    self.kdefix[username] = homepath
            if self.kdefix:
                self.detailedresults += "The following users don't " + \
                                        "have kde properly configured for " + \
                                        "screen locking:\n"
                for user in self.kdefix:
                    self.detailedresults += user + "\n"
                return False
            else:
                return True
        else:
            kdeparent1 = os.path.join(self.environ.geteuidhome(), ".kde")
            kdeparent2 = os.path.join(self.environ.geteuidhome(), ".kde4")
            kdefile = os.path.join(self.environ.geteuidhome(), self.rcpath)
            if not os.path.exists(kdeparent1) and not os.path.exists(kdeparent2):
                self.detailedresults += "Current user doesn't use kde.  " + \
                    "No need to configure.\n"
                self.logger.log(LogPriority.DEBUG, self.detailedresults)
                return True
            else:
                if not os.path.exists(kdefile):
                    self.detailedresults += "Your " + kdefile + \
                        " file doesn't exist.\n"
                    return False
                elif not self.searchFile(kdefile):
                    self.detailedresults += "Did not find " + \
                        "required contents in " + kdefile + "\n"
                    return False
                else:
                    return True

    def fix(self):
        """ConfigureScreenLocking.fix() method to correct screen locking
        
        @author: dwalker

        :param self: essential if you override this definition
        :returns: bool - True if fix is successful, False if it isn't

        """

        self.detailedresults = ""
        self.rulesuccess = True
        self.iditerator = 0

        try:
            self.detailedresults = ""
            success = True
            if self.environ.getosfamily() == "linux":
                if not self.ci.getcurrvalue():
                    self.detailedresults += "Rule not enabled so nothing was done\n"
                    self.logger.log(LogPriority.DEBUG, 'Rule was not enabled, so nothing was done')
                    return
                if self.euid == 0:
                    if not self.ph.install(self.screen_pkg):
                        success = False
                        self.logger.log(LogPriority.DEBUG, "Failed to install required package 'screen'")
                else:
                    self.detailedresults += "\nNote: Some required packages may not be installed because STONIX is not running with elevated privileges."
                if self.gnomeInstalled:
                    if not self.fixGnome():
                        success = False
                if self.kdeInstalled:
                    if not self.fixKde():
                        success = False
            elif self.environ.getosfamily() == "darwin":
                if self.environ.geteuid() == 0:
                    self.iditerator = 0
                    eventlist = self.statechglogger.findrulechanges(self.rulenumber)
                    for event in eventlist:
                        self.statechglogger.deleteentry(event)
                success = self.fixMac()
            self.rulesuccess = success
        except(KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.detailedresults += "\n" + traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)

        return self.rulesuccess

    def fixKde(self):
        """This method checks if the kde screenlock file is configured
        properly.  Please note, this rule may fail if the owner and group of
        configuration file are not that of the user in question but doesn't
        necessarily mean your system is out of compliance.  If the fix fails
        Please check the logs to determing the real reason of non rule success.
        @author: dwalker

        :param self: essential if you override this definition
        :returns: bool - True if KDE is successfully configured, False if it
                isn't

        """

        success = True
        if self.environ.geteuid() == 0:
            self.logdispatch.log(LogPriority.DEBUG,
                                 'ConfigureScreenLocking.fixKde')
            if not self.kdefix:
                return True
            for user in self.kdefix:
                homepath = self.kdefix[user]
                kdefile = os.path.join(homepath, self.rcpath)
                if not self.correctFile(kdefile, user):
                    success = False
                    self.detailedresults += "Unable to configure " + \
                                            kdefile + "\n"
                    self.logger.log(LogPriority.DEBUG, self.detailedresults)
        else:
            username = ""
            homepath = self.environ.geteuidhome()
            kdefile = os.path.join(homepath, self.rcpath)
            uidnum = int(self.environ.geteuid())
            passwddata = readFile("/etc/passwd", self.logger)
            found = False
            for user in passwddata:
                user = user.split(':')
                try:
                    puidnum = int(user[2])

                    if puidnum == uidnum:
                        username = user[0]
                        found = True
                except IndexError:
                    continue

            if not found:
                self.detailedresults += "Could not obtain your user id.\n" + \
                                        "Stonix couldn't proceed with correcting " + kdefile + "\n"
                success = False

            elif not self.correctFile(kdefile, username):

                self.detailedresults += "Stonix couldn't correct the contents " + \
                                        " of " + kdefile + "\n"
                success = False
        return success

    def fixGnome(self):
        """ensures gnome is configured to automatically screen lock after
        15 minutes of inactivity, if gnome is installed
        @author: dwalker

        :param self: essential if you override this definition
        :returns: bool - True if gnome is successfully configured, False if it
                isn't

        """
        info = ""
        success = True
        gconf = "/usr/bin/gconftool-2"
        gsettings = "/usr/bin/gsettings"
        if os.path.exists(gconf):
            #variable self.setcmds still has items left in its dictionary
            #which was set in the reportGnome method, meaning some values
            #either were incorrect or didn't have values.  Go through and
            #set each remaining value that isn't correct

            cmd = ""

            if self.setcmds:
                for item in self.setcmds:
                    if item == "/apps/gnome-screensaver/idle_activation_enabled":
                        cmd = gconf + " --type bool --set /apps/gnome-screensaver/idle_activation_enabled true"
                    elif item == "/apps/gnome-screensaver/lock_enabled":
                        cmd = gconf + " --type bool --set /apps/gnome-screensaver/lock_enabled true"
                    elif item == "/apps/gnome-screensaver/mode":
                        cmd = gconf + ' --type string --set /apps/gnome-screensaver/mode "blank-only"'
                    elif item == "/desktop/gnome/session/idle_delay":
                        if self.gconfidletime:
                            cmd = gconf + " --type int --set /desktop/gnome/session/idle_delay " + \
                                self.gconfidletime
                        else:
                            cmd = gconf + " --type int --set /desktop/gnome/session/idle_delay 15"
                    if self.cmdhelper.executeCommand(cmd):
                        if self.cmdhelper.getReturnCode() != 0:
                            info += "Unable to set value for " + cmd + "\n"
                            success = False
                    else:
                        info += "Unable to set value for " + cmd + "\n"
                        success = False

        if os.path.exists(gsettings):
            setcmds = ["org.gnome.desktop.screensaver idle-activation-enabled true",
                       "org.gnome.desktop.screensaver lock-enabled true",
                       "org.gnome.desktop.screensaver lock-delay 0",
                       "org.gnome.desktop.screensaver picture-opacity 100",
                       "org.gnome.desktop.screensaver picture-uri ''",
                       "org.gnome.desktop.session idle-delay 900"]
                       # " set org.gnome.desktop.session idle-delay " + self.gsettingsidletime]
            for cmd in setcmds:
                cmd2 = gsettings + " set " + cmd
                self.cmdhelper.executeCommand(cmd2)
                if self.cmdhelper.getReturnCode() != 0:
                    success = False
                    info += "Unable to set value for " + cmd + \
                        " using gsettings\n"

            # Set gsettings with dconf
            # Unlock dconf settings
            # Create dconf settings lock file
            if self.environ.geteuid() == 0:
                if not os.path.exists(self.dconfsettingslock):
                    if not createFile(self.dconfsettingslock, self.logger):
                        self.rulesuccess = False
                        self.detailedresults += "Unable to create stonix-settings file\n"
                        self.formatDetailedResults("fix", self.rulesuccess,
                                   self.detailedresults)
                        return False
                #write correct contents to dconf lock file
                if os.path.exists(self.dconfsettingslock):
                    # Write to the lock file
                    if self.dconflockdata:
                        contents = ""
                        tmpfile = self.dconfsettingslock + ".tmp"
                        for line in self.dconflockdata:
                            contents += line + "\n"
                        if not writeFile(tmpfile, contents, self.logger):
                            self.rulesuccess = False
                            self.detailedresults += "Unable to write contents to " + \
                                "stonix-settings file\n"
                        else:
                            os.rename(tmpfile, self.dconfsettingslock)
                            os.chown(self.dconfsettingslock, 0, 0)
                            os.chmod(self.dconfsettingslock, 0o644)
                            resetsecon(self.dconfsettingslock)
                # Create dconf user profile file
                if not os.path.exists(self.dconfuserprofile):
                    if not createFile(self.dconfuserprofile, self.logger):
                        self.rulesuccess = False
                        self.detailedresults += "Unable to create dconf " + \
                                                "user profile file\n"
                        self.formatDetailedResults("fix", self.rulesuccess,
                                   self.detailedresults)
                        return False
                # Write dconf user profile
                if os.path.exists(self.dconfuserprofile):
                    tmpfile = self.dconfuserprofile + ".tmp"
                    if not writeFile(tmpfile, self.userprofilecontent, self.logger):
                        self.rulesuccess = False
                        self.detailedresults += "Unabled to write to dconf user" + \
                            " profile file\n"
                        self.formatDetailedResults("fix", self.rulesuccess,
                                       self.detailedresults)
                        return False
                    else:
                        os.rename(tmpfile, self.dconfuserprofile)
                        os.chown(self.dconfuserprofile, 0, 0)
                        os.chmod(self.dconfuserprofile, 0o644)
                        resetsecon(self.dconfuserprofile)
                # Fix dconf settings
                if not os.path.exists(self.dconfsettings):
                    if not createFile(self.dconfsettings, self.logger):
                        self.rulesuccess = False
                        self.detailedresults += "Unable to create " + self.dconfsettings + " file \n"
                        self.formatDetailedResults("fix", self.rulesuccess,
                                   self.detailedresults)
                        return False
                    self.dconfdata = {"org/gnome/desktop/screensaver": {
                                                    "idle-activation-enabled": "true",
                                                    "lock-enabled": "true",
                                                    "lock-delay": "0",
                                                    "picture-opacity": "100",
                                                    "picture-uri": "\'\'"},
                                      "org/gnome/desktop/session": {
                                                    "idle-delay": "uint32 900"}}
                    self.kveditordconf = KVEditorStonix(self.statechglogger,
                                                        self.logger,
                                                        "tagconf",
                                                        self.dconfsettings,
                                                        self.dconfsettings + ".tmp",
                                                        self.dconfdata, "present",
                                                        "closedeq")
                    self.kveditordconf.report()
                if self.kveditordconf.fixables:
                    if not self.kveditordconf.fix():
                        success = False
                        self.detailedresults += "Unable to put correct settings inside " + \
                            self.dconfsettings + "\n"
                    elif not self.kveditordconf.commit():
                        success = False
                        self.detailedresults += "Unable to put correct settings inside " + \
                            self.dconfsettings + "\n"
                #run dconf update command to make dconf changes take effect
                if os.path.exists("/bin/dconf"):
                    cmd = "/bin/dconf update"
                    self.cmdhelper.executeCommand(cmd)
                elif os.path.exists("/usr/bin/dconf"):
                    cmd = "/usr/bin/dconf update"
                    self.cmdhelper.executeCommand(cmd)
        self.detailedresults += info
        return success


    def fixMac(self):
        """Mac osx specific fix submethod
        
        @author: dwalker

        :param self: essential if you override this definition
        :returns: bool - True if system is successfully fix, False if it isn't

        """
        success = RuleKVEditor.fix(self, True)
        return success

    def searchFile(self, filehandle):
        """temporary method to separate the code to find directives from the
        rest of the code.  Will put back all in one method eventually
        @author: dwalker

        :param filehandle: string
        :returns: bool

        """
        self.editor = ""
        kvt = "tagconf"
        intent = "present"
        tpath = filehandle + ".tmp"
        conftype = "closedeq"
        self.editor = KVEditorStonix(self.statechglogger, self.logger, kvt,
                                     filehandle, tpath, self.kdeprops, intent,
                                     conftype)
        if not self.editor.report():
            return False
        else:
            return True

    def correctFile(self, kfile, user):
        """separate method to find the correct contents of each file passed in
        as a parameter.
        @author: dwalker

        :param kfile: 
        :param user: 
        :returns: bool

        """
        success = True

        if not os.path.exists(kfile):
            if not createFile(kfile, self.logger):
                self.detailedresults += "Unable to create " + kfile + \
                    " file for the user\n"
                self.logger.log(LogPriority.DEBUG, self.detailedresults)
                return False
        if not self.searchFile(kfile):
            if self.editor.fixables:
                if not self.editor.fix():
                    debug = "Kveditor fix is failing for file " + \
                        kfile + "\n"
                    self.logger.log(LogPriority.DEBUG, debug)
                    self.detailedresults += "Unable to correct contents for " + \
                        kfile + "\n"
                    return False
                elif not self.editor.commit():
                    debug = "Kveditor commit is failing for file " + \
                            kfile + "\n"
                    self.logger.log(LogPriority.DEBUG, debug)
                    self.detailedresults += "Unable to correct contents for " + \
                               kfile + "\n"
                    return False
        uid = getpwnam(user)[2]
        gid = getpwnam(user)[3]

        if uid != "" and gid != "":
            os.chmod(kfile, 0o600)
            os.chown(kfile, uid, gid)
            resetsecon(kfile)
        else:
            success = False
            self.detailedresults += "Unable to obtain uid and gid of " + user + "\n"
            self.logger.log(LogPriority.DEBUG, self.detailedresults)

        return success

    def undo(self):
        self.detailedresults += "This rule cannot be reverted\n"
        self.rulesuccess = False
        self.formatDetailedResults("undo", self.rulesuccess, self.detailedresults)
