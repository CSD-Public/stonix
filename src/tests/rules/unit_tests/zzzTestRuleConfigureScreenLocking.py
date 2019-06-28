#!/usr/bin/env python
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
This is a Unit Test for Rule ConfigureAppleSoftwareUpdate

@author: ekkehard j. koch
@change: 03/26/2013 Original Implementation
@change: 2016/02/10 roy Added sys.path.append for being able to unit test this
                        file as well as with the test harness.
'''
from __future__ import absolute_import
import unittest
import sys
import re
import os
import traceback
import time

sys.path.append("../../../..")
from glob import glob
from pwd import getpwnam
from src.tests.lib.RuleTestTemplate import RuleTest
from src.stonix_resources.CommandHelper import CommandHelper
from src.tests.lib.logdispatcher_mock import LogPriority
from src.stonix_resources.rules.ConfigureScreenLocking import ConfigureScreenLocking
from src.stonix_resources.KVEditorStonix import KVEditorStonix
from src.stonix_resources.stonixutilityfunctions import iterate, checkPerms, setPerms, createFile
from src.stonix_resources.stonixutilityfunctions import readFile, resetsecon, getOctalPerms, writeFile
from subprocess import PIPE, Popen


class zzzTestRuleConfigureScreenLocking(RuleTest):

    def setUp(self):
        RuleTest.setUp(self)
        self.rule = ConfigureScreenLocking(self.config,
                                           self.environ,
                                           self.logdispatch,
                                           self.statechglogger)
        self.logger = self.logdispatch
        self.rulename = self.rule.rulename
        self.rulenumber = self.rule.rulenumber
        self.effectiveUserID = self.environ.geteuid()
        self.ch = CommandHelper(self.logdispatch)
        self.dc = "/usr/bin/defaults"

    def tearDown(self):
        pass

    def runTest(self):
        self.simpleRuleTest()

    def setConditionsForRule(self):
        '''Configure system for the unit test

        :param self: essential if you override this definition
        :returns: boolean - If successful True; If failure False
        @author: ekkehard j. koch

        '''
        success = True
        if self.environ.getosfamily() == "darwin":
            if self.effectiveUserID == 0:
                if success:
                    command = [self.dc, "-currentHost", "delete",
                               "/Library/Preferences/com.apple.screensaver",
                               "askForPassword"]
                    self.logdispatch.log(LogPriority.DEBUG, str(command))
                    success = self.ch.executeCommand(command)
                if success:
                    command = [self.dc, "-currentHost", "delete",
                               "/Library/Preferences/com.apple.screensaver",
                               "idleTime"]
                    self.logdispatch.log(LogPriority.DEBUG, str(command))
                    success = self.ch.executeCommand(command)
                if success:
                    command = [self.dc, "-currentHost", "delete",
                               "/Library/Preferences/com.apple.screensaver",
                               "loginWindowIdleTime"]
                    self.logdispatch.log(LogPriority.DEBUG, str(command))
                    success = self.ch.executeCommand(command)
            else:
                if success:
                    command = [self.dc, "-currentHost", "delete",
                               "~/Library/Preferences/com.apple.screensaver",
                               "askForPassword"]
                    self.logdispatch.log(LogPriority.DEBUG, str(command))
                    success = self.ch.executeCommand(command)
                if success:
                    command = [self.dc, "-currentHost", "delete",
                               "~/Library/Preferences/com.apple.screensaver",
                               "askForPasswordDelay"]
                    self.logdispatch.log(LogPriority.DEBUG, str(command))
                    success = self.ch.executeCommand(command)
        else:
            success1 = self.setkde()
            if self.effectiveUserID == 0:
                success2 = self.setgnome()
            else:
                success2 = True
            if success1 and success2:
                success = True
            else:
                success = False
        return success

    def setkde(self):
        '''Method to setup kde desktop to not be compliant
        @author: dwalker


        :returns: bool

        '''
        self.kdeprops = {"ScreenSaver": {"Enabled": "true",
                                             "Lock": "true",
                                             "LockGrace": "60000",
                                             "Timeout": "840"}}
        self.kderuin = []
        debug = "Inside setkde method"
        success = True
        bindir = glob("/usr/bin/kde*")
        kdefound = False
        for kdefile in bindir:
            if re.search("^/usr/bin/kde\d$", str(kdefile)):
                kdefound = True
        if kdefound and self.environ.geteuid() == 0:
            contents = readFile("/etc/passwd", self.logger)
            if not contents:
                debug += "You have some serious issues, /etc/passwd is blank\n"
                self.logger.log(LogPriority.ERROR, debug)
                return False
            for line in contents:
                temp = line.split(":")
                try:
                    if int(temp[2]) >= 500:
                        if temp[5] and re.search('/', temp[5]):
                            homebase = temp[5]
                            if not re.search("^/home/", homebase):
                                continue
                            kfile = homebase + "/.kde/share/config/kscreensaverrc"
                            if os.path.exists(kfile):
                                uid = getpwnam(temp[0])[2]
                                gid = getpwnam(temp[0])[3]
                                if checkPerms(kfile, [uid, gid, 0o600],
                                                  self.logger):
                                    if not setPerms(kfile, [0, 0, 0o644],
                                                    self.logger):
                                        success = False
                                        debug += "Unable to set incorrect perms " + \
                                            "on " + kfile + " for testing\n"
                                if not self.wreckFile(kfile):
                                    debug += "Was not able to mess " + \
                                        "up file for testing\n"
                                    success = False
                        else:
                            debug += "placeholder 6 in /etc/passwd is not a \
directory, invalid form of /etc/passwd"
                            self.logger.log(LogPriority.ERROR, debug)
                            return False
                except IndexError:
                    success = False
                    debug += traceback.format_exc() + "\n"
                    debug += "Index out of range\n"
                    self.logger.log(LogPriority.ERROR, debug)
                    break
                except Exception:
                    break
        elif kdefound:
            who = "/usr/bin/whoami"
            message = Popen(who, stdout=PIPE, shell=False)
            info = message.stdout.read().strip()
            contents = readFile('/etc/passwd', self.logger)
            if not contents:
                debug += "You have some serious issues, /etc/passwd is blank\n"
                self.logger.log(LogPriority.ERROR, debug)
                return False
            compliant = True
            for line in contents:
                temp = line.split(':')
                try:
                    if temp[0] == info:
                        if temp[5] and re.search('/', temp[5]):
                            homebase = temp[5]
                            if not re.search("^/home/", homebase):
                                continue
                            kfile = homebase + "/.kde/share/config/kscreensaverrc"
                            if os.path.exists(kfile):
                                uid = getpwnam(temp[0])[2]
                                gid = getpwnam(temp[0])[3]
                                if checkPerms(kfile, [uid, gid, 0o600],
                                                  self.logger):
                                    if not setPerms(kfile, [0, 0, 0o644],
                                                    self.logger):
                                        success = False
                                        debug += "Unable to set incorrect perms " + \
                                            "on " + kfile + " for testing\n"
                                if not self.wreckFile(kfile):
                                    debug += "Was not able to mess " + \
                                        "up file for testing\n"
                                    success = False
                        else:
                            debug += "placeholder 6 in /etc/passwd is not a \
directory, invalid form of /etc/passwd"
                            self.logger.log(LogPriority.ERROR, debug)
                            return False
                        break
                except IndexError:
                    success = False
                    debug += traceback.format_exc() + "\n"
                    debug += "Index out of range\n"
                    self.logger.log(LogPriority.ERROR, debug)
                    self.detailedresults += "Unexpected formatting in " + \
                        "/etc/passwd"
                    break
                except Exception:
                    debug += traceback.format_exc() + "\n"
                    self.logger.log(LogPriority.ERROR, debug)
                    break
        return success

    def setgnome(self):
        '''Method to setup gnome desktop to not be compliant
        @author: dwalker


        :returns: bool

        '''
        success = True
        debug = "Inside setgnome method\n"
        gconf = "/usr/bin/gconftool-2"
        gsettings = "/usr/bin/gsettings"
        dconfsettingslock = "/etc/dconf/db/local.d/locks/stonix-settings.conf"
        dconflockdata = ["/org/gnome/desktop/session/idle-delay",
                           "/org/gnome/desktop/screensaver/idle-activation-enabled",
                           "/org/gnome/desktop/screensaver/lock-enabled",
                           "/org/gnome/desktop/screensaver/lock-delay",
                           "/org/gnome/desktop/screensaver/picture-uri"]
        dconfsettings = "/etc/dconf/db/local.d/local.key"
        dconfdata = {"org/gnome/desktop/screensaver": {
                        "idle-activation-enabled": "true",
                        "lock-enabled": "true",
                        "lock-delay": "0",
                        "picture-opacity": "100",
                        "picture-uri": "\'\'"},
                    "org/gnome/desktop/session": {
                        "idle-delay": "uint32 900"}}
        dconfuserprofile = "/etc/dconf/profile/user"
        userprofilecontent = "user-db:user\n" + \
                                          "system-db:local"
        if os.path.exists(gconf):
            setcmds1 = ["/apps/gnome-screensaver/idle_activation_enabled false",
                       "/apps/gnome-screensaver/lock_enabled false"]
            setcmds2 = "/desktop/gnome/session/idle_delay 5"
            for cmd in setcmds1:
                cmd2 = gconf + " --type bool --set " + cmd
                if not self.ch.executeCommand(cmd2):
                    success = False
                    debug += "Issues setting " + cmd2 + "\n"
            cmd2 = gconf + " --type int --set " + setcmds2
            if not self.ch.executeCommand(cmd2):
                success = False
                debug += "Issues setting " + cmd2 + "\n"
        if os.path.exists(gsettings):
            # delete lock file so that
            if os.path.exists(dconfsettingslock):
                os.remove(dconfsettingslock)
                cmd = "/usr/bin/dconf update"
                self.ch.executeCommand(cmd)
            setcmds = [" set org.gnome.desktop.screensaver " +
                       "idle-activation-enabled false",
                       " set org.gnome.desktop.screensaver lock-enabled false",
                       " set org.gnome.desktop.screensaver lock-delay 10",
                       " set org.gnome.desktop.screensaver picture-opacity 50",
                       " set org.gnome.desktop.session idle-delay 20"]
            for cmd in setcmds:
                cmd2 = gsettings + cmd
                if not self.ch.executeCommand(cmd2):
                    success = False
                    debug += "Issues setting " + cmd2 + "\n"
            #write correct contents to dconf lock file
            if os.path.exists(dconfsettings):
                self.kveditor = KVEditorStonix(self.statechglogger,
                                               self.logger,
                                               "tagconf",
                                               dconfsettings,
                                               dconfsettings + ".tmp",
                                               dconfdata, "notpresent",
                                               "closedeq")
                if not self.kveditor.report():
                    if not self.kveditor.fix():
                        success = False
                        debug += "Unable to set incorrect contents " + \
                            "for " + dconfsettings + "\n"
                    elif not self.kveditor.commit():
                        success = False
                        debug += "Unable to set incorrect contents " + \
                            "for " + dconfsettings + "\n"
        # self.logger.log(LogPriority.ERROR, debug)
        return success

    def wreckFile(self, filehandle):
        '''Method to ensure correct contents are NOT in file for testing
        @author: dwalker

        :param filehandle: string
        :returns: bool

        '''
        self.editor = ""
        kvt = "tagconf"
        intent = "notpresent"
        tpath = filehandle + ".tmp"
        conftype = "closedeq"
        self.editor = KVEditorStonix(self.statechglogger, self.logger, kvt,
                                     filehandle, tpath, self.kdeprops, intent,
                                     conftype)
        if not self.editor.report():
            if self.editor.fix():
                if self.editor.commit():
                    return True
                else:
                    return False
            else:
                return False
        else:
            return True
    
    def checkReportForRule(self, pCompliance, pRuleSuccess):
        '''check on whether report was correct

        :param self: essential if you override this definition
        :param pCompliance: the self.iscompliant value of rule
        :param pRuleSuccess: did report run successfully
        :returns: boolean - If successful True; If failure False
        @author: ekkehard j. koch

        '''
        self.logdispatch.log(LogPriority.DEBUG, "pCompliance = " + \
                             str(pCompliance) + ".")
        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " + \
                             str(pRuleSuccess) + ".")
        success = True
        return success

    def checkFixForRule(self, pRuleSuccess):
        '''check on whether fix was correct

        :param self: essential if you override this definition
        :param pRuleSuccess: did report run successfully
        :returns: boolean - If successful True; If failure False
        @author: ekkehard j. koch

        '''
        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " + \
                             str(pRuleSuccess) + ".")
        success = True
        return success

    def checkUndoForRule(self, pRuleSuccess):
        '''check on whether undo was correct

        :param self: essential if you override this definition
        :param pRuleSuccess: did report run successfully
        :returns: boolean - If successful True; If failure False
        @author: ekkehard j. koch

        '''
        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " + \
                             str(pRuleSuccess) + ".")
        success = True
        return success

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
