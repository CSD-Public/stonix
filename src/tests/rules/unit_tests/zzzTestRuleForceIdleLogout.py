#!/usr/bin/env python3
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
This is a Unit Test for Rule ForceIdleLogout

@author: Eric Ball
@change: 2016/08/25 Original Implementation
'''

import unittest
import sys
import os
import re
from random import randint

sys.path.append("../../../..")
from src.tests.lib.RuleTestTemplate import RuleTest
from src.tests.lib.logdispatcher_mock import LogPriority
from src.stonix_resources.rules.ForceIdleLogout import ForceIdleLogout
from src.stonix_resources.pkghelper import Pkghelper
from src.stonix_resources.CommandHelper import CommandHelper
from src.stonix_resources.stonixutilityfunctions import readFile
from src.stonix_resources.KVEditorStonix import KVEditorStonix


class zzzTestRuleForceIdleLogout(RuleTest):

    def setUp(self):
        RuleTest.setUp(self)
        self.rule = ForceIdleLogout(self.config,
                                    self.environ,
                                    self.logdispatch,
                                    self.statechglogger)
        self.logger = self.logdispatch
        self.rulename = self.rule.rulename
        self.rulenumber = self.rule.rulenumber
        self.rule.filci.updatecurrvalue(True)
        self.checkUndo = True
        self.cmdhelper = CommandHelper(self.logger)
        self.ph = Pkghelper(self.logger, self.environ)
        self.gnomesettingpath = "/etc/dconf/db/local.d/00-autologout"
        self.gnomelockpath = "/etc/dconf/db/local.d/locks/autologout"
        self.undotimeout = ""
        self.undoforcelogout = ""
        self.kdesddm = False
        myos = self.environ.getostype().lower()
        if re.search("red hat", myos) or re.search("centos", myos):
            self.gconf = "GConf2"
        else:
            self.gconf = "gconf2"
        self.timeoutci = self.rule.timeoutci.getcurrvalue()

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
        if self.environ.osfamily == 'linux':
            try:
                self.seconds = self.timeoutci * 60
            except(TypeError):
                debug = "FORCEIDLELOGOUTTIMEOUT value is not " + \
                                        "valid!\n"
                self.logger.log(LogPriority.DEBUG, debug)
                return False
            self.kdesddm = self.ph.check("sddm")
            self.gnomesettingpath = "/etc/dconf/db/local.d/00-autologout"
            desktopmgr = False
            desktopmgrs = ["gdm", "gdm3", "kdm", "kde-workspace", "sddm", "patterns-kde-kde_yast"]
            if self.ph.check("gdm") or self.ph.check("gdm3"):
                desktopmgr = True
            if self.ph.check("kdm") or self.ph.check("kde-workspace")or \
                    self.ph.check("sddm") or self.ph.check("patterns-kde-kde_yast"):
                desktopmgr = True
            if not desktopmgr:
                for mgr in desktopmgrs:
                    if self.ph.checkAvailable(mgr):
                        if self.ph.install(mgr):
                            desktopmgr = True
                if not desktopmgr:
                    success = False
                    debug = "Unable to install a desktop manager for testing\n"
                    self.logger.log(LogPriority.DEBUG, debug)
            success = self.setgnome()
            success = self.setkde()
        elif self.environ.getosfamily() == 'darwin':
            if not self.setosx():
                success = False
        return success

    def setgnome(self):
        '''
        @author: dwalker
        @return: bool - success
        '''
        debug = ""
        if self.environ.geteuid() != 0:
            debug = "Unable to set gnome conditions in unit " + \
                "test because user is not root."

        success = True
        if os.path.exists('/etc/dconf/db/local.d'):
            if os.path.exists(self.gnomesettingpath):
                if not os.remove(self.gnomesettingpath):
                    success = False
                    debug = "Unable to remove " + self.gnomesettingpath + \
                        " for unit test preconditions\n"
                    self.logger.log(LogPriority.DEBUG, debug)
        if self.ph.check(self.gconf):
            get = "/usr/bin/gconftool-2 --direct --config-source " + \
                "xml:readwrite:/etc/gconf/gconf.xml.mandatory --get "
            set = "/usr/bin/gconftool-2 --direct --config-source " + \
                "xml:readwrite:/etc/gconf/gconf.xml.mandatory --set "
            unset = "/usr/bin/gconftool-2 --direct --config-source " + \
                "xml/readwrite:/etc/gconf/gconf.xml.mandatory --unset "
            idletimecmd = get + "/desktop/gnome/session/max_idle_time"
            if self.cmdhelper.executeCommand(idletimecmd):
                output = self.cmdhelper.getOutput()
                if output:
                    try:
                        if int(output[0].strip()) == self.seconds:
                            timeout = int(self.seconds) + 5
                            idletimecmd = set + "--type integer /desktop/gnome/session/max_idle_time " + \
                                str(timeout)
                            if not self.cmdhelper.executeCommand(idletimecmd):
                                success = False
                                debug = "Unable to set incorrect timeout value for " + \
                                    "unit test preconditions\n"
                                self.logger.log(LogPriority.DEBUG, debug)
                    except(IndexError):
                        debug = "No output to display timeout value\n"
                        self.logger.log(LogPriority.DEBUG, debug)
            else:
                success = False
                debug = "Unable to obtain the timeout value\n"
                self.logger.log(LogPriority.DEBUG, debug)
            idleactcmd = get + "/desktop/gnome/session/max_idle_action"
            if self.cmdhelper.executeCommand(idleactcmd):
                output = self.cmdhelper.getOutput()
                if output:
                    if re.search("forced-logout", output[0]):
                        idleact = unset + "/desktop/gnome/session/max_idle_action"
                        if not self.cmdhelper.executeCommand(idleact):
                            success = False
                            debug = "Unable to unset max_idle_action for " + \
                                "unit test preconditions\n"
                            self.logger.log(LogPriority.DEBUG, debug)

        return success

    def setkde(self):
        '''
        @author: dwalker
        @return: bool - success
        '''
        success = True
        debug = ""
        if self.kdesddm:
            self.kdecheck = ".config/kdeglobals"
            self.rcpath = ".config/kscreenlockerrc"
            self.kdeprops = {"ScreenSaver": {"Timeout": str(self.seconds)}}
        else:
            self.kdecheck = ".kde"
            self.rcpath = ".kde/share/config/kscreensaverrc"
            self.kdeprops = {"ScreenSaver": {"AutoLogout": "true",
                                             "AutoLogoutTimeout": str(self.seconds)}}
        contents = readFile("/etc/passwd", self.logger)
        for line in contents:
            username = ""
            homepath = ""
            temp = line.split(":")
            try:
                username = temp[0]
                homepath = temp[5]
            except(IndexError):
                continue
            kdeparent = os.path.join(homepath, self.kdecheck)
            kdefile = os.path.join(homepath, self.rcpath)
            if not os.path.exists(kdeparent):
                continue
            elif os.path.exists(kdefile):
                if self.searchFile(kdefile):
                    if not self.messFile(kdefile):
                        success = False
                        debug = "Unable to set incorrect values for kde " + \
                                "for user " + username + " in " + \
                                "unit test preconditions\n"
                        self.logger.log(LogPriority.DEBUG, debug)
        return success

    def searchFile(self, filehandle):
        '''temporary method to separate the code to find directives from the
        rest of the code.  Will put back all in one method eventually
        @author: dwalker
        @return: bool
        @param filehandle: string
        '''
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

    def messFile(self, filehandle):
        success = True
        self.editor = ""
        garbagevalue = ""
        while True:
            garbagevalue = randint(0, 200)
            if garbagevalue != self.timeoutci:
                break
        kvt = "tagconf"
        intent = "present"
        tpath = filehandle + ".tmp"
        conftype = "closedeq"
        if self.kdesddm:
            self.kdecheck = ".config/kdeglobals"
            self.rcpath = ".config/kscreenlockerrc"
            self.kdeprops = {"ScreenSaver": {"Timeout": str(garbagevalue)}}
        else:
            self.kdecheck = ".kde"
            self.rcpath = ".kde/share/config/kscreensaverrc"
            self.kdeprops = {"ScreenSaver": {"AutoLogout": "true",
                                             "AutoLogoutTimeout": str(garbagevalue)}}
        self.editor = KVEditorStonix(self.statechglogger, self.logger, kvt,
                                     filehandle, tpath, self.kdeprops, intent,
                                     conftype)
        self.editor.report()
        if not self.editor.fix():
            success = False
        elif not self.editor.commit():
            success = False
        return success




    def checkReportForRule(self, pCompliance, pRuleSuccess):
        '''check on whether report was correct

        :param self: essential if you override this definition
        :param pCompliance: the self.iscompliant value of rule
        :param pRuleSuccess: did report run successfully
        :returns: boolean - If successful True; If failure False
        @author: ekkehard j. koch

        '''
        self.logdispatch.log(LogPriority.DEBUG, "pCompliance = " +
                             str(pCompliance) + ".")
        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " +
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
        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " +
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
        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " +
                             str(pRuleSuccess) + ".")
        success = True
        return success

if __name__ == "__main__":
    unittest.main()
