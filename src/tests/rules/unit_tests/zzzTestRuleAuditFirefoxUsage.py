#!/usr/bin/env python
###############################################################################
#                                                                             #
# Copyright 2015.  Los Alamos National Security, LLC. This material was       #
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
This is a Unit Test for Rule AuditFirefoxUsage

@author: Eric Ball
@change: 2016/05/06 eball Original implementation
@change: 2016/08/01 eball Added conditional before running tests
@change: 2016/09/15 eball Moved profiles.ini var to profilePath, made mozPath
    the parent directory again
'''
from __future__ import absolute_import
import os
import shutil
import unittest
from time import sleep
from src.stonix_resources.CommandHelper import CommandHelper
from src.stonix_resources.pkghelper import Pkghelper
from src.stonix_resources.rules.AuditFirefoxUsage import AuditFirefoxUsage
from src.tests.lib.logdispatcher_mock import LogPriority
from src.tests.lib.RuleTestTemplate import RuleTest


class zzzTestRuleAuditFirefoxUsage(RuleTest):

    def setUp(self):
        RuleTest.setUp(self)
        self.rule = AuditFirefoxUsage(self.config,
                                      self.environ,
                                      self.logdispatch,
                                      self.statechglogger)
        self.rulename = self.rule.rulename
        self.rulenumber = self.rule.rulenumber
        self.ch = CommandHelper(self.logdispatch)
        self.ph = Pkghelper(self.logdispatch, self.environ)
        self.initMozDir = False
        self.moveMozDir = False
        self.mozPath = "/root/.mozilla/firefox"
        self.profilePath = "/root/.mozilla/firefox/profiles.ini"

    def tearDown(self):
        mozPath = self.mozPath
        if self.initMozDir and os.path.exists(mozPath):
            shutil.rmtree(mozPath)
        elif self.moveMozDir:
            if os.path.exists(mozPath):
                shutil.rmtree(mozPath)
            if os.path.exists(mozPath + ".stonixtmp"):
                os.rename(mozPath + ".stonixtmp", mozPath)

    def runTest(self):
        profilePath = self.profilePath
        if self.ph.check("firefox"):
            self.browser = "/usr/bin/firefox"
            self.setConditionsForRule()
            # setConditionsForRule will not work on a remote terminal. If the
            # path doesn't exist, we will skip the test.
            if os.path.exists(profilePath):
                self.assertFalse(self.rule.report(), "Report was not false " +
                                 "after test conditions were set")
            else:
                self.logdispatch.log(LogPriority.DEBUG,
                                     "Firefox directory was not created. " +
                                     "Skipping test.")
        elif self.ph.check("iceweasel"):
            self.browser = "/usr/bin/iceweasel"
            self.setConditionsForRule()
            # setConditionsForRule will not work on a remote terminal. If the
            # path doesn't exist, we will skip the test.
            if os.path.exists(profilePath):
                self.assertFalse(self.rule.report(), "Report was not false " +
                                 "after test conditions were set")
            else:
                self.logdispatch.log(LogPriority.DEBUG,
                                     "Firefox directory was not created. " +
                                     "Skipping test.")
        else:
            debug = "Firefox not installed. Unit test will not make " + \
                "any changes."
            self.logdispatch.log(LogPriority.DEBUG, debug)
            return True

    def setConditionsForRule(self):
        '''
        Configure system for the unit test
        @param self: essential if you override this definition
        @return: boolean - If successful True; If failure False
        @author: Eric Ball
        '''
        success = True
        browser = self.browser
        mozPath = self.mozPath

        if not os.path.exists(mozPath):
            self.ch.wait = False
            command = [browser, "google.com"]
            self.ch.executeCommand(command)
            sleep(15)
            self.initMozDir = True
        else:
            self.ch.wait = False
            os.rename(mozPath, mozPath + ".stonixtmp")
            command = [browser, "google.com"]
            self.ch.executeCommand(command)
            sleep(15)
            self.moveMozDir = True

        command = ["/usr/bin/killall", "-q", "-u", "root", browser]
        self.ch.executeCommand(command)

        return success

    def checkReportForRule(self, pCompliance, pRuleSuccess):
        '''
        check on whether report was correct
        @param self: essential if you override this definition
        @param pCompliance: the self.iscompliant value of rule
        @param pRuleSuccess: did report run successfully
        @return: boolean - If successful True; If failure False
        @author: ekkehard j. koch
        '''
        self.logdispatch.log(LogPriority.DEBUG, "pCompliance = " +
                             str(pCompliance) + ".")
        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " +
                             str(pRuleSuccess) + ".")
        success = True
        return success

    def checkFixForRule(self, pRuleSuccess):
        '''
        check on whether fix was correct
        @param self: essential if you override this definition
        @param pRuleSuccess: did report run successfully
        @return: boolean - If successful True; If failure False
        @author: ekkehard j. koch
        '''
        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " +
                             str(pRuleSuccess) + ".")
        success = True
        return success

    def checkUndoForRule(self, pRuleSuccess):
        '''
        check on whether undo was correct
        @param self: essential if you override this definition
        @param pRuleSuccess: did report run successfully
        @return: boolean - If successful True; If failure False
        @author: ekkehard j. koch
        '''
        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " +
                             str(pRuleSuccess) + ".")
        success = True
        return success

if __name__ == "__main__":
    unittest.main()
