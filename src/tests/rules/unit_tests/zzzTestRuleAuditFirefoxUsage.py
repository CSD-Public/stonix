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

    def tearDown(self):
        if self.initMozDir:
            shutil.rmtree("/root/.mozilla")
        elif self.moveMozDir:
            shutil.rmtree("/root/.mozilla")
            os.rename("/root/.mozilla.stonixtmp", "/root/.mozilla")

    def runTest(self):
        if self.ph.check("firefox"):
            self.browser = "firefox"
            self.setConditionsForRule()
            self.assertFalse(self.rule.report())
        elif self.ph.check("iceweasel"):
            self.browser = "iceweasel"
            self.setConditionsForRule()
            self.assertFalse(self.rule.report())
        else:
            debug = "Firefox not installed. Unit test will not make any " + \
                "changes."
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

        if not os.path.exists("/root/.mozilla"):
            self.ch.wait = False
            command = [browser, "google.com"]
            self.ch.executeCommand(command)
            sleep(5)
            self.initMozDir = True
        else:
            self.ch.wait = False
            os.rename("/root/.mozilla", "/root/.mozilla.stonixtmp")
            command = [browser, "google.com"]
            self.ch.executeCommand(command)
            sleep(10)
            self.moveMozDir = True

        command = ["killall", "-q", "-u", "root", browser]
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
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
