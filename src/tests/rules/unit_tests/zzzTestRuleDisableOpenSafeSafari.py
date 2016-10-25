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
This is a Unit Test for Rule DisableOpenSafeSafari
Created on Jan 22, 2015

@author: dwalker
@change: 2015-02-25 - ekkehard - Updated to make unit test work
@change: 2016/02/10 roy Added sys.path.append for being able to unit test this
                        file as well as with the test harness.
'''
from __future__ import absolute_import
import unittest
import sys

sys.path.append("../../../..")
from src.tests.lib.RuleTestTemplate import RuleTest
from src.stonix_resources.CommandHelper import CommandHelper
from src.tests.lib.logdispatcher_mock import LogPriority
from src.stonix_resources.rules.DisableOpenSafeSafari import DisableOpenSafeSafari

class zzzTestRuleDisableOpenSafeSafari(RuleTest):
    
    def setUp(self):
        RuleTest.setUp(self)
        self.rule = DisableOpenSafeSafari(self.config,
                                          self.environ,
                                          self.logdispatch,
                                          self.statechglogger)
        self.rulename = self.rule.rulename
        self.rulenumber = self.rule.rulenumber
        self.ch = CommandHelper(self.logdispatch)
        self.dc = "/usr/bin/defaults"
        self.path = "com.apple.Safari"
        self.key = "AutoOpenSafeDownloads"
    def tearDown(self):
        pass

    def runTest(self):
        self.simpleRuleTest()

    def setConditionsForRule(self):
        '''
        This makes sure the intial report fails by executing the following
        commands:
        defaults write com.apple.Safari AutoOpenSafeDownloads -bool yes
        @param self: essential if you override this definition
        @return: boolean - If successful True; If failure False
        @author: dwalker
        '''
        success = False
        cmd = [self.dc, "write", self.path, self.key, "-bool", "yes"]
        self.logdispatch.log(LogPriority.DEBUG, str(cmd))
        if self.ch.executeCommand(cmd):
            success = self.checkReportForRule(False, True)
        return success
    
    def checkReportForRule(self, pCompliance, pRuleSuccess):
        '''
        To see what happended run these commands:
        defaults read com.apple.Safari AutoOpenSafeDownloads
        @param self: essential if you override this definition
        @return: boolean - If successful True; If failure False
        @author: ekkehard j. koch
        '''
        success = True
        self.logdispatch.log(LogPriority.DEBUG, "pCompliance = " + \
                             str(pCompliance) + ".")
        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " + \
                             str(pRuleSuccess) + ".")
        cmd = [self.dc, "read", self.path, self.key]
        self.logdispatch.log(LogPriority.DEBUG, str(cmd))
        if self.ch.executeCommand(cmd):
            output = self.ch.getOutputString()
        return success

    def checkFixForRule(self, pRuleSuccess):
        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " + \
                             str(pRuleSuccess) + ".")
        success = self.checkReportForRule(True, pRuleSuccess)
        return success

    def checkUndoForRule(self, pRuleSuccess):
        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " + \
                             str(pRuleSuccess) + ".")
        success = self.checkReportForRule(False, pRuleSuccess)
        return success

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
