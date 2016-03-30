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
This is a Unit Test for Rule InstallRootCert

@author: Eric Ball
@change: 2016/03/25 eball Original implementation
'''
from __future__ import absolute_import
import re
import unittest
from src.stonix_resources.CommandHelper import CommandHelper
from src.stonix_resources.rules.InstallRootCert import InstallRootCert
from src.tests.lib.logdispatcher_mock import LogPriority
from src.tests.lib.RuleTestTemplate import RuleTest


class zzzTestRuleInstallRootCert(RuleTest):

    def setUp(self):
        RuleTest.setUp(self)
        self.rule = InstallRootCert(self.config,
                                    self.environ,
                                    self.logdispatch,
                                    self.statechglogger)
        self.rulename = self.rule.rulename
        self.rulenumber = self.rule.rulenumber
        self.ch = CommandHelper(self.logdispatch)

    def tearDown(self):
        pass

    def runTest(self):
        self.simpleRuleTest()

    def setConditionsForRule(self):
        '''
        Configure system for the unit test
        @param self: essential if you override this definition
        @return: boolean - If successful True; If failure False
        @author: Eric Ball
        '''
        success = True
        self.missingSystemCert = False
        cmd = ["curl", "https://gitlab.lanl.gov"]
        if not self.ch.executeCommand(cmd):
            success = False
        if re.search("not recoginized", self.ch.getAllString()):
            self.missingSystemCert = True
        return success

    def testUndo(self):
        self.rule.report()
        initialDetailedResults = self.rule.detailedresults
        self.rule.fix()
        postFixDetailedResults = self.rule.detailedresults
        if not (initialDetailedResults == postFixDetailedResults):
            self.rule.undo()
            self.rule.report()
            postUndoDetailedResults = self.rule.detailedresults
            self.assertEqual(initialDetailedResults, postUndoDetailedResults,
                             "Undo did not return the system to its initial " +
                             "state")

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
        @author: Eric Ball
        '''
        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " +
                             str(pRuleSuccess) + ".")
        success = True
        cmd = ["curl", "https://gitlab.lanl.gov"]
        if not self.ch.executeCommand(cmd):
            success = False
        if self.missingSystemCert:
            self.assertTrue(re.search("<html>", self.ch.getAllString()),
                            "Rule fix did not allow error-free connection " +
                            "to gitlab.lanl.gov")
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
