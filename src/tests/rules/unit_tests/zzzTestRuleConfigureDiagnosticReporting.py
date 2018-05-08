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
This is a Unit Test for Rule ConfigureDiagnosticReporting

@author: Eric Ball
@change: 2016/07/07 Original Implementation
'''
from __future__ import absolute_import
import sys
import unittest

sys.path.append("../../../..")
from src.tests.lib.RuleTestTemplate import RuleTest
from src.stonix_resources.CommandHelper import CommandHelper
from src.tests.lib.logdispatcher_mock import LogPriority
from src.stonix_resources.rules.ConfigureDiagnosticReporting import ConfigureDiagnosticReporting


class zzzTestRuleConfigureDiagnosticReporting(RuleTest):

    def setUp(self):
        RuleTest.setUp(self)
        self.rule = ConfigureDiagnosticReporting(self.config,
                                                 self.environ,
                                                 self.logdispatch,
                                                 self.statechglogger)
        self.rulename = self.rule.rulename
        self.rulenumber = self.rule.rulenumber
        self.ch = CommandHelper(self.logdispatch)
        self.dc = "/usr/bin/defaults"

    def tearDown(self):
        pass

    def runTest(self):
        self.simpleRuleTest()

    def setConditionsForRule(self):
        '''
        This makes sure the initial report fails

        @param self: essential if you override this definition
        @return: boolean - If successful True; If failure False
        @author: Eric Ball
        '''
        success = True
        if success:
            command = [self.dc, "write", "/Library/Application Support/" +
                       "CrashReporter/DiagnosticMessagesHistory.plist",
                       "AutoSubmit", "-bool", "yes"]
            self.logdispatch.log(LogPriority.DEBUG, str(command))
            success = self.ch.executeCommand(command)
        if success:
            version = self.environ.getosver()
            versionsplit = version.split(".")
            if len(versionsplit) >= 2:
                minorversion = int(versionsplit[1])
            else:
                minorversion = 0
            if minorversion >= 10:
                command = [self.dc, "write", "/Library/Application Support/" +
                           "CrashReporter/DiagnosticMessagesHistory.plist",
                           "ThirdPartyDataSubmit", "-bool", "yes"]
                self.logdispatch.log(LogPriority.DEBUG, str(command))
                success = self.ch.executeCommand(command)
        return success

    def checkReportForRule(self, pCompliance, pRuleSuccess):
        '''
        Did the first rule report do what it was supposed to
        @param self: essential if you override this definition
        @param pCompliance: compliance of first rule report boolean
        @param pRuleSuccess: success of first report execution boolean
        @return: boolean - If successful True; If failure False
        @author: ekkehard j. koch
        '''
        self.logdispatch.log(LogPriority.DEBUG, "pCompliance = " +
                             str(pCompliance) + ".")
        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " +
                             str(pRuleSuccess) + ".")
        success = True
        if pCompliance:
            success = False
            self.logdispatch.log(LogPriority.DEBUG, "pCompliance = " +
                                 str(pCompliance) + " it should be false!")
        if not pRuleSuccess:
            success = False
            self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " +
                                 str(pRuleSuccess) + " it should be true!")
        return success

    def checkFixForRule(self, pRuleSuccess):
        '''
        Did the rule fix do what it was supposed to
        @param self: essential if you override this definition
        @param pRuleSuccess: success of fix execution boolean
        @return: boolean - If successful True; If failure False
        @author: ekkehard j. koch
        '''
        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " +
                             str(pRuleSuccess) + ".")
        success = True
        if not pRuleSuccess:
            success = False
            self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " +
                                 str(pRuleSuccess) + " it should be true!")
        return success

    def checkReportFinalForRule(self, pCompliance, pRuleSuccess):
        '''
        Did the final rule report do what it was supposed to
        @param self: essential if you override this definition
        @param pCompliance: compliance of final rule report boolean
        @param pRuleSuccess: success of final report execution boolean
        @return: boolean - If successful True; If failure False
        @author: ekkehard j. koch
        '''

        self.logdispatch.log(LogPriority.DEBUG, "pCompliance = " +
                             str(pCompliance) + ".")
        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " +
                             str(pRuleSuccess) + ".")
        success = True
        if not pCompliance:
            success = False
            self.logdispatch.log(LogPriority.DEBUG, "pCompliance = " +
                                 str(pCompliance) + " it should be true!")
        if not pRuleSuccess:
            success = False
            self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " +
                                 str(pRuleSuccess) + " it should be true!")
        return success

    def checkUndoForRule(self, pRuleSuccess):
        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " +
                             str(pRuleSuccess) + ".")
        if not pRuleSuccess:
            success = False
            self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " +
                                 str(pRuleSuccess) + " it should be true!")
        return success

if __name__ == "__main__":
    unittest.main()
