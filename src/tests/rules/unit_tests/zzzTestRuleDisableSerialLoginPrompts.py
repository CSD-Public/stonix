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
This is a Unit Test for Rule DisableSerialLoginPrompts

@author: Eric Ball
@change: 2015/08/03 eball Original Implementation
@change: 2016/02/10 roy Added sys.path.append for being able to unit test this
                        file as well as with the test harness.
'''
from __future__ import absolute_import
import unittest
import os
import sys
import traceback

sys.path.append("../../../..")
from src.tests.lib.RuleTestTemplate import RuleTest
from src.tests.lib.logdispatcher_mock import LogPriority
from src.stonix_resources.stonixutilityfunctions import createFile, writeFile
from src.stonix_resources.rules.DisableSerialLoginPrompts import DisableSerialLoginPrompts


class zzzTestRuleDisableSerialLoginPrompts(RuleTest):

    def setUp(self):
        RuleTest.setUp(self)
        self.rule = DisableSerialLoginPrompts(self.config, self.environ,
                                              self.logdispatch,
                                              self.statechglogger)
        self.rulename = self.rule.rulename
        self.rulenumber = self.rule.rulenumber

    def tearDown(self):
        if os.path.exists(self.tmppath):
            try:
                os.rename(self.tmppath, self.path)
            except Exception:
                self.logdispatch.log(LogPriority.ERROR, traceback.format_exc())

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
        self.path = "/etc/securetty"
        self.tmppath = self.path + ".utmp"
        sttyText = '''vc/1
vc/2
vc/3
vc/4
vc/5
vc/6
tty1
tty2
tty3
tty4
tty5
tty6
console
ttyS0
ttyS1
'''
        if os.path.exists(self.path):
            try:
                os.rename(self.path, self.tmppath)
            except Exception:
                success = False
                self.logdispatch.log(LogPriority.ERROR, traceback.format_exc())
        if not createFile(self.path, self.logdispatch):
            success = False
        if not writeFile(self.path, sttyText, self.logdispatch):
            success = False

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
