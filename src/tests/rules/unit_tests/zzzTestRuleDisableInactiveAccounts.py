#!/usr/bin/env python
###############################################################################
#                                                                             #
# Copyright 2015-2019.  Los Alamos National Security, LLC. This material was       #
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
This is a Unit Test for Rule DisableInactiveAccounts

@author: Breen Malmberg
@change: 02/11/2016 Original Implementation
'''

from __future__ import absolute_import
import sys
import unittest
import os

sys.path.append("../../../..")
from src.tests.lib.RuleTestTemplate import RuleTest
from src.stonix_resources.CommandHelper import CommandHelper
from src.tests.lib.logdispatcher_mock import LogPriority
from src.stonix_resources.rules.DisableInactiveAccounts import DisableInactiveAccounts


class zzzTestRuleDisableInactiveAccounts(RuleTest):

    def setUp(self):
        RuleTest.setUp(self)
        self.rule = DisableInactiveAccounts(self.config,
                                    self.environ,
                                    self.logdispatch,
                                    self.statechglogger)
        self.rulename = self.rule.rulename
        self.rulenumber = self.rule.rulenumber
        self.ch = CommandHelper(self.logdispatch)

    def tearDown(self):
        pass

    def runTest(self):
        self.setConditionsForRule()
        self.simpleRuleTest()

    def setConditionsForRule(self):
        '''
        Configure system for the unit test
        @param self: essential if you override this definition
        @return: boolean - If successful True; If failure False
        @author: Breen Malmberg
        '''
        success = True
        return success

    def test_dscl_path(self):
        '''
        test for valid location of dscl command path
        @author: Breen Malmberg
        '''

        found = False
        if os.path.exists('/usr/bin/dscl'):
            found = True
        self.assertTrue(found, True)

    def test_get_users(self):
        '''
        test the command to get the list of users
        @author: Breen Malmberg
        '''

        self.ch.executeCommand('/usr/bin/dscl . -ls /Users')
        rc = self.ch.getReturnCode()
        # rc should always be 0 after this command is run (means it ran successfully)
        # however 0 is interpreted as false by python, so.. assertFalse
        self.assertFalse(rc, "The return code for getting the list of users should always be 0 (success)")

    def test_pwpolicy_path(self):
        '''
        test for valid location of pwpolicy command path
        @author: Breen Malmberg
        '''

        found = False
        if os.path.exists('/usr/bin/pwpolicy'):
            found = True
        self.assertTrue(found, True)

    def test_initobjs(self):
        '''
        test whether the private method initobjs works
        @author: Breen Malmberg
        '''

        self.rule.initobjs()
        self.assertTrue(self.rule.cmdhelper, "CommandHelper object should always initialize after initobjs() is run")

    def checkReportForRule(self, pCompliance, pRuleSuccess):
        '''
        check on whether report was correct
        @param self: essential if you override this definition
        @param pCompliance: the self.iscompliant value of rule
        @param pRuleSuccess: did report run successfully
        @return: boolean - If successful True; If failure False
        @author: Breen Malmberg
        '''
        self.logdispatch.log(LogPriority.DEBUG, "pCompliance = " + \
                             str(pCompliance) + ".")
        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " + \
                             str(pRuleSuccess) + ".")
        success = True
        return success

    def checkFixForRule(self, pRuleSuccess):
        '''
        check on whether fix was correct
        @param self: essential if you override this definition
        @param pRuleSuccess: did report run successfully
        @return: boolean - If successful True; If failure False
        @author: Breen Malmberg
        '''
        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " + \
                             str(pRuleSuccess) + ".")
        success = True
        return success

    def checkUndoForRule(self, pRuleSuccess):
        '''
        check on whether undo was correct
        @param self: essential if you override this definition
        @param pRuleSuccess: did report run successfully
        @return: boolean - If successful True; If failure False
        @author: Breen Malmberg
        '''
        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " + \
                             str(pRuleSuccess) + ".")
        success = True
        return success

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
