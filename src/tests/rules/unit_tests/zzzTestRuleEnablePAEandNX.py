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
This is a Unit Test for Rule EnablePAEandNX

@author: Breen Malmberg
@change: 5/9/2016 Original Implementation
'''
from __future__ import absolute_import
import sys
import unittest

sys.path.append("../../../..")
from src.tests.lib.RuleTestTemplate import RuleTest
from src.stonix_resources.CommandHelper import CommandHelper
from src.tests.lib.logdispatcher_mock import LogPriority
from src.stonix_resources.rules.EnablePAEandNX import EnablePAEandNX


class zzzTestRuleEnablePAEandNX(RuleTest):

    def setUp(self):
        RuleTest.setUp(self)
        self.rule = EnablePAEandNX(self.config,
                                  self.environ,
                                  self.logdispatch,
                                  self.statechglogger)
        self.rulename = self.rule.rulename
        self.rulenumber = self.rule.rulenumber
        self.rule.ci.updatecurrvalue(True)
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
        @author: ekkehard j. koch
        '''

        success = True
        return success

    def test_checkPAE(self):
        '''
        test for correct return values for checkPAE method, under multiple conditions

        @author: Breen Malmberg
        '''

        self.rule.initobjs()

        self.assertFalse(self.rule.checkPAE(""), "checkPAE should return False if no package is specified")
        self.assertFalse(self.rule.checkPAE([]), "checkPAE should return False if package specified is not of type: string")
        self.assertFalse(self.rule.checkPAE(1), "checkPAE should return False if package specified is not of type: string")
        self.assertFalse(self.rule.checkPAE({}), "checkPAE should return False if package specified is not of type: string")

    def test_getSystemARCH(self):
        '''
        test the return values for getSystemARCH method

        @author: Breen Malmberg
        '''

        self.assertFalse(self.rule.getSystemARCH() not in [32, 64], "The return value of getSystemARCH should always be either 32 or 64")
        self.assertTrue(self.rule.getSystemARCH() in [32, 64], "The return value of getSystemARCH should always be either 32 or 64")

    def test_getSystemOS(self):
        '''
        test return values of getSystemOS method

        @author: Breen Malmberg
        '''

        self.assertFalse(self.rule.getSystemOS() == "", "getSystemOS should never return a blank string")

    def test_checkNX(self):
        '''
        test returns for checkNX method

        @author: Breen Malmberg
        '''

        # stub
        pass

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
    # import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
