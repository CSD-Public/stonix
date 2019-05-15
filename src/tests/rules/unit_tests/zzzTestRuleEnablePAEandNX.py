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
This is a Unit Test for Rule EnablePAEandNX

@author: Breen Malmberg
@change: 5/9/2016 Original Implementation
'''
from __future__ import absolute_import

import sys
import unittest
import os

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
        '''Configure system for the unit test

        :param self: essential if you override this definition
        :returns: boolean - If successful True; If failure False
        @author: ekkehard j. koch

        '''

        success = True
        return success

    def test_checkPAE(self):
        '''test for correct return values for checkPAE method, under multiple conditions
        
        @author: Breen Malmberg


        '''

        self.rule.initobjs()

        self.assertFalse(self.rule.checkPAE([]))
        self.assertFalse(self.rule.checkPAE(1))
        self.assertFalse(self.rule.checkPAE({}))

    def test_path(self):
        ''' '''

        result = os.path.exists("/proc/cpuinfo")
        self.assertTrue(result)

    def test_getSystemARCH(self):
        '''test the return values for getSystemARCH method
        
        @author: Breen Malmberg


        '''

        result = True

        if self.rule.getSystemARCH() not in [32, 64]:
            result = False

        self.assertTrue(result)

    def test_getSystemOS(self):
        '''test return values of getSystemOS method
        
        @author: Breen Malmberg


        '''

        if self.rule.getSystemOS() == "":
            self.fail("getSystemOS returned a blank string. This should never happen.")

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
    # import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
