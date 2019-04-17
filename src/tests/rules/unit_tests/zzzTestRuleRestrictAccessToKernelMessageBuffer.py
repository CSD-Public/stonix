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
This is a Unit Test for Rule RestrictAccessToKernelMessageBuffer

@author: Breen Malmberg
@change: 05/17/2016 original implementation
'''

from __future__ import absolute_import
import sys
import unittest

sys.path.append("../../../..")
from src.tests.lib.RuleTestTemplate import RuleTest
from src.stonix_resources.CommandHelper import CommandHelper
from src.tests.lib.logdispatcher_mock import LogPriority
from src.stonix_resources.rules.RestrictAccessToKernelMessageBuffer import RestrictAccessToKernelMessageBuffer


class zzzTestRuleRestrictAccessToKernelMessageBuffer(RuleTest):

    def setUp(self):
        RuleTest.setUp(self)
        self.rule = RestrictAccessToKernelMessageBuffer(self.config,
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
        @author: ekkehard j. koch
        '''

        success = True
        self.ch.executeCommand("sysctl -w kernel.dmesg_restrict=0")
        return success

    def test_initobjs(self):
        '''
        test initobjs method of RestrictAccessToKernelMessageBuffer
        '''

        self.rule.initobjs()
        self.assertFalse(self.rule.ch == None, "initobjs method should successfully initialize the command helper object self.ch within the rule.")

    def test_localize(self):
        '''
        test localize method of RestrictAccessToKernelMessageBuffer
        '''

        self.rule.localize()
        self.assertFalse(self.rule.fixcommand == "", "localize should set the fixcommand variable to the correct command string.")
        self.assertFalse(self.rule.fixcommand == None, "localize should set the fixcommand variable to the correct command string.")
        self.assertFalse(self.rule.reportcommand == "", "localize should set the reportcommand variable to the correct command string.")
        self.assertFalse(self.rule.reportcommand == None, "localize should set the reportcommand variable to the correct command string.")

    def test_reportFalse(self):
        '''
        test report return value in case of non compliant state
        '''

        self.ch.executeCommand("sysctl -w kernel.dmesg_restrict=0")
        self.assertFalse(self.rule.report(), "when the kernel.dmesg_restrict option is set to 0, report should always return False")

    def test_reportTrue(self):
        '''
        test report return value in case of compliant state
        '''

        self.ch.executeCommand("sysctl -w kernel.dmesg_restrict=1")
        self.assertTrue(self.rule.report(), "when the kernel.dmesg_restrict option is set to 1, report should always return True")

    def checkReportForRule(self, pCompliance, pRuleSuccess):
        '''
        check on whether report was correct
        @param self: essential if you override this definition
        @param pCompliance: the self.iscompliant value of rule
        @param pRuleSuccess: did report run successfully
        @return: boolean - If successful True; If failure False
        @author: ekkehard j. koch
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
        @author: ekkehard j. koch
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
        @author: ekkehard j. koch
        '''
        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " + \
                             str(pRuleSuccess) + ".")
        success = True
        return success

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
