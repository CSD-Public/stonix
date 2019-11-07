#!/usr/bin/env python3
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


"""
This is a Unit Test for Rule TCPWrappers

@author: ekkehard j. koch
@change: 03/18/2013 Original Implementation
@change: 2016/02/10 roy Added sys.path.append for being able to unit test this
                        file as well as with the test harness.
"""


import unittest
import sys

sys.path.append("../../../..")
from src.tests.lib.RuleTestTemplate import RuleTest
from src.tests.lib.logdispatcher_mock import LogPriority
from src.stonix_resources.rules.TCPWrappers import TCPWrappers


class zzzTestRuleTCPWrappers(RuleTest):

    def setUp(self):
        ''' '''

        RuleTest.setUp(self)
        self.rule = TCPWrappers(self.config, self.environ, self.logdispatch, self.statechglogger)
        self.rulename = self.rule.rulename
        self.rulenumber = self.rule.rulenumber

    def tearDown(self):
        ''' '''

        pass

    def runTest(self):
        ''' '''

        self.simpleRuleTest()

    def setConditionsForRule(self):
        '''Configure system for the unit test


        :returns: boolean - If successful True; If failure False
        @author: ekkehard j. koch

        '''

        success = True
        return success

    def test_convert(self):
        '''test the convert method in tcpwrappers'''

        self.assertEqual("", self.rule.convert_to_legacy(""))
        self.assertEqual("name.domain", self.rule.convert_to_legacy("name.domain"))
        self.assertEqual("129.175.0.0/255.255.0.0", self.rule.convert_to_legacy("129.175.0.0/16"))
        self.assertEqual("129.175.1.0/255.255.255.0", self.rule.convert_to_legacy("129.175.1.0/24"))
        self.assertEqual("129.0.0.0/255.0.0.0", self.rule.convert_to_legacy("129.0.0.0/8"))

    def test_init(self):
        '''test whether parameters in init are set correctly'''

        self.assertIsNotNone(self.rule.osname)
        self.assertIsNotNone(self.rule.osmajorver)
        self.assertTrue(isinstance(self.rule.osname, str))
        self.assertTrue(isinstance(self.rule.osmajorver, str))
        self.assertIsNotNone(self.rule.ci)
        self.assertIsNotNone(self.rule.ci.getcurrvalue())
        self.assertIsNotNone(self.rule.allownetCI)
        self.assertIsNotNone(self.rule.allownetCI.getcurrvalue())

    def checkReportForRule(self, pCompliance, pRuleSuccess):
        '''check whether report was correct

        :param pCompliance: the self.iscompliant value of rule
        :param pRuleSuccess: did report run successfully
        :returns: boolean - If successful True; If failure False
        @author: ekkehard j. koch

        '''

        self.logdispatch.log(LogPriority.DEBUG, "pCompliance = " + str(pCompliance) + ".")
        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " + str(pRuleSuccess) + ".")
        success = True
        return success

    def checkFixForRule(self, pRuleSuccess):
        '''check whether fix was correct

        :param pRuleSuccess: did report run successfully
        :returns: boolean - If successful True; If failure False
        @author: ekkehard j. koch

        '''

        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " + str(pRuleSuccess) + ".")
        success = True
        return success

    def checkUndoForRule(self, pRuleSuccess):
        '''check whether undo was correct

        :param pRuleSuccess: did report run successfully
        :returns: boolean - If successful True; If failure False
        @author: ekkehard j. koch

        '''

        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " + str(pRuleSuccess) + ".")
        success = True
        return success

if __name__ == "__main__":
    unittest.main()
