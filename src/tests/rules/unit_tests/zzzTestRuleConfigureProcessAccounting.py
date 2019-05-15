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


"""
This is a Unit Test for Rule ConfigureProcessAccounting

@author: Eric Ball
@change: 2016/04/19 Eric Ball Original Implementation
@change: 2016/08/02 Eric Ball Added debug statements to the beginning of tests to
        make debug output more useful
@change: 2017/10/23 Roy Nielsen - change to new service helper interface
"""

from __future__ import absolute_import

import unittest
import sys

sys.path.append("../../../..")
from src.tests.lib.RuleTestTemplate import RuleTest
from src.tests.lib.logdispatcher_mock import LogPriority
from src.stonix_resources.pkghelper import Pkghelper
from src.stonix_resources.ServiceHelper import ServiceHelper
from src.stonix_resources.rules.ConfigureProcessAccounting import ConfigureProcessAccounting


class zzzTestRuleConfigureProcessAccounting(RuleTest):

    def setUp(self):
        ''' '''

        RuleTest.setUp(self)
        self.rule = ConfigureProcessAccounting(self.config, self.environ,
                                               self.logdispatch,
                                               self.statechglogger)
        self.rulename = self.rule.rulename
        self.rulenumber = self.rule.rulenumber

    def setConditionsForRule(self):
        '''Configure system for the unit test


        :returns: boolean - If successful True; If failure False

        '''

        success = True
        return success

    def tearDown(self):
        ''' '''

        self.rule.ci.updatecurrvalue(True)

    def runTest(self):
        ''' '''

        self.simpleRuleTest()

    def test_pkg_report(self):
        ''' '''

        self.rule.packages = []

        self.assertFalse(self.rule.report())

    def test_pkg_fix(self):
        ''' '''

        self.rule.packages = []

        self.assertFalse(self.rule.fix())
        self.assertEqual(self.rule.iditerator, 0)

    def test_ci(self):
        ''' '''

        self.assertNotEqual(self.rule.ci, None)
        self.assertNotEqual(self.rule.ci.getcurrvalue(), None)

        self.rule.ci.updatecurrvalue(False)

        self.assertFalse(self.rule.fix())
        self.assertEqual(self.rule.iditerator, 0)

    def test_init(self):
        ''' '''

        self.assertIsNotNone(self.rule.ph)
        self.assertIsNotNone(self.rule.sh)
        self.assertEqual(self.rule.rulename, "ConfigureProcessAccounting")
        self.assertEqual(self.rule.rulenumber, 97)

    def checkReportForRule(self, pCompliance, pRuleSuccess):
        '''check on whether report was correct

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
        '''check on whether fix was correct

        :param pRuleSuccess: did report run successfully
        :returns: boolean - If successful True; If failure False
        @author: ekkehard j. koch

        '''

        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " + str(pRuleSuccess) + ".")
        success = True
        return success

    def checkUndoForRule(self, pRuleSuccess):
        '''check on whether undo was correct

        :param pRuleSuccess: did report run successfully
        :returns: boolean - If successful True; If failure False
        @author: ekkehard j. koch

        '''

        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " + str(pRuleSuccess) + ".")
        success = True
        return success

if __name__ == "__main__":
    unittest.main()
