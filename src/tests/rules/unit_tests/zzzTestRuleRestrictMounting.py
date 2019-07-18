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
This is a Unit Test for Rule RestrictMounting

@author: Eric Ball
@change: 2015/07/07 Original Implementation
@change: 2016/02/10 roy Added sys.path.append for being able to unit test this
                        file as well as with the test harness.
@change: 2016/08/01 Eric Ball Removed testFixAndUndo, replaced with checkUndo flag.
    Also simplified setting of CIs.
@change: 2017/10/23 Roy Nielsen - change to new service helper interface
@change: 20019/04/08 Breen Malmberg - re-wrote unit tests; added to do note in rule
"""


import os
import sys
import unittest

sys.path.append("../../../..")
from src.tests.lib.RuleTestTemplate import RuleTest
from src.stonix_resources.CommandHelper import CommandHelper
from src.tests.lib.logdispatcher_mock import LogPriority
from src.stonix_resources.rules.RestrictMounting import RestrictMounting
from src.stonix_resources.pkghelper import Pkghelper
from src.stonix_resources.ServiceHelper import ServiceHelper


class zzzTestRuleRestrictMounting(RuleTest):

    def setUp(self):
        ''' '''

        RuleTest.setUp(self)
        self.rule = RestrictMounting(self.config, self.environ, self.logdispatch, self.statechglogger)
        self.rulename = self.rule.rulename
        self.rulenumber = self.rule.rulenumber
        self.ch = CommandHelper(self.logdispatch)
        self.ph = Pkghelper(self.logdispatch, self.environ)
        self.sh = ServiceHelper(self.environ, self.logdispatch)
        self.checkUndo = True
        self.serviceTarget = ""

    def tearDown(self):
        ''' '''

        pass

    def runTest(self):
        ''' '''

        self.simpleRuleTest()

    def setConditionsForRule(self):
        ''' '''

        pass

    def test_required_paths(self):
        ''' '''

        required_paths = ["/usr/bin/gsettings", "/usr/bin/gconftool-2", "/usr/bin/dbus-launch"]
        paths_exist = [p for p in required_paths if os.path.exists(p)]

        self.assertNotEqual(paths_exist, [])

    def test_rulenumber(self):
        ''' '''

        self.assertEqual(112, self.rulenumber)

    def test_rulename(self):
        ''' '''

        self.assertEqual("RestrictMounting", self.rulename)

    def test_CIs(self):
        ''' '''

        self.assertIsNotNone(self.rule.consoleCi)
        self.assertIsNotNone(self.rule.autofsCi)
        self.assertIsNotNone(self.rule.gnomeCi)

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
    unittest.main()
