#!/usr/bin/env python
###############################################################################
#                                                                             #
# Copyright 2015-2019.  Los Alamos National Security, LLC. This material was  #
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
        """

        @return:
        """

        RuleTest.setUp(self)
        self.rule = ConfigureProcessAccounting(self.config, self.environ,
                                               self.logdispatch,
                                               self.statechglogger)
        self.rulename = self.rule.rulename
        self.rulenumber = self.rule.rulenumber

    def setConditionsForRule(self):
        """
        Configure system for the unit test

        @return: boolean - If successful True; If failure False
        """

        success = True
        return success

    def tearDown(self):
        """

        @return: 
        """

        self.rule.ci.updatecurrvalue(True)

    def runTest(self):
        """

        @return:
        """

        self.simpleRuleTest()

    def test_pkg_report(self):
        """

        @return:
        """

        self.rule.packages = []

        self.assertFalse(self.rule.report())

    def test_pkg_fix(self):
        """

        @return:
        """

        self.rule.packages = []

        self.assertFalse(self.rule.fix())
        self.assertEqual(self.rule.iditerator, 0)

    def test_ci(self):
        """

        @return:
        """

        self.assertNotEqual(self.rule.ci, None)
        self.assertNotEqual(self.rule.ci.getcurrvalue(), None)

        self.rule.ci.updatecurrvalue(False)

        self.assertFalse(self.rule.fix())
        self.assertEqual(self.rule.iditerator, 0)

    def test_init(self):
        """

        @return:
        """

        self.assertIsNotNone(self.rule.ph)
        self.assertIsNotNone(self.rule.sh)
        self.assertEqual(self.rule.rulename, "ConfigureProcessAccounting")
        self.assertEqual(self.rule.rulenumber, 97)

    def checkReportForRule(self, pCompliance, pRuleSuccess):
        """
        check on whether report was correct

        @param pCompliance: the self.iscompliant value of rule
        @param pRuleSuccess: did report run successfully
        @return: boolean - If successful True; If failure False
        @author: ekkehard j. koch
        """

        self.logdispatch.log(LogPriority.DEBUG, "pCompliance = " + str(pCompliance) + ".")
        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " + str(pRuleSuccess) + ".")
        success = True
        return success

    def checkFixForRule(self, pRuleSuccess):
        """
        check on whether fix was correct

        @param pRuleSuccess: did report run successfully
        @return: boolean - If successful True; If failure False
        @author: ekkehard j. koch
        """

        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " + str(pRuleSuccess) + ".")
        success = True
        return success

    def checkUndoForRule(self, pRuleSuccess):
        """
        check on whether undo was correct

        @param pRuleSuccess: did report run successfully
        @return: boolean - If successful True; If failure False
        @author: ekkehard j. koch
        """

        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " + str(pRuleSuccess) + ".")
        success = True
        return success

if __name__ == "__main__":
    unittest.main()
