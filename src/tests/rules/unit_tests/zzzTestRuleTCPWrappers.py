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
"""
This is a Unit Test for Rule TCPWrappers

@author: ekkehard j. koch
@change: 03/18/2013 Original Implementation
@change: 2016/02/10 roy Added sys.path.append for being able to unit test this
                        file as well as with the test harness.
"""

from __future__ import absolute_import
import unittest
import sys

sys.path.append("../../../..")
from src.tests.lib.RuleTestTemplate import RuleTest
from src.tests.lib.logdispatcher_mock import LogPriority
from src.stonix_resources.rules.TCPWrappers import TCPWrappers


class zzzTestRuleTCPWrappers(RuleTest):

    def setUp(self):
        """

        @return: 
        """

        RuleTest.setUp(self)
        self.rule = TCPWrappers(self.config, self.environ, self.logdispatch, self.statechglogger)
        self.rulename = self.rule.rulename
        self.rulenumber = self.rule.rulenumber

    def tearDown(self):
        """

        @return: 
        """

        pass

    def runTest(self):
        """

        @return: 
        """

        self.simpleRuleTest()

    def setConditionsForRule(self):
        """
        Configure system for the unit test

        @return: boolean - If successful True; If failure False
        @author: ekkehard j. koch
        """

        success = True
        return success

    def test_convert(self):
        """
        test the convert method in tcpwrappers

        @return:
        """

        self.assertEqual("", self.rule.convert_to_legacy(""))
        self.assertEqual("name.domain", self.rule.convert_to_legacy("name.domain"))
        self.assertEqual("129.175.0.0/255.255.0.0", self.rule.convert_to_legacy("129.175.0.0/16"))
        self.assertEqual("129.175.1.0/255.255.255.0", self.rule.convert_to_legacy("129.175.1.0/24"))
        self.assertEqual("129.0.0.0/255.0.0.0", self.rule.convert_to_legacy("129.0.0.0/8"))

    def test_init(self):
        """
        test whether parameters in init are set correctly

        @return:
        """

        self.assertIsNotNone(self.rule.osname)
        self.assertIsNotNone(self.rule.osmajorver)
        self.assertTrue(isinstance(self.rule.osname, basestring))
        self.assertTrue(isinstance(self.rule.osmajorver, basestring))
        self.assertIsNotNone(self.rule.ci)
        self.assertIsNotNone(self.rule.ci.getcurrvalue())
        self.assertIsNotNone(self.rule.allownetCI)
        self.assertIsNotNone(self.rule.allownetCI.getcurrvalue())

    def checkReportForRule(self, pCompliance, pRuleSuccess):
        """
        check whether report was correct

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
        check whether fix was correct

        @param pRuleSuccess: did report run successfully
        @return: boolean - If successful True; If failure False
        @author: ekkehard j. koch
        """

        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " + str(pRuleSuccess) + ".")
        success = True
        return success

    def checkUndoForRule(self, pRuleSuccess):
        """
        check whether undo was correct

        @param pRuleSuccess: did report run successfully
        @return: boolean - If successful True; If failure False
        @author: ekkehard j. koch
        """

        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " + str(pRuleSuccess) + ".")
        success = True
        return success

if __name__ == "__main__":
    unittest.main()
