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
Created On: 2018/07/11

This is a Unit Test for Rule DisableUbuntuDataCollection

@author: ekkehard j. koch, Breen Malmberg
'''



import sys
import unittest

sys.path.append("../../../..")

from src.tests.lib.RuleTestTemplate import RuleTest
from src.tests.lib.logdispatcher_mock import LogPriority
from src.stonix_resources.rules.DisableUbuntuDataCollection import DisableUbuntuDataCollection
from src.stonix_resources.pkghelper import Pkghelper


class zzzTestRuleDisableUbuntuDataCollection(RuleTest):

    def setUp(self):
        '''


        :returns: None
        @author: ekkehard j. koch, Breen Malmberg

        '''

        RuleTest.setUp(self)
        self.rule = DisableUbuntuDataCollection(self.config, self.environ, self.logdispatch, self.statechglogger)
        self.rulename = self.rule.rulename
        self.rulenumber = self.rule.rulenumber
        self.ph = Pkghelper(self.logdispatch, self.environ)
        self.datacollectionpkgs = ["popularity-contest", "apport", "ubuntu-report"]
        self.teardownpkgs = []

    def tearDown(self):
        '''


        :returns: None

        '''

        for pkg in self.teardownpkgs:
            self.ph.remove(pkg)
            self.teardownpkgs.remove(pkg)

    def runTest(self):
        '''


        :returns: None

        '''

        self.simpleRuleTest()

    def setConditionsForRule(self):
        '''Configure system for the unit test


        :returns: success

        :rtype: bool
@author: ekkehard j. koch, Breen Malmberg

        '''

        success = True
        self.rule.enabledCI.updatecurrvalue(True)

        for pkg in self.datacollectionpkgs:
            if not self.ph.check(pkg):
                self.ph.install(pkg)
                self.teardownpkgs.append(pkg)
        return success

    def checkReportForRule(self, pCompliance, pRuleSuccess):
        '''check on whether report was correct

        :param pCompliance: the self.iscompliant value of rule
        :param pRuleSuccess: did report run successfully
        :returns: success
        :rtype: bool
@author: ekkehard j. koch

        '''

        self.logdispatch.log(LogPriority.DEBUG, "pCompliance = " + str(pCompliance) + ".")
        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " + str(pRuleSuccess) + ".")
        success = True
        return success

    def checkFixForRule(self, pRuleSuccess):
        '''check on whether fix was correct

        :param pRuleSuccess: did report run successfully
        :returns: success
        :rtype: bool
@author: ekkehard j. koch

        '''

        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " + str(pRuleSuccess) + ".")
        success = True
        return success

    def checkUndoForRule(self, pRuleSuccess):
        '''check on whether undo was correct

        :param pRuleSuccess: did report run successfully
        :returns: success
        :rtype: bool
@author: ekkehard j. koch

        '''

        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " + str(pRuleSuccess) + ".")
        success = True
        return success

if __name__ == "__main__":
    unittest.main()
