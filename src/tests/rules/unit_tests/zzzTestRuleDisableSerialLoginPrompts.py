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


'''
This is a Unit Test for Rule DisableSerialLoginPrompts

@author: Eric Ball
@change: 2015/08/03 eball Original Implementation
@change: 2016/02/10 roy Added sys.path.append for being able to unit test this
                        file as well as with the test harness.
'''

import unittest
import os
import sys
import traceback

sys.path.append("../../../..")
from src.tests.lib.RuleTestTemplate import RuleTest
from src.tests.lib.logdispatcher_mock import LogPriority
from src.stonix_resources.stonixutilityfunctions import createFile, writeFile
from src.stonix_resources.rules.DisableSerialLoginPrompts import DisableSerialLoginPrompts


class zzzTestRuleDisableSerialLoginPrompts(RuleTest):

    def setUp(self):
        RuleTest.setUp(self)
        self.rule = DisableSerialLoginPrompts(self.config, self.environ,
                                              self.logdispatch,
                                              self.statechglogger)
        self.rulename = self.rule.rulename
        self.rulenumber = self.rule.rulenumber

    def tearDown(self):
        if os.path.exists(self.tmppath):
            try:
                os.rename(self.tmppath, self.path)
            except Exception:
                self.logdispatch.log(LogPriority.ERROR, traceback.format_exc())

    def runTest(self):
        self.simpleRuleTest()

    def setConditionsForRule(self):
        '''Configure system for the unit test

        :param self: essential if you override this definition
        :returns: boolean - If successful True; If failure False
        @author: Eric Ball

        '''
        success = True
        self.path = "/etc/securetty"
        self.tmppath = self.path + ".utmp"
        sttyText = '''vc/1
vc/2
vc/3
vc/4
vc/5
vc/6
tty1
tty2
tty3
tty4
tty5
tty6
console
ttyS0
ttyS1
'''
        if os.path.exists(self.path):
            try:
                os.rename(self.path, self.tmppath)
            except Exception:
                success = False
                self.logdispatch.log(LogPriority.ERROR, traceback.format_exc())
        if not createFile(self.path, self.logdispatch):
            success = False
        if not writeFile(self.path, sttyText, self.logdispatch):
            success = False

        return success

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
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
