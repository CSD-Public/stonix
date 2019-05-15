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
Created on Feb 10, 2015

@author: root
@change: 2016/02/10 roy Added sys.path.append for being able to unit test this
                        file as well as with the test harness.
'''
from __future__ import absolute_import
import unittest
import sys

sys.path.append("../../../..")
from src.tests.lib.RuleTestTemplate import RuleTest
from src.tests.lib.logdispatcher_mock import LogPriority
from src.stonix_resources.rules.ReqPassSysPref import ReqPassSysPref
from src.stonix_resources.CommandHelper import CommandHelper

import re


class zzzTestReqPassSysPref(RuleTest):

    def setUp(self):

        RuleTest.setUp(self)
        self.rule = ReqPassSysPref(self.config,
                                self.environ,
                                self.logdispatch,
                                self.statechglogger)
        self.cmdhelper = CommandHelper(self.logdispatch)
        self.rulename = self.rule.rulename
        self.rulenumber = self.rule.rulenumber

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
        setuplist = ["system.preferences", "system.preferences.accessibility",
                     "system.preferences.accounts", "system.preferences.datetime",
                     "system.preferences.energysaver", "system.preferences.location",
                     "system.preferences.network", "system.preferences.nvram",
                     "system.preferences.parental-controls", "system.preferences.printing",
                     "system.preferences.security", "system.preferences.security.remotepair",
                     "system.preferences.sharing", "system.preferences.softwareupdate",
                     "system.preferences.startupdisk", "system.preferences.timemachine",
                     "system.preferences.version-cue"]
        plistfile = "/System/Library/Security/authorization.plist"
        plistbuddy = "/usr/libexec/PlistBuddy"

        for option in setuplist:
            self.cmdhelper.executeCommand(plistbuddy + " -c 'Set rights:" + option + ":shared 1 " + plistfile)
            errorout = self.cmdhelper.getErrorString()
            if errorout:
                if re.search("Does Not Exist", errorout):
                    self.cmdhelper.executeCommand(plistbuddy + " -c 'Add rights:" + option + ":shared bool true " + plistfile)
                    erradd = self.cmdhelper.getErrorString()
                    if erradd:
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
        self.logdispatch.log(LogPriority.DEBUG, "pCompliance = " + \
                             str(pCompliance) + ".")
        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " + \
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
        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " + \
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
        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " + \
                             str(pRuleSuccess) + ".")
        success = True
        return success


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
