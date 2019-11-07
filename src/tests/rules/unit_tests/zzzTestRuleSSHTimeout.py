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
This is a Unit Test for Rule SSHTimeout

@author: Eric Ball
@change: 2015/09/24 eball Original Implementation
@change: 2016/02/10 roy Added sys.path.append for being able to unit test this
                        file as well as with the test harness.
'''

import unittest
import os
import sys

sys.path.append("../../../..")
from src.tests.lib.RuleTestTemplate import RuleTest
from src.stonix_resources.CommandHelper import CommandHelper
from src.stonix_resources.KVEditorStonix import KVEditorStonix
from src.stonix_resources.stonixutilityfunctions import setPerms, iterate
from src.tests.lib.logdispatcher_mock import LogPriority
from src.stonix_resources.rules.SSHTimeout import SSHTimeout


class zzzTestRuleSSHTimeout(RuleTest):

    def setUp(self):
        RuleTest.setUp(self)
        self.rule = SSHTimeout(self.config,
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
        '''Configure system for the unit test

        :param self: essential if you override this definition
        :returns: boolean - If successful True; If failure False
        @author: Eric Ball

        '''
        success = True
        # Run report() to get variables
        self.rule.report()
        ssh = {"ClientAliveInterval": "0",
               "ClientAliveCountMax": "900"}
        if os.path.exists(self.rule.path):
            kvtype = "conf"
            intent = "present"
            self.editor = KVEditorStonix(self.statechglogger, self.logdispatch,
                                         kvtype, self.rule.path,
                                         self.rule.tpath, ssh, intent, "space")
            if not self.editor.report():
                if self.editor.fixables:
                    if self.editor.fix():
                        if not self.editor.commit():
                            success = False
                            debug = "KVEditor commit did not succeed"
                            self.logdispatch.log(LogPriority.DEBUG, debug)
                    else:
                        success = False
                        debug = "KVEditor fix() did not succeed"
                        self.logdispatch.log(LogPriority.DEBUG, debug)
            self.rule.iditerator = 0
            myid = iterate(self.rule.iditerator, self.rule.rulenumber)
            if not setPerms(self.rule.path, [99, 99, 0o770], self.logdispatch,
                            self.statechglogger, myid):
                success = False
                debug = "Could not set permissions"
                self.logdispatch.log(LogPriority.DEBUG, debug)
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
    # import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
