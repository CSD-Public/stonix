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
This is a Unit Test for Rule SecureIPV4

@author: ekkehard j. koch
@change: 03/04/2013 Original Implementation
@change: 2016/02/10 roy Added sys.path.append for being able to unit test this
                        file as well as with the test harness.
@change: 2016/06/01 eball Added statechglogger to FileHelper parameters
@change: 2016/07/08 ekkehard complete renaming to SecureIPV4
@change: 2016/07/28 eball Complete renaming to SecureIPV4 (again)
'''

import unittest
import sys

sys.path.append("../../../..")
from src.tests.lib.RuleTestTemplate import RuleTest
from src.stonix_resources.filehelper import FileHelper
from src.tests.lib.logdispatcher_mock import LogPriority
from src.stonix_resources.rules.SecureIPV4 import SecureIPV4


class zzzTestRuleSecureIPV4(RuleTest):

    def setUp(self):
        RuleTest.setUp(self)
        self.rule = SecureIPV4(self.config,
                               self.environ,
                               self.logdispatch,
                               self.statechglogger)
        self.rulename = self.rule.rulename
        self.rulenumber = self.rule.rulenumber
        self.fh = FileHelper(self.logdispatch, self.statechglogger)

    def tearDown(self):
        pass

    def runTest(self):
        self.simpleRuleTest()

    def setConditionsForRule(self):
        '''Reset sysctl.conf to original
        @author: ekkehard j. koch


        '''
        success = True
        if self.environ.getosfamily() == 'darwin':
            if success:
                self.files = {"sysctl.conf": {"path": "/private/etc/sysctl.conf",
                                              "remove": True,
                                              "content": None,
                                              "permissions": None,
                                              "owner": "root",
                                              "group": "wheel"}
                              }
                for filelabel, fileinfo in sorted(self.files.items()):
                    success = self.fh.addFile(filelabel,
                                              fileinfo["path"],
                                              fileinfo["remove"],
                                              fileinfo["content"],
                                              fileinfo["permissions"],
                                              fileinfo["owner"],
                                              fileinfo["group"])
                    if not success:
                        break
            if success:
                success = self.fh.fixFiles()
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
