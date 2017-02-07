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
from __future__ import absolute_import
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
        '''
        Reset sysctl.conf to original
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
        '''
        check on whether report was correct
        @param self: essential if you override this definition
        @param pCompliance: the self.iscompliant value of rule
        @param pRuleSuccess: did report run successfully
        @return: boolean - If successful True; If failure False
        @author: ekkehard j. koch
        '''
        self.logdispatch.log(LogPriority.DEBUG, "pCompliance = " +
                             str(pCompliance) + ".")
        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " +
                             str(pRuleSuccess) + ".")
        success = True
        return success

    def checkFixForRule(self, pRuleSuccess):
        '''
        check on whether fix was correct
        @param self: essential if you override this definition
        @param pRuleSuccess: did report run successfully
        @return: boolean - If successful True; If failure False
        @author: ekkehard j. koch
        '''
        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " +
                             str(pRuleSuccess) + ".")
        success = True
        return success

    def checkUndoForRule(self, pRuleSuccess):
        '''
        check on whether undo was correct
        @param self: essential if you override this definition
        @param pRuleSuccess: did report run successfully
        @return: boolean - If successful True; If failure False
        @author: ekkehard j. koch
        '''
        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " +
                             str(pRuleSuccess) + ".")
        success = True
        return success

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
