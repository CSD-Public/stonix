#!/usr/bin/env python
###############################################################################
#                                                                             #
# Copyright 2015-2019.  Los Alamos National Security, LLC. This material was       #
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
This is a Unit Test for Rule DisablePrelinking

@author: Eric Ball
@change: 2016/02/10 eball Original implementation
'''
from __future__ import absolute_import
import os
import re
import unittest
from src.stonix_resources.CommandHelper import CommandHelper
from src.stonix_resources.KVEditorStonix import KVEditorStonix
from src.stonix_resources.pkghelper import Pkghelper
from src.stonix_resources.rules.DisablePrelinking import DisablePrelinking
from src.stonix_resources.stonixutilityfunctions import writeFile
from src.tests.lib.logdispatcher_mock import LogPriority
from src.tests.lib.RuleTestTemplate import RuleTest


class zzzTestRuleDisablePrelinking(RuleTest):

    def setUp(self):
        RuleTest.setUp(self)
        self.rule = DisablePrelinking(self.config,
                                      self.environ,
                                      self.logdispatch,
                                      self.statechglogger)
        self.rulename = self.rule.rulename
        self.rulenumber = self.rule.rulenumber
        self.ch = CommandHelper(self.logdispatch)
        self.ph = Pkghelper(self.logdispatch, self.environ)
        self.prelinkInstalled = False

    def tearDown(self):
        if not self.prelinkInstalled:
            self.ph.remove("prelink")

    def runTest(self):
        self.simpleRuleTest()

    def setConditionsForRule(self):
        '''
        Configure system for the unit test
        @param self: essential if you override this definition
        @return: boolean - If successful True; If failure False
        @author: ekkehard j. koch
        '''
        success = True
        if self.ph.check("prelink"):
            self.prelinkInstalled = True
        elif self.ph.checkAvailable("prelink"):
            self.ph.install("prelink")
        else:
            return True
        path = "/usr/sbin/prelink"
        cmd = [path, "/bin/ls"]
        if os.path.exists(path):
            self.ch.executeCommand(cmd)

        if re.search("debian|ubuntu", self.environ.getostype().lower()):
            path = "/etc/default/prelink"
        else:
            path = "/etc/sysconfig/prelink"
        if os.path.exists(path):
            tmppath = path + ".tmp"
            data = {"PRELINKING": "yes"}
            self.editor = KVEditorStonix(self.statechglogger, self.logdispatch,
                                         "conf", path, tmppath,
                                         data, "present", "closedeq")
            if not self.editor.report():
                if self.editor.fix():
                    if not self.editor.commit():
                        success = False
                        self.logdispatch.log(LogPriority.ERROR,
                                             "KVEditor failed to commit.")
                else:
                    success = False
                    self.logdispatch.log(LogPriority.ERROR,
                                         "KVEditor failed to fix.")
        else:
            writeFile(path, "PRELINKING=yes", self.logdispatch)

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
