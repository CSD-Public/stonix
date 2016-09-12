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
This is a Unit Test for Rule LinuxPackageSigning

@author: Breen Malmberg
@change: 2016/04/11 original implementation
@change: 2016/09/12 eball Added else statement in init to ensure self.backup
    always exists, plus debug statements to test methods, added checkUndo
'''

from __future__ import absolute_import
import sys
import unittest
from shutil import copyfile
import os
import re

sys.path.append("../../../..")
from src.tests.lib.RuleTestTemplate import RuleTest
from src.tests.lib.logdispatcher_mock import LogPriority
from src.stonix_resources.rules.LinuxPackageSigning import LinuxPackageSigning


class zzzTestRuleLinuxPackageSigning(RuleTest):

    def setUp(self):
        RuleTest.setUp(self)
        self.rule = LinuxPackageSigning(self.config,
                                        self.environ,
                                        self.logdispatch,
                                        self.statechglogger)
        self.rulename = self.rule.rulename
        self.rulenumber = self.rule.rulenumber
        self.checkUndo = True

        self.rule.localize()

        self.confpath = self.rule.path
        if os.path.exists(self.confpath):
            self.backup = self.confpath + ".stonixtesttemp"
            copyfile(self.confpath, self.backup)
        else:
            self.backup = ""

    def tearDown(self):
        if os.path.exists(self.backup):
            copyfile(self.backup, self.confpath)
            os.remove(self.backup)

    def setConditionsForRule(self):
        '''
        Configure system for the unit test
        @param self: essential if you override this definition
        @return: boolean - If successful True; If failure False
        @author: ekkehard j. koch
        '''

        success = True
        return success

    def test_default(self):
        '''
        '''

        self.simpleRuleTest()

    def test_gpgoff(self):
        '''
        '''
        self.logdispatch.log(LogPriority.DEBUG, "Running test_gpgoff")
        found = 0

        if not self.rule.suse:

            f = open(self.confpath, "r")
            contentlines = f.readlines()
            f.close()

            for line in contentlines:
                if re.search("gpgcheck", line):
                    contentlines = [c.replace(line, "gpgcheck=0\n")
                                    for c in contentlines]
                    found = 1

            if not found:
                contentlines.append("gpgcheck=0\n")
            f = open(self.confpath, "w")
            f.writelines(contentlines)
            f.close()

            self.simpleRuleTest()

    def test_gpgmissing(self):
        '''
        '''
        self.logdispatch.log(LogPriority.DEBUG, "Running test_gpgmissing")

        if not self.rule.suse:

            f = open(self.confpath, "r")
            contentlines = f.readlines()
            f.close()

            for line in contentlines:
                if re.search("gpgcheck", line):
                    contentlines = [c.replace(line, "\n") for c in contentlines]

            f = open(self.confpath, "w")
            f.writelines(contentlines)
            f.close()

            self.simpleRuleTest()

    def test_gpgon(self):
        '''
        '''
        self.logdispatch.log(LogPriority.DEBUG, "Running test_gpgon")

        found = 0

        if not self.rule.suse:

            f = open(self.confpath, "r")
            contentlines = f.readlines()
            f.close()

            for line in contentlines:
                if re.search("gpgcheck", line):
                    contentlines = [c.replace(line, "gpgcheck=1\n")
                                    for c in contentlines]
                    found = 1

            if not found:
                contentlines.append("gpgcheck=1\n")
            f = open(self.confpath, "w")
            f.writelines(contentlines)
            f.close()

            self.simpleRuleTest()

    def test_gpggarbage(self):
        '''
        '''
        self.logdispatch.log(LogPriority.DEBUG, "Running test_gpggarbage")

        found = 0

        if not self.rule.suse:

            f = open(self.confpath, "r")
            contentlines = f.readlines()
            f.close()

            for line in contentlines:
                if re.search("gpgcheck", line):
                    contentlines = [c.replace(line, "gpgcheck=ab234\n")
                                    for c in contentlines]
                    found = 1

            if not found:
                contentlines.append("gpgcheck=1ab234\n")
            f = open(self.confpath, "w")
            f.writelines(contentlines)
            f.close()

            self.simpleRuleTest()

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
    unittest.main()
