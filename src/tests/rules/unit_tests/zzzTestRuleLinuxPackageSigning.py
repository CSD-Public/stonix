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
This is a Unit Test for Rule LinuxPackageSigning

@author: Breen Malmberg
@change: 2016/04/11 original implementation
@change: 2016/09/12 eball Added else statement in init to ensure self.backup
    always exists, plus debug statements to test methods, added checkUndo
@change: 2018/04/09 - Breen Malmberg - changed the setUp to use a list of possible
        configuration paths/files because that's what the rule currently uses (instead
        of a single "path")
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
        ''' '''

        RuleTest.setUp(self)
        self.rule = LinuxPackageSigning(self.config,
                                        self.environ,
                                        self.logdispatch,
                                        self.statechglogger)
        self.rulename = self.rule.rulename
        self.rulenumber = self.rule.rulenumber
        self.checkUndo = True

        self.rule.localize()
        self.backup = ""
        self.confpath = ""

        self.confpaths = self.rule.repos
        for p in self.confpaths:
            if os.path.exists(p):
                self.confpath = p
                self.backup = p + ".stonixtest"
                copyfile(p, self.backup)

    def tearDown(self):
        ''' '''

        if os.path.exists(self.backup):
            copyfile(self.backup, self.confpath)
            os.remove(self.backup)

    def setConditionsForRule(self):
        '''Configure system for the unit test

        :param self: essential if you override this definition
        :returns: boolean - If successful True; If failure False
        @author: ekkehard j. koch

        '''

        success = True
        return success

    def test_default(self):
        ''' '''

        self.simpleRuleTest()

    def test_gpgoff(self):
        ''' '''

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
        ''' '''

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
        ''' '''

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
        ''' '''

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
    unittest.main()
