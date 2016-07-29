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
This is a Unit Test for Rule SecureMTA

@author: ekkehard j. koch
@change: 03/18/2013 Original Implementation
@change: 2015/12/22 eball Added tests
@change: 2016/02/10 roy Added sys.path.append for being able to unit test this
                        file as well as with the test harness.
@change: 2016/07/29 eball Changed pfTmp path to fix cross-device link errors
'''
from __future__ import absolute_import
import os
import unittest
import sys

sys.path.append("../../../..")
from src.tests.lib.RuleTestTemplate import RuleTest
from src.stonix_resources.CommandHelper import CommandHelper
from src.stonix_resources.pkghelper import Pkghelper
from src.tests.lib.logdispatcher_mock import LogPriority
from src.stonix_resources.rules.SecureMTA import SecureMTA


class zzzTestRuleSecureMTA(RuleTest):

    def setUp(self):
        RuleTest.setUp(self)
        self.rule = SecureMTA(self.config,
                              self.environ,
                              self.logdispatch,
                              self.statechglogger)
        self.rulename = self.rule.rulename
        self.rulenumber = self.rule.rulenumber
        self.ch = CommandHelper(self.logdispatch)
        if self.environ.operatingsystem == "Mac OS X":
            self.isMac = True
        else:
            self.isMac = False
        if not self.isMac:
            self.ph = Pkghelper(self.logdispatch, self.environ)
            self.origState = [False, False, False, False]

            self.smPath = "/etc/mail/sendmail.cf"
            self.smTmp = self.smPath + ".stonixUT"
            self.pfPathlist = ['/etc/postfix/main.cf',
                               '/private/etc/postfix/main.cf',
                               '/usr/lib/postfix/main.cf']
            pfpkgnames = ['postfix', 'squeeze', 'squeeze-backports',
                          'wheezy', 'jessie', 'sid', 'CNDpostfix', 'lucid',
                          'lucid-updates', 'lucid-backports', 'precise',
                          'precise-updates', 'quantal', 'quantal-updates',
                          'raring', 'saucy', 'wheezy-backports',
                          'postfix-current', 'trusty', 'trusty-updates',
                          'vivid', 'wily', 'xenial']
            self.postfixpkg = ""
            for pkg in pfpkgnames:
                if self.ph.check(pkg):
                    self.postfixpkg = pkg
                    break
            self.pfPath = ""
            for path in self.pfPathlist:
                if os.path.exists(path):
                    self.pfPath = path
                    break
            if self.pfPath == "":
                self.pfPath = "/etc/postfix/main.cf"
            self.pfTmp = self.pfPath + ".stonixUT"

            if self.ph.check("sendmail"):
                self.origState[0] = True
            if self.ph.check(self.postfixpkg):
                self.origState[1] = True
            if os.path.exists(self.smPath):
                self.origState[2] = True
                os.rename(self.smPath, self.smTmp)
            if os.path.exists(self.pfPath):
                self.origState[3] = True
                os.rename(self.pfPath, self.pfTmp)

    def tearDown(self):
        if not self.isMac:
            if self.origState[0] is True and not self.ph.check("sendmail"):
                self.ph.install("sendmail")
            elif self.origState[0] is False and self.ph.check("sendmail"):
                self.ph.remove("sendmail")

            if self.origState[1] is True and not self.ph.check(self.postfixpkg):
                self.ph.install(self.postfixpkg)
            elif self.origState[1] is False and self.ph.check(self.postfixpkg):
                self.ph.remove(self.postfixpkg)

            if self.origState[2] is True and os.path.exists(self.smTmp):
                smDir = os.path.split(self.smPath)[0]
                if not os.path.exists(smDir):
                    os.makedirs(smDir)
                os.rename(self.smTmp, self.smPath)
            elif self.origState[2] is False and os.path.exists(self.smPath):
                os.remove(self.smPath)

            if self.origState[3] is True and os.path.exists(self.pfTmp):
                pfDir = os.path.split(self.pfPath)[0]
                if not os.path.exists(pfDir):
                    os.makedirs(pfDir)
                os.rename(self.pfTmp, self.pfPath)
            elif self.origState[3] is False and os.path.exists(self.pfPath):
                os.remove(self.pfPath)

    def testFalseFalseFalseFalse(self):
        if not self.isMac:
            if self.ph.check("sendmail"):
                self.ph.remove("sendmail")
            if self.ph.check(self.postfixpkg):
                self.ph.remove(self.postfixpkg)
            if os.path.exists(self.smPath):
                os.remove(self.smPath)
            if os.path.exists(self.pfPath):
                os.remove(self.pfPath)
            self.simpleRuleTest()

    def testTrueFalseFalseFalse(self):
        if not self.isMac:
            if not self.ph.check("sendmail"):
                self.ph.install("sendmail")
            if self.ph.check(self.postfixpkg):
                self.ph.remove(self.postfixpkg)
            if os.path.exists(self.smPath):
                os.remove(self.smPath)
            if os.path.exists(self.pfPath):
                os.remove(self.pfPath)
            self.simpleRuleTest()

    def testTrueTrueFalseFalse(self):
        if not self.isMac:
            if not self.ph.check("sendmail"):
                self.ph.install("sendmail")
            if not self.ph.check(self.postfixpkg):
                self.ph.install(self.postfixpkg)
            if os.path.exists(self.smPath):
                os.remove(self.smPath)
            if os.path.exists(self.pfPath):
                os.remove(self.pfPath)
            self.simpleRuleTest()

    def testTrueTrueTrueFalse(self):
        if not self.isMac:
            if not self.ph.check("sendmail"):
                self.ph.install("sendmail")
            if not self.ph.check(self.postfixpkg):
                self.ph.install(self.postfixpkg)
            if not os.path.exists(self.smPath):
                splitpath = self.smPath.split('/')
                del splitpath[-1]
                subdir = "/".join(splitpath)
                if not os.path.exists(subdir):
                    os.makedirs(subdir, 0755)
                open(self.smPath, "w")
            if os.path.exists(self.pfPath):
                os.remove(self.pfPath)
            self.simpleRuleTest()

    def testTrueTrueTrueTrue(self):
        if not self.isMac:
            if not self.ph.check("sendmail"):
                self.ph.install("sendmail")
            if not self.ph.check(self.postfixpkg):
                self.ph.install(self.postfixpkg)
            if not os.path.exists(self.smPath):
                splitpath = self.smPath.split('/')
                del splitpath[-1]
                subdir = "/".join(splitpath)
                if not os.path.exists(subdir):
                    os.makedirs(subdir, 0755)
                open(self.smPath, "w")
            if not os.path.exists(self.pfPath):
                splitpath = self.pfPath.split('/')
                del splitpath[-1]
                subdir = "/".join(splitpath)
                if not os.path.exists(subdir):
                    os.makedirs(subdir, 0755)
                open(self.pfPath, "w")
            self.simpleRuleTest()

    def testTrueFalseTrueFalse(self):
        if not self.isMac:
            if not self.ph.check("sendmail"):
                self.ph.install("sendmail")
            if self.ph.check(self.postfixpkg):
                self.ph.remove(self.postfixpkg)
            if not os.path.exists(self.smPath):
                splitpath = self.smPath.split('/')
                del splitpath[-1]
                subdir = "/".join(splitpath)
                if not os.path.exists(subdir):
                    os.makedirs(subdir, 0755)
                open(self.smPath, "w")
            if os.path.exists(self.pfPath):
                os.remove(self.pfPath)
            self.simpleRuleTest()

    def testFalseTrueFalseFalse(self):
        if not self.isMac:
            if self.ph.check("sendmail"):
                self.ph.remove("sendmail")
            if not self.ph.check(self.postfixpkg):
                self.ph.install(self.postfixpkg)
            if os.path.exists(self.smPath):
                os.remove(self.smPath)
            if os.path.exists(self.pfPath):
                os.remove(self.pfPath)
            self.simpleRuleTest()

    def testFalseTrueFalseTrue(self):
        if not self.isMac:
            if self.ph.check("sendmail"):
                self.ph.remove("sendmail")
            if not self.ph.check(self.postfixpkg):
                self.ph.install(self.postfixpkg)
            if os.path.exists(self.smPath):
                os.remove(self.smPath)
            if not os.path.exists(self.pfPath):
                splitpath = self.pfPath.split('/')
                del splitpath[-1]
                subdir = "/".join(splitpath)
                if not os.path.exists(subdir):
                    os.makedirs(subdir, 0755)
                open(self.pfPath, "w")
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
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
