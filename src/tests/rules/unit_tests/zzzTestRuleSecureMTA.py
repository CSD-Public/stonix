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
This is a Unit Test for Rule SecureMTA

@author: ekkehard j. koch
@change: 03/18/2013 Original Implementation
@change: 2015/12/22 eball Added tests
@change: 2016/02/10 roy Added sys.path.append for being able to unit test this
                        file as well as with the test harness.
@change: 2016/07/29 eball Changed pfTmp path to fix cross-device link errors
'''

import os
import unittest
import sys

sys.path.append("../../../..")
from src.tests.lib.RuleTestTemplate import RuleTest
from src.stonix_resources.CommandHelper import CommandHelper
from src.stonix_resources.pkghelper import Pkghelper
from src.tests.lib.logdispatcher_mock import LogPriority
from src.stonix_resources.rules.SecureMTA import SecureMTA
from src.stonix_resources.localize import MAILRELAYSERVER
from src.stonix_resources.KVEditorStonix import KVEditorStonix


class zzzTestRuleSecureMTA(RuleTest):

    def setUp(self):
        RuleTest.setUp(self)
        self.rule = SecureMTA(self.config,
                              self.environ,
                              self.logdispatch,
                              self.statechglogger)
        self.rulename = self.rule.rulename
        self.rulenumber = self.rule.rulenumber
        self.logger = self.logdispatch
        self.ch = CommandHelper(self.logdispatch)
        if self.environ.operatingsystem == "Mac OS X":
            self.isMac = True
        else:
            self.isMac = False

    def tearDown(self):
        pass
#         if not self.isMac:
#             if self.origState[0] is True and not self.ph.check("sendmail"):
#                 self.ph.install("sendmail")
#             elif self.origState[0] is False and self.ph.check("sendmail"):
#                 self.ph.remove("sendmail")
# 
#             if self.origState[1] is True and not self.ph.check(self.postfixpkg):
#                 self.ph.install(self.postfixpkg)
#             elif self.origState[1] is False and self.ph.check(self.postfixpkg):
#                 self.ph.remove(self.postfixpkg)
# 
#             if self.origState[2] is True and os.path.exists(self.smTmp):
#                 smDir = os.path.split(self.smPath)[0]
#                 if not os.path.exists(smDir):
#                     os.makedirs(smDir)
#                 os.rename(self.smTmp, self.smPath)
#             elif self.origState[2] is False and os.path.exists(self.smPath):
#                 os.remove(self.smPath)
# 
#             if self.origState[3] is True and os.path.exists(self.pfTmp):
#                 pfDir = os.path.split(self.pfPath)[0]
#                 if not os.path.exists(pfDir):
#                     os.makedirs(pfDir)
#                 os.rename(self.pfTmp, self.pfPath)
#             elif self.origState[3] is False and os.path.exists(self.pfPath):
#                 os.remove(self.pfPath)
    def runTest(self):
        self.simpleRuleTest()
    def setConditionsForRule(self):
        '''Configure system for the unit test

        :param self: essential if you override this definition
        :returns: boolean - If successful True; If failure False
        @author: dwalker

        '''
        success = True
        pfdata = {'inet_interfaces': 'localhost',
                'default_process_limit': '100',
                'smtpd_client_connection_count_limit': '10',
                'smtpd_client_connection_rate_limit': '30',
                'queue_minfree': '20971520',
                'header_size_limit': '51200',
                'message_size_limit': '10485760',
                'smtpd_recipient_limit': '100',
                'smtpd_banner': '$myhostname ESMTP',
                'mynetworks_style': 'host',
                'smtpd_recipient_restrictions':
                'permit_mynetworks, reject_unauth_destination',
                'relayhost': MAILRELAYSERVER}
        if not self.isMac:
            smdata = {"O SmtpGreetingMessage": "",
                      "O PrivacyOptions": "goaway"}
            self.ph = Pkghelper(self.logdispatch, self.environ)
            self.origState = [False, False, False, False]
            self.smPath = "/etc/mail/sendmail.cf"
            self.smTmp = self.smPath + ".stonixUT"
            self.pfPathlist = ['/etc/postfix/main.cf',
                               '/usr/lib/postfix/main.cf']
            self.postfixpkg = "postfix"
            self.pfPath = ""
            for path in self.pfPathlist:
                if os.path.exists(path):
                    self.pfPath = path
                    break
            self.pfTmp = self.pfPath + ".stonixUT"
            #if postfix file exists, remove any correct contents
            if self.pfPath:
                self.postfixed = KVEditorStonix(self.statechglogger,
                    self.logger, "conf", self.pfPath, self.pfTmp,
                    pfdata, "notpresent", "openeq")
                if not self.postfixed.report():
                    if self.postfixed.removeables:
                        print("kveditor has removeables\n")
                        if not self.postfixed.fix():
                            success = False
            if os.path.exists(self.smPath):
                self.sndmailed = KVEditorStonix(self.statechglogger, self.logger,
                    "conf", self.smPath, self.smTmp, smdata, "notpresent",
                    "closedeq")
                if not self.sndmailed.report():
                    if self.postfixed.removeables:
                        if not self.postfixed.fix():
                            success = False

            #remove postfix if installed
            if self.ph.check("postfix"):
                if not self.ph.remove("postfix"):
                    success = False
            #remove sendmail if installed
            if not self.ph.checkAvailable("postfix"):
                if self.ph.check("sendmail"):
                    if not self.ph.remove("sendmail"):
                        success = False
        else:
            self.pfPath = "/private/etc/postfix/main.cf"
            self.pfTmp = self.pfPath + ".stonixUT"
            if os.path.exists(self.pfPath):
                self.postfixed = KVEditorStonix(self.statechglogger,
                    self.logger, "conf", self.pfPath, self.pfTmp,
                    pfdata, "notpresent", "openeq")
                if not self.postfixed.report():
                    if self.postfixed.removeables:
                        if not self.postfixed.fix():
                            success = False
#             if self.ph.check("sendmail"):
#                 self.origState[0] = True
#             if self.ph.check(self.postfixpkg):
#                 self.origState[1] = True
#             if os.path.exists(self.smPath):
#                 self.origState[2] = True
#                 os.rename(self.smPath, self.smTmp)
#             if os.path.exists(self.pfPath):
#                 self.origState[3] = True
#                 os.rename(self.pfPath, self.pfTmp)
        return success
#     def testFalseFalseFalseFalse(self):
#         if not self.isMac:
#             if self.ph.check("sendmail"):
#                 self.ph.remove("sendmail")
#             if self.ph.check(self.postfixpkg):
#                 self.ph.remove(self.postfixpkg)
#             if os.path.exists(self.smPath):
#                 os.remove(self.smPath)
#             if os.path.exists(self.pfPath):
#                 os.remove(self.pfPath)
#             self.simpleRuleTest()
# 
#     def testTrueFalseFalseFalse(self):
#         if not self.isMac:
#             if not self.ph.check("sendmail"):
#                 self.ph.install("sendmail")
#             if self.ph.check(self.postfixpkg):
#                 self.ph.remove(self.postfixpkg)
#             if os.path.exists(self.smPath):
#                 os.remove(self.smPath)
#             if os.path.exists(self.pfPath):
#                 os.remove(self.pfPath)
#             self.simpleRuleTest()
# 
#     def testTrueTrueFalseFalse(self):
#         if not self.isMac:
#             if not self.ph.check("sendmail"):
#                 self.ph.install("sendmail")
#             if not self.ph.check(self.postfixpkg):
#                 self.ph.install(self.postfixpkg)
#             if os.path.exists(self.smPath):
#                 os.remove(self.smPath)
#             if os.path.exists(self.pfPath):
#                 os.remove(self.pfPath)
#             self.simpleRuleTest()
# 
#     def testTrueTrueTrueFalse(self):
#         if not self.isMac:
#             if not self.ph.check("sendmail"):
#                 self.ph.install("sendmail")
#             if not self.ph.check(self.postfixpkg):
#                 self.ph.install(self.postfixpkg)
#             if not os.path.exists(self.smPath):
#                 splitpath = self.smPath.split('/')
#                 del splitpath[-1]
#                 subdir = "/".join(splitpath)
#                 if not os.path.exists(subdir):
#                     os.makedirs(subdir, 0755)
#                 open(self.smPath, "w")
#             if os.path.exists(self.pfPath):
#                 os.remove(self.pfPath)
#             self.simpleRuleTest()
# 
#     def testTrueTrueTrueTrue(self):
#         if not self.isMac:
#             if not self.ph.check("sendmail"):
#                 self.ph.install("sendmail")
#             if not self.ph.check(self.postfixpkg):
#                 self.ph.install(self.postfixpkg)
#             if not os.path.exists(self.smPath):
#                 splitpath = self.smPath.split('/')
#                 del splitpath[-1]
#                 subdir = "/".join(splitpath)
#                 if not os.path.exists(subdir):
#                     os.makedirs(subdir, 0755)
#                 open(self.smPath, "w")
#             if not os.path.exists(self.pfPath):
#                 splitpath = self.pfPath.split('/')
#                 del splitpath[-1]
#                 subdir = "/".join(splitpath)
#                 if not os.path.exists(subdir):
#                     os.makedirs(subdir, 0755)
#                 open(self.pfPath, "w")
#             self.simpleRuleTest()
# 
#     def testTrueFalseTrueFalse(self):
#         if not self.isMac:
#             if not self.ph.check("sendmail"):
#                 self.ph.install("sendmail")
#             if self.ph.check(self.postfixpkg):
#                 self.ph.remove(self.postfixpkg)
#             if not os.path.exists(self.smPath):
#                 splitpath = self.smPath.split('/')
#                 del splitpath[-1]
#                 subdir = "/".join(splitpath)
#                 if not os.path.exists(subdir):
#                     os.makedirs(subdir, 0755)
#                 open(self.smPath, "w")
#             if os.path.exists(self.pfPath):
#                 os.remove(self.pfPath)
#             self.simpleRuleTest()
# 
#     def testFalseTrueFalseFalse(self):
#         if not self.isMac:
#             if self.ph.check("sendmail"):
#                 self.ph.remove("sendmail")
#             if not self.ph.check(self.postfixpkg):
#                 self.ph.install(self.postfixpkg)
#             if os.path.exists(self.smPath):
#                 os.remove(self.smPath)
#             if os.path.exists(self.pfPath):
#                 os.remove(self.pfPath)
#             self.simpleRuleTest()
# 
#     def testFalseTrueFalseTrue(self):
#         if not self.isMac:
#             if self.ph.check("sendmail"):
#                 self.ph.remove("sendmail")
#             if not self.ph.check(self.postfixpkg):
#                 self.ph.install(self.postfixpkg)
#             if os.path.exists(self.smPath):
#                 os.remove(self.smPath)
#             if not os.path.exists(self.pfPath):
#                 splitpath = self.pfPath.split('/')
#                 del splitpath[-1]
#                 subdir = "/".join(splitpath)
#                 if not os.path.exists(subdir):
#                     os.makedirs(subdir, 0755)
#                 open(self.pfPath, "w")
#             self.simpleRuleTest()

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
