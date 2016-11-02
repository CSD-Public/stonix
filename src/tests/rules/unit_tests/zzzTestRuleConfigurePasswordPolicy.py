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
Created on Jun 9, 2015

@author: dwalker
@change: 2016/02/10 roy Added sys.path.append for being able to unit test this
                        file as well as with the test harness.
@change: 2016/04/06 eball Updated name to ConfigureProfileManagement
@change: 2016/11/02 eball Updated name to ConfigurePasswordPolicy
'''
from __future__ import absolute_import
import unittest
import sys, os

sys.path.append("../../../..")
from src.tests.lib.RuleTestTemplate import RuleTest
from src.tests.lib.logdispatcher_mock import LogPriority
from src.stonix_resources.rules.ConfigurePasswordPolicy import ConfigurePasswordPolicy
from src.stonix_resources.CommandHelper import CommandHelper
from src.stonix_resources.KVEditorStonix import KVEditorStonix


class zzzTestRuleConfigurePasswordPolicy(RuleTest):

    def setUp(self):
        RuleTest.setUp(self)
        self.rule = ConfigurePasswordPolicy(self.config, self.environ,
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
        '''
        @author: dwalker
        @note: This unit test will install two incorrect profiles on purpose
            to force system non-compliancy
        '''
        success = True
        goodprofiles = {}
        pwprofile = os.path.abspath(os.path.join(os.path.dirname(sys.argv[0]))) + \
                   "/src/stonix_resources/files/stonix4macPasscodeProfileFor" + \
                   "OSXElCapitan10.11.mobileconfig"
        secprofile = os.path.abspath(os.path.join(os.path.dirname(sys.argv[0]))) + \
                   "/src/stonix_resources/files/stonix4macSecurity&Privacy" + \
                   "ForOSXElcapitan10.11.mobileconfig"
        pwprofiledict = {"com.apple.mobiledevice.passwordpolicy":
                              {"allowSimple": ["1", "bool"],
                               "forcePIN": ["1", "bool"],
                               "maxFailedAttempts": ["5", "int", "less"],
                               "maxPINAgeInDays": ["180", "int", "more"],
                               "minComplexChars": ["1", "int", "more"],
                               "minLength": ["8", "int", "more"],
                               "minutesUntilFailedLoginReset":
                               ["15", "int", "more"],
                               "pinHistory": ["5", "int", "more"],
                               "requireAlphanumeric": ["1", "bool"]}}
        spprofiledict = {"com.apple.screensaver": "",
                              "com.apple.loginwindow": "",
                              "com.apple.systempolicy.managed": "",
                              "com.apple.SubmitDiagInfo": "",
                              "com.apple.preference.security": "",
                              "com.apple.MCX": "",
                              "com.apple.applicationaccess": "",
                              "com.apple.systempolicy.control": ""}
        self.rule.pwprofile = pwprofile
        self.rule.secprofile = secprofile
        goodprofiles[pwprofile] = pwprofiledict
        goodprofiles[secprofile] = spprofiledict 
        cmd = ["/usr/sbin/system_profiler", "SPConfigurationProfileDataType"]
        if self.ch.executeCommand(cmd):
            output = self.ch.getOutput()
            if output:
                for item, values in goodprofiles.iteritems():
                    self.editor = KVEditorStonix(self.statechglogger,
                                                  self.logdispatch, "profiles", "",
                                                  "", values, "", "", output)
                    if self.editor.report():
                        cmd = ["/usr/bin/profiles", "-R", "-F", item]
                        if not self.ch.executeCommand(cmd):
                            success = False
                        else:
                            cmd = ["/usr/bin/profiles", "-I", "-F,", item + "fake"]
                            if not self.ch.executeCommand(cmd):
                                success = False
        else:
            success = False
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
