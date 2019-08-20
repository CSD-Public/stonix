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
Created on Jun 9, 2015

@author: dwalker
@change: 2016/02/10 roy Added sys.path.append for being able to unit test this
                        file as well as with the test harness.
@change: 2016/04/06 eball Updated name to ConfigureProfileManagement
@change: 2016/11/02 eball Updated name to ConfigurePasswordPolicy
'''

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
        '''@author: dwalker
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
                for item, values in goodprofiles.items():
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
