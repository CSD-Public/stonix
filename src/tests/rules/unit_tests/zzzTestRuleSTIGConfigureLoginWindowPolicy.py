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
This is a unit test for rule STIGConfigureLoginWindowPolicy
Created on Jun 6, 2017

@author: dwalker
'''

import unittest
import sys
sys.path.append("../../../..")
from src.tests.lib.RuleTestTemplate import RuleTest
from src.stonix_resources.CommandHelper import CommandHelper
from src.tests.lib.logdispatcher_mock import LogPriority
from src.stonix_resources.rules.STIGConfigureLoginWindowPolicy import STIGConfigureLoginWindowPolicy
from re import search

class zzzTestRuleSTIGConfigureLoginWindowPolicy(RuleTest):
    
    def setUp(self):
        RuleTest.setUp(self)
        self.rule = STIGConfigureLoginWindowPolicy(self.config,
                               self.environ,
                               self.logdispatch,
                               self.statechglogger)
        self.rulename = self.rule.rulename
        self.rulenumber = self.rule.rulenumber
        self.ch = CommandHelper(self.logdispatch)
        self.identifier = "mil.disa.STIG.loginwindow.alacarte"
        if search("10\.10.*", self.environ.getosver()):
            self.rule.profile = "/Users/vagrant/stonix/src/stonix_resources/files/" + \
                         "U_Apple_OS_X_10-10_Workstation_V1R2_STIG_Login_Window_Policy.mobileconfig"
        elif search("10\.11\.*", self.environ.getosver()):
            self.rule.profile = "/Users/vagrant/stonix/src/stonix_resources/files/" + \
                         "U_Apple_OS_X_10-11_V1R1_STIG_Login_Window_Policy.mobileconfig"
        else:
            self.rule.profile = "/Users/vagrant/stonix/src/stonix_resources/files/" + \
                         "U_Apple_macOS_10-12_V1R1_STIG_Login_Window_Policy.mobileconfig"
    def tearDown(self):
        pass

    def runTest(self):
        self.simpleRuleTest()

    def setConditionsForRule(self):
        success = True
        self.detailedresults = ""
        cmd = ["/usr/bin/profiles", "-P"]
        if not self.ch.executeCommand(cmd):
            success = False
            self.detailedresults += "Unable to run profiles command\n"
        else:
            output = self.ch.getOutput()
            if output:
                for line in output:
                    if search("mil\.disa\.STIG\.loginwindow\.alacarte$", line.strip()):
                        cmd = ["/usr/bin/profiles", "-R", "-p", self.identifier]
                        if not self.ch.executeCommand(cmd):
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
    # import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
