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
This is a Unit Test for Rule ConfigureAppleSoftwareUpdate

@author: ekkehard j. koch
@change: 2013/02/27 Original Implementation
@change: 2016/02/10 roy Added sys.path.append for being able to unit test this
                        file as well as with the test harness.
@change: 2016/11/01 ekkehard add disable automatic macOS (OS X) updates
'''

import sys
import unittest

sys.path.append("../../../..")
from src.tests.lib.RuleTestTemplate import RuleTest
from src.stonix_resources.CommandHelper import CommandHelper
from src.tests.lib.logdispatcher_mock import LogPriority
from src.stonix_resources.rules.ConfigureAppleSoftwareUpdate import ConfigureAppleSoftwareUpdate


class zzzTestRuleConfigureAppleSoftwareUpdate(RuleTest):

    def setUp(self):
        RuleTest.setUp(self)
        self.rule = ConfigureAppleSoftwareUpdate(self.config,
                                                 self.environ,
                                                 self.logdispatch,
                                                 self.statechglogger)
        self.rulename = self.rule.rulename
        self.rulenumber = self.rule.rulenumber
        self.ch = CommandHelper(self.logdispatch)
        self.dc = "/usr/bin/defaults"

    def tearDown(self):
        pass

    def runTest(self):
        self.simpleRuleTest()

    def setConditionsForRule(self):
        '''This makes sure the intial report fails by executing the following
        commands:
        defaults -currentHost delete /Library/Preferences/com.apple.SoftwareUpdate CatalogURL
        defaults -currentHost write /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload -bool yes
        defaults -currentHost write /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled -bool yes
        defaults -currentHost write /Library/Preferences/com.apple.SoftwareUpdate ConfigDataInstall -bool yes
        defaults -currentHost write /Library/Preferences/com.apple.SoftwareUpdate DisableCriticalUpdateInstall -bool yes
        defaults -currentHost delete /Library/Preferences/com.apple.SoftwareUpdate AllowPreReleaseInstallation

        :param self: essential if you override this definition
        :returns: boolean - If successful True; If failure False
        @author: ekkehard j. koch

        '''
        success = True
        if success:
            command = [self.dc, "-currentHost", "delete",
                       "/Library/Preferences/com.apple.SoftwareUpdate",
                       "CatalogURL"]
            self.logdispatch.log(LogPriority.DEBUG, str(command))
            success = self.ch.executeCommand(command)
        if success:
            command = [self.dc, "-currentHost", "write",
                       "/Library/Preferences/com.apple.SoftwareUpdate",
                       "AutomaticDownload", "-bool", "yes"]
            self.logdispatch.log(LogPriority.DEBUG, str(command))
            success = self.ch.executeCommand(command)
        if success:
            command = [self.dc, "-currentHost", "write",
                       "/Library/Preferences/com.apple.SoftwareUpdate",
                       "AutomaticCheckEnabled", "-bool", "yes"]
            self.logdispatch.log(LogPriority.DEBUG, str(command))
            success = self.ch.executeCommand(command)
        if success:
            command = [self.dc, "-currentHost", "write",
                       "/Library/Preferences/com.apple.SoftwareUpdate",
                       "ConfigDataInstall", "-bool", "yes"]
            self.logdispatch.log(LogPriority.DEBUG, str(command))
            success = self.ch.executeCommand(command)
        if success:
            command = [self.dc, "-currentHost", "write",
                       "/Library/Preferences/com.apple.SoftwareUpdate",
                       "DisableCriticalUpdateInstall", "-bool", "yes"]
            self.logdispatch.log(LogPriority.DEBUG, str(command))
            success = self.ch.executeCommand(command)
        if success:
            command = [self.dc, "-currentHost", "delete",
                       "/Library/Preferences/com.apple.SoftwareUpdate",
                       "AllowPreReleaseInstallation"]
            self.logdispatch.log(LogPriority.DEBUG, str(command))
            success = self.ch.executeCommand(command)
        if success:
            command = [self.dc, "-currentHost", "write",
                       "/Library/Preferences/com.apple.commerce",
                       "AutoUpdateRestartRequired", "-bool", "yes"]
            self.logdispatch.log(LogPriority.DEBUG, str(command))
            success = self.ch.executeCommand(command)
        if success:
            success = self.checkReportForRule(False, True)
        return success

    def checkReportForRule(self, pCompliance, pRuleSuccess):
        '''Did the first rule report do what it was supposed to

        :param self: essential if you override this definition
        :param pCompliance: compliance of first rule report boolean
        :param pRuleSuccess: success of first report execution boolean
        :returns: boolean - If successful True; If failure False
        @author: ekkehard j. koch

        '''
        self.logdispatch.log(LogPriority.DEBUG, "pCompliance = " + \
                             str(pCompliance) + ".")
        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " + \
                             str(pRuleSuccess) + ".")
        success = True
        if pCompliance:
            success = False
            self.logdispatch.log(LogPriority.DEBUG, "pCompliance = " + \
                             str(pCompliance) + " it should be false!")
        if not pRuleSuccess:
            success = False
            self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " + \
                                 str(pRuleSuccess) + " it should be true!")
        return success

    def checkFixForRule(self, pRuleSuccess):
        '''Did the rule fix do what it was supposed to

        :param self: essential if you override this definition
        :param pRuleSuccess: success of fix execution boolean
        :returns: boolean - If successful True; If failure False
        @author: ekkehard j. koch

        '''
        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " + \
                             str(pRuleSuccess) + ".")
        success = True
        if not pRuleSuccess:
            success = False
            self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " + \
                                 str(pRuleSuccess) + " it should be true!")
        return success

    def checkReportFinalForRule(self, pCompliance, pRuleSuccess):
        '''Did the final rule report do what it was supposed to

        :param self: essential if you override this definition
        :param pCompliance: compliance of final rule report boolean
        :param pRuleSuccess: success of final report execution boolean
        :returns: boolean - If successful True; If failure False
        @author: ekkehard j. koch

        '''

        self.logdispatch.log(LogPriority.DEBUG, "pCompliance = " + \
                             str(pCompliance) + ".")
        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " + \
                             str(pRuleSuccess) + ".")
        success = True
        if not pCompliance:
            success = False
            self.logdispatch.log(LogPriority.DEBUG, "pCompliance = " + \
                             str(pCompliance) + " it should be true!")
        if not pRuleSuccess:
            success = False
            self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " + \
                                 str(pRuleSuccess) + " it should be true!")
        return success
    
    def checkUndoForRule(self, pRuleSuccess):
        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " + \
                             str(pRuleSuccess) + ".")
        if not pRuleSuccess:
            success = False
            self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " + \
                                 str(pRuleSuccess) + " it should be true!")
        return success

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
