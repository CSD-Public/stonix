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
This is a Unit Test for Rule ConfigureAppleSoftwareUpdate

@author: Brandon R. Gonzales
@change: 2018/12/12 - Original implementation
'''

import sys
import unittest
import os
import pwd

sys.path.append("../../../..")
from src.tests.lib.RuleTestTemplate import RuleTest
from src.stonix_resources.CommandHelper import CommandHelper
from src.stonix_resources.rules.ShowBluetoothIcon import ShowBluetoothIcon

class zzzTestRuleShowBluetoothIcon(RuleTest):

    def setUp(self):
        RuleTest.setUp(self)
        self.rule = ShowBluetoothIcon(self.config,
                                      self.environ,
                                      self.logdispatch,
                                      self.statechglogger)
        self.rulename = self.rule.rulename
        self.rulenumber = self.rule.rulenumber
        self.setCheckUndo(True)
        self.ch = CommandHelper(self.logdispatch)
        self.dc = "/usr/bin/defaults"

    def runTest(self):
        # This rule is only intended to be ran in user mode
        if self.environ.geteuid() != 0:
            self.simpleRuleTest()

    def setConditionsForRule(self):
        '''This makes sure the initial report fails by executing the following
        command:
        defaults -currentHost delete /Users/(username)/Library/Preferences/com.apple.systemuiserver menuExtras

        :param self: essential if you override this definition
        :returns: boolean - If successful True; If failure False
        @author: Brandon R. Gonzales

        '''
        success = True
        if success:
            user = pwd.getpwuid(os.getuid())[0]
            self.systemuiserver = "/Users/" + user + "/Library/Preferences/com.apple.systemuiserver"
            if os.path.exists(self.systemuiserver):
                command = [self.dc, "-currentHost", "delete", self.systemuiserver, "menuExtras"]
                success = self.ch.executeCommand(command)
        if success:
            success = self.checkReportForRule(False, True)
        return success

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
