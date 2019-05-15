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
Created on Mar 2, 2015

@author: dwalker
@change: 2016/02/10 roy Added sys.path.append for being able to unit test this
                        file as well as with the test harness.
'''
from __future__ import absolute_import
import unittest
import sys

sys.path.append("../../../..")
from src.tests.lib.RuleTestTemplate import RuleTest
from src.stonix_resources.CommandHelper import CommandHelper
from src.tests.lib.logdispatcher_mock import LogPriority
from src.stonix_resources.rules.EncryptSwap import EncryptSwap

class zzzTestRuleEncryptSwap(RuleTest):

    def setUp(self):
        RuleTest.setUp(self)
        self.rule = EncryptSwap(self.config,
                                  self.environ,
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
        '''This method runs the following command to make sure system is in a
        non compliant state before rule runs:
        sudo defaults write /Library/Preferences/com.apple.virtualMemory
        UseEncryptedSwap -bool no
        @author: dwalker


        :returns: bool - True if successful, False if not

        '''
        cmd = ["/usr/bin/defaults", "write", 
               "/Library/Preferences/com.apple.virtualMemory", "-bool", "no"]
        if self.ch.executeCommand(cmd):
            return True
        else:
            return False

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
