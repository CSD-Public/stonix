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
Created on Dec 13, 2018
This is a Unit Test for Rule NoDirectRootLogin

@author: Brandon R. Gonzales

'''

import unittest
import sys
import os

sys.path.append("../../../..")
from src.tests.lib.RuleTestTemplate import RuleTest
from src.stonix_resources.CommandHelper import CommandHelper
from src.stonix_resources.rules.NoDirectRootLogin import NoDirectRootLogin


class zzzTestRuleNoDirectRootLogin(RuleTest):

    def setUp(self):
        RuleTest.setUp(self)
        self.rule = NoDirectRootLogin(self.config,
                                      self.environ,
                                      self.logdispatch,
                                      self.statechglogger)
        self.rulename = self.rule.rulename
        self.rulenumber = self.rule.rulenumber
        self.checkUndo = True

        self.ch = CommandHelper(self.logdispatch)
        self.securettypath = "/etc/securetty"

    def runTest(self):
        self.simpleRuleTest()

    def setConditionsForRule(self):
        '''Configure system to fail before the unit test

        :param self: essential if you override this definition
        :returns: boolean - If successful True; If failure False
        @author: Brandon R. Gonzales

        '''
        success = True
        if os.path.exists(self.securettypath):
            cmd = ["rm", self.securettypath]
            self.ch.executeCommand(cmd)
        return success


if __name__ == "__main__":
    unittest.main()
