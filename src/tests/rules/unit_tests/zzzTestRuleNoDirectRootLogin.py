#!/usr/bin/env python
###############################################################################
#                                                                             #
# Copyright 2015-2018.  Los Alamos National Security, LLC. This material was       #
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
Created on Dec 13, 2018
This is a Unit Test for Rule NoDirectRootLogin

@author: Brandon R. Gonzales

'''
from __future__ import absolute_import
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
        '''
        Configure system to fail before the unit test
        @param self: essential if you override this definition
        @return: boolean - If successful True; If failure False
        @author: Brandon R. Gonzales
        '''
        success = True
        if os.path.exists(self.securettypath):
            cmd = ["rm", self.securettypath]
            self.ch.executeCommand(cmd)
        return success


if __name__ == "__main__":
    unittest.main()
