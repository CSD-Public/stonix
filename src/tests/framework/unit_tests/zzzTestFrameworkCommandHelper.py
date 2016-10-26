#!/usr/bin/env python
'''
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

Created on 11/27/2012

@author: ekkehard
@change: roy - adding sys.path.append for both test framework and individual
               test runs.
'''
from __future__ import absolute_import
import unittest
import sys

sys.path.append("../../../..")
from src.tests.lib.logdispatcher_lite import LogPriority
from src.tests.lib.logdispatcher_lite import LogDispatcher
from src.stonix_resources.environment import Environment
from src.stonix_resources.CommandHelper import CommandHelper


class zzzTestFrameworkCommandHelper(unittest.TestCase):

    def setUp(self):
        self.enviro = Environment()
        self.enviro.setdebugmode(True)
        self.logger = LogDispatcher(self.enviro)
        self.commandhelper = CommandHelper(self.logger)

    def tearDown(self):
        pass

    def testBlankCommand(self):
        self.assertRaises(ValueError, self.commandhelper.setCommand, "")

        self.assertRaises(TypeError, self.commandhelper.executeCommand, None)

        self.assertRaises(ValueError, self.commandhelper.executeCommand, "")

        self.assertRaises(ValueError, self.commandhelper.setCommand, [])

        self.assertRaises(TypeError, self.commandhelper.executeCommand, None)

        self.assertRaises(ValueError, self.commandhelper.executeCommand, [])

    def testExecuteValidCommand(self):
        self.assertTrue(self.commandhelper.executeCommand("ls -l /"),
                        "Execute Valid Command string Failed!")

        self.assertTrue(self.commandhelper.executeCommand(["ls", "-l", "/"]),
                        "Execute Valid Command List Failed!")

    def testExecuteInvalidCommand(self):
        self.assertRaises(TypeError, self.commandhelper.executeCommand, 0)

        self.assertRaises(TypeError, self.commandhelper.executeCommand,
                          ['ls', 0, '/'])

    def testSetLogPriority(self):
        self.assertRaises(TypeError, self.commandhelper.setLogPriority, 0)

        self.assertTrue(self.commandhelper.setLogPriority(LogPriority.INFO),
                        "Execute setLogPriority(0) Command string Failed!")

        self.assertTrue(self.commandhelper.executeCommand(["ls", "-l", "/"]),
                        "Execute commandhelper.executeCommand(['ls','-l','/'])"
                        + " Command List Failed!")

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
