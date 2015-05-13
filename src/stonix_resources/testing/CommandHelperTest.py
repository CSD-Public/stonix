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
'''
from __future__ import absolute_import
import unittest
import os
import time
from ..environment import Environment
from ..logdispatcher import LogDispatcher
from ..CommandHelper import CommandHelper
from ..logdispatcher import LogPriority


class Test(unittest.TestCase):

    def setUp(self):
        self.enviro = Environment()
        self.enviro.setdebugmode(True)
        self.logger = LogDispatcher(self.enviro)
        self.commandhelper = CommandHelper(self.logger)

    def tearDown(self):
        pass

    def testBlankCommand(self):
        self.failUnlessEqual(self.commandhelper.setCommand(""), True,
                              "Setting Blank Command List Failed")

        self.failUnlessEqual(self.commandhelper.executeCommand(), False,
                              "Setting Blank Command List Failed")

        self.failUnlessEqual(self.commandhelper.executeCommand(""), False,
                              "Setting Blank Command List Failed")

        self.failUnlessEqual(self.commandhelper.setCommand([]), True,
                              "Setting Blank Command List Failed")

        self.failUnlessEqual(self.commandhelper.executeCommand(), False,
                              "Setting Blank Command List Failed")

        self.failUnlessEqual(self.commandhelper.executeCommand([]), False,
                              "Setting Blank Command List Failed")

    def testExecuteValidCommand(self):
        self.failUnlessEqual(self.commandhelper.executeCommand("ls -l /"), True,
                             "Execute Valid Command string Failed!")

        self.failUnlessEqual(self.commandhelper.executeCommand(["ls","-l","/"]), True,
                             "Execute Valid Command List Failed!")

    def testExecuteInvalidCommand(self):
        self.failUnlessEqual(self.commandhelper.executeCommand(0), False,
                             "Execute test commandhelper.executeCommand(0) Failed!")

        self.failUnlessEqual(self.commandhelper.executeCommand(['ls',0,'/']), False,
                             "Execute test commandhelper.executeCommand(['ls',0,'/']) Failed!")

    def testSetLogPriority(self):
        self.failUnlessEqual(self.commandhelper.setLogPriority(0), False,
                             "Execute setLogPriority(0) Command string Failed!")

        self.failUnlessEqual(self.commandhelper.setLogPriority(LogPriority.INFO), True,
                             "Execute setLogPriority(0) Command string Failed!")

        self.failUnlessEqual(self.commandhelper.executeCommand(["ls","-l","/"]), True,
                             "Execute commandhelper.executeCommand(['ls','-l','/']) Command List Failed!")

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()