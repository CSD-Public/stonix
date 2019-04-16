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

Created on 11/27/2012

Perform tests on different parts of the functionality for framework CommandHelper

@author: ekkehard
@change: roy - adding sys.path.append for both test framework and individual
               test runs.
@change: Breen Malmberg - 04/11/2018 - added class doc string; removed
        testinvalidcommand test since it was just essentially testing whether
        python threw a typeerror exception when given an argument that was the wrong type
        (it wasn't testing our framework - it was testing python itself)
@todo: fill out all remaining empty method doc strings
@note: If you're going to write assertRaises tests, make sure that you are not
        catching them somewhere else in the call chain and throwing them as exceptions
        (tracebacks) there, before it can come back to the assertRaise() method call, here.
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
    '''
    Perform tests on different parts of the functionality for framework CommandHelper

    @param unittest.TestCase: unittest TestCase class inheritance object reference
    @author: ekkehard
    @change: Breen Malmberg - 04/11/2018 - removed assertion tests -
                you can't test for exception assertions in code that is wrapped by try
                except because the try except intercepts the exception and throws it
                and it never gets back to the assertraises call (see tf ticket for documentation)
    '''

    def setUp(self):
        '''
        '''

        self.enviro = Environment()
        self.enviro.setdebugmode(True)
        self.logger = LogDispatcher(self.enviro)
        self.commandhelper = CommandHelper(self.logger)

    def tearDown(self):
        '''
        '''

        pass

    def testExecuteValidCommand(self):
        '''
        '''

        self.assertTrue(self.commandhelper.executeCommand("ls -l /"),
                        "Execute Valid Command string Failed!")

        self.assertTrue(self.commandhelper.executeCommand(["ls", "-l", "/"]),
                        "Execute Valid Command List Failed!")

    def testSetLogPriority(self):
        '''
        '''

        self.assertTrue(self.commandhelper.setLogPriority(LogPriority.INFO),
                        "Execute setLogPriority(0) Command string Failed!")

        self.assertTrue(self.commandhelper.executeCommand(["ls", "-l", "/"]),
                        "Execute commandhelper.executeCommand(['ls','-l','/'])"
                        + " Command List Failed!")

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
