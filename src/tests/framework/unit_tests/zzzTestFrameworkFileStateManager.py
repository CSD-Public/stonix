#!/usr/bin/python
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
"""
@created: 2017/02/28

@author: Roy Nielsen
"""
import os
import re
import sys
import ctypes
import shutil
import unittest

sys.path.append("../../../..")
from src.stonix_resources.FileStateManager import FileStateManager
from src.stonix_resources.environment import Environment
from src.stonix_resources.CommandHelper import CommandHelper
from src.tests.lib.logdispatcher_lite import LogDispatcher, LogPriority
from src.stonix_resources.get_libc import getLibc

lp = LogPriority

LIBC = getLibc()

environ = Environment()
environ.stonixversion = "1.2.3"
logger = LogDispatcher(debug_mode=True)
logger.initializeLogs("/tmp/zzzTestFrameworkFileStateManager", extension_type="time", syslog=False, myconsole=False)

class NotApplicableToThisOS(Exception):
    """
    Custom Exception
    """
    def __init__(self, *args, **kwargs):
        Exception.__init__(self, *args, **kwargs)


class zzzTestFrameworkFileStateManager(unittest.TestCase):
    """
    Class for testing the FileStateManager.
    """
    def setUp(self):
        """
        """
        #self.environ = Environment()
        #self.environ.stonixversion = "1.2.3"
        self.environ = environ
        self.logger = logger
        #self.logger = LogDispatcher(self.environ, debug_mode=True, )
        #self.logger.initializeLogs("/tmp/zzzTestFrameworkFileStateManager", extension_type="time", syslog=False, myconsole=False)
        
        self.fsm = FileStateManager(self.environ, self.logger)
        self.fsm.setPrefix("/tmp/stonixtest")
        self.fsm.setMode("filecmp")
        self.fsm.setVersion = "1.2.3"
        self.testMetaDirs = ["/tmp/stonixtest/1.2.3/stateBefore",
                             "/tmp/stonixtest/1.2.3/stateAfter",
                             "/tmp/stonixtest/1.2.4.5/stateBefore",
                             "/tmp/stonixtest/1.2.4.5/stateAfter",
                             "/tmp/stonixtest/1.6.3/stateBefore",
                             "/tmp/stonixtest/1.6.3/stateAfter",
                             "/tmp/stonixtest/2.2.3/stateBefore",
                             "/tmp/stonixtest/2.2.3/stateAfter",
                             "/tmp/stonixtest/2.8.3/stateBefore",
                             "/tmp/stonixtest/2.8.3/stateAfter",
                             "/tmp/stonixtest/1.2.2/stateBefore",
                             "/tmp/stonixtest/1.2.2/stateAfter"]

        self.testTargetDirs = ["/tmp/stonixtest/testOne",
                               "/tmp/stonixtest/testOne/testTwo",
                               "/tmp/stonixtest/testOne/testTrhee",
                               "/tmp/stonixtest/testFour"]

        for meta in self.testMetaDirs:
            for item in self.testTargetDirs:
                os.makedirs(meta + item)

        for item in self.testTargetDirs:
            os.makedirs(item)

        LIBC.sync()
        self.ch = CommandHelper(self.logger)
        self.logger.log(lp.INFO, "setUp...")
        

    ############################################################################
    
    def tearDown(self):
        """
        Make sure the appropriate files are removed..
        """
        shutil.rmtree("/tmp/stonixtest")
        LIBC.sync()
        LIBC.sync()

    ############################################################################
    
    def test_isFileInStateCheck(self):
        """
        Run methods or functionality that performs a state change on a file.
        
        subtests include:
            - before state equals after state equals target state
            - expected state change
            - unexpected, previous state, state change
            - unexpected no-match state change (expected fail)
            - missing reference state file (expected fail)
            - missing target (expected fail)
            - missing target state (expected fail)

        @author: Roy Nielsen
        """
        
        #####
        # Set up and test for expected state check
        firstTestFile = self.testTargetDirs[0] + "/test"
        
        fpBefore = open(self.testMetaDirs[0] + firstTestFile, "w")
        fpAfter = open(self.testMetaDirs[1] + firstTestFile, "w")
        fpTarget = open(firstTestFile, "w")
        
        for item in [fpBefore, fpAfter, fpTarget]:
            item.write("Hello World!")
            item.close()
            LIBC.sync()
        
        success, _ = self.fsm.isFileInStates(["stateBefore", "stateAfter"], 
                                               firstTestFile)
        
        self.logger.log(lp.DEBUG, "first test . . .")
        self.logger.log(lp.DEBUG, "Success: " + str(success))
        self.logger.log(lp.DEBUG, "      _: " + str(_))
        self.assertTrue(success, "State check failure...")
        
        LIBC.sync()
        
        #####
        # Set up and test for successful state check from a previous state
        fpPrevious = open(self.testMetaDirs[2] + firstTestFile, "w")
        fpPrevious.write("Hello World!")
        fpPrevious.close()

        fpBefore = open(self.testMetaDirs[1] + firstTestFile, "w")
        fpBefore.write("hello world")
        fpBefore.close()

        fpBefore = open(self.testMetaDirs[0] + firstTestFile, "w")
        fpBefore.write("hello world")
        fpBefore.close()

        success, _ = self.fsm.isFileInStates(["stateBefore", "stateAfter"],
                                               firstTestFile)        

        self.logger.log(lp.DEBUG, "second test . . .")
        self.logger.log(lp.DEBUG, "Success: " + str(success))
        self.logger.log(lp.DEBUG, "      _: " + str(_))
        self.assertTrue(success, "Could not aquire a refrence...")

        LIBC.sync()
        
        #####
        # Set up and test for no state match in any history (expected fail)
        firstTestFile = self.testTargetDirs[0] + "/test"

        fpPrevious = open(self.testMetaDirs[0] + "/" + self.testTargetDirs[0] + "/test", "w")
        fpPrevious.write("Hello wworld!")
        fpPrevious.close()

        #####
        # Set up and test for no state match in any history (expected fail)
        fpPrevious = open(self.testMetaDirs[2] + "/" + self.testTargetDirs[0] + "/test", "w")
        fpPrevious.write("Hello wwworld!")
        fpPrevious.close()

        LIBC.sync()

        success, _ = self.fsm.isFileInStates(["stateBefore", "stateAfter"],
                                               firstTestFile)

        self.logger.log(lp.DEBUG, "Third test . . .")
        self.logger.log(lp.DEBUG, "Success: " + str(success))
        self.logger.log(lp.DEBUG, "      _: " + str(_))
        self.assertFalse(success, "Could not aquire a refrence...")

       #####
        # Set up and test for missing reference state file (expected fail)

        LIBC.sync()

        success, _ = self.fsm.isFileInStates(["AnotherState", "stateAfter"],
                                               firstTestFile)

        self.logger.log(lp.DEBUG, "fourth test . . .")
        self.logger.log(lp.DEBUG, "Success: " + str(success))
        self.logger.log(lp.DEBUG, "      _: " + str(_))
        self.assertFalse(success, "Could not aquire a refrence...")

        #####
        # Set up and test for missing target state (expected fail)

        LIBC.sync()

        success, _ = self.fsm.isFileInStates([], firstTestFile)

        self.logger.log(lp.DEBUG, "fifth . . .")
        self.logger.log(lp.DEBUG, "Success: " + str(success))
        self.logger.log(lp.DEBUG, "      _: " + str(_))
        self.assertFalse(success, "Could not aquire a refrence...")

        #####
        # Set up and test for missing map file (expected fail)

        LIBC.sync()
    
        success, _ = self.fsm.isFileInStates(["stateBefore", "stateAfter"], "")

        self.logger.log(lp.DEBUG, "sixth test . . .")
        self.logger.log(lp.DEBUG, "Success: " + str(success))
        self.logger.log(lp.DEBUG, "      _: " + str(_))
        self.assertFalse(success, "Could not aquire a refrence...")

    ############################################################################

    def test_isSaneFilePath(self):
        """
        """
        self.assertTrue(False, "Not yet implemented")

    ############################################################################

    def test_isKnownStateMatch(self):
        """
        """
        self.assertTrue(False, "Not yet implemented")

    ############################################################################

    def test_areFilesInStates(self):
        """
        """
        self.assertTrue(False, "Not yet implemented")

    ############################################################################

    def test_buildSearchList(self):
        """
        """
        self.assertTrue(False, "Not yet implemented")

    ############################################################################

    def test_qsort(self):
        """
        """
        self.assertTrue(False, "Not yet implemented")

    ############################################################################

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
