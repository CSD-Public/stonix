#!/usr/bin/python
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

"""
@created: 2017/02/28

@author: Roy Nielsen
"""
import os
import re
import sys
import time
import ctypes
import shutil
import filecmp
import unittest
from distutils.version import LooseVersion

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
        self.fsm.setVersion("1.2.3")
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
                try:
                    os.makedirs(meta + item)
                except OSError:
                    pass

        for item in self.testTargetDirs:
            try:
                os.makedirs(item)
            except OSError:
                pass

        LIBC.sync()
        #time.sleep(2)
        self.ch = CommandHelper(self.logger)
        self.logger.log(lp.INFO, "setUp...")

        version = "/" + environ.getstonixversion()
        osFamily = "/" + environ.getosfamily()
        osType = "/" + environ.getostype()
        osVersion = "/" + environ.getosver()
        state = osFamily + osType + osVersion + "/stateAfter"
        state = re.sub(" ", "", state)

    ############################################################################

    def tearDown(self):
        """
        Make sure the appropriate files are removed..
        """
        shutil.rmtree("/tmp/stonixtest")
        LIBC.sync()
        LIBC.sync()
        #time.sleep(2)

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
        invalidResults = []

        invalidFilePaths = ["^abc","$garbage","user@email.address.net",
                            "NotAFile!","one+one=two"]

        for item in invalidFilePaths:
            result = self.fsm.isSaneFilePath(item)
            invalidResults.append(result)

        if True in invalidResults:
            invalidCheck = False
        else:
            invalidCheck = True

        self.assertFalse(invalidCheck, "Found a valid format in the invalid path list.")

        validResults = []

        validFilePaths = ["/","/bin","/usr/local/bin",
                          ".bashrc","/tmp/test_file-v1.2.3",
                          "/home/user/.bashrc","/etc/sshd_config"]

        for item in validFilePaths:
            result = self.fsm.isSaneFilePath(item)
            validResults.append(result)

        if False in validResults:
            validCheck = False
        else:
            validCheck = True

        self.assertTrue(validCheck, "Found an invalid format in the valid path list.")

    ############################################################################

    def test_isKnownStateMatch(self):
        """
        """
        testFp = open("/tmp/test", "w")
        testFp.write("Hello World!")
        testFp.close()

        result = self.fsm.isKnownStateMatch("/tmp/test", "/tmp/test")
        self.assertTrue(result, "Files don't match...")

        os.unlink("/tmp/test")

    ############################################################################

    def test_areFilesInStates(self):
        """
        """
        success = False

        fileOne   = "/firstTestFile"
        fileTwo   = "/secondTestFile"
        fileThree = "/thirdTestFile"
        fileFour  = "/fourthTestFile"
        fileFive  = "/fifthTestFile"

        filesOrig = [self.testTargetDirs[0] + fileOne,
                     self.testTargetDirs[1] + fileTwo,
                     self.testTargetDirs[2] + fileThree,
                     self.testTargetDirs[3] + fileFour,
                     self.testTargetDirs[1] + fileFive,
                     ]
        filesTargetState = [self.testTargetDirs[0] + fileOne,
                            self.testTargetDirs[1] + fileTwo,
                            self.testTargetDirs[2] + fileThree,
                            self.testTargetDirs[3] + fileFour,
                            self.testTargetDirs[1] + fileFive,
                            ]


        for item in filesOrig:
            itemFp = open(item, "w")
            itemFp.write("Hello World!")
            itemFp.close()
            LIBC.sync()

        #####
        # Check the latest version in that stateAfter state as the "expected state"
        for item in filesTargetState:
            myfile = self.testMetaDirs[9] + item
            myfileFp = open(myfile, "w")
            myfileFp.write("Hello World!")
            myfileFp.close()
            LIBC.sync()

        states = ["stateAfter", "stateBefore"]

        success, _ = self.fsm.areFilesInStates(states, filesOrig)

        self.assertTrue(success, "Files in States check one failed...")

        #####
        # Found approved files in one of the iterative states
        for item in filesOrig:
            itemFp = open(item, "w")
            itemFp.write("hello world!")
            itemFp.close()
            LIBC.sync()

        filesStateOne = [self.testTargetDirs[0] + fileOne,
                         self.testTargetDirs[1] + fileTwo,
                         self.testTargetDirs[2] + fileThree,
                         self.testTargetDirs[3] + fileFour,
                         self.testTargetDirs[1] + fileFive,
                         ]

        #####
        # Check a previous state and find all the correct files in that state
        for item in filesTargetState:
            myfile = self.testMetaDirs[0] + item
            myfileFp = open(myfile, "w")
            myfileFp.write("hello world!")
            myfileFp.close()
            LIBC.sync()

        states = ["stateAfter", "stateBefore"]

        success, _ = self.fsm.areFilesInStates(states, filesOrig)

        self.assertTrue(success, "Files in States check two failed...")

        #####
        # multiple files in another state, but not all of them
        filesStateOne = [self.testTargetDirs[0] + fileOne,
                         self.testTargetDirs[1] + fileTwo,
                         self.testTargetDirs[2] + fileThree,
                         ]

        #####
        # Check a previous state and find all the correct files in that state
        for item in filesOrig:
            itemFp = open(item, "w")
            itemFp.write("Hello World")
            itemFp.close()
            LIBC.sync()

        for item in filesStateOne:
            myfile = self.testMetaDirs[3] + item
            myfileFp = open(myfile, "w")
            myfileFp.write("Hello World")
            myfileFp.close()
            LIBC.sync()

        states = ["stateAfter", "stateBefore"]

        success, _ = self.fsm.areFilesInStates(states, filesOrig)

        self.assertFalse(success, "Files in States check three succeeded...")

        #####
        # There is one file off in one state, match till found in states
        filesStateOne = [self.testTargetDirs[0] + fileOne,
                         self.testTargetDirs[1] + fileTwo,
                         self.testTargetDirs[2] + fileThree,
                         self.testTargetDirs[3] + fileFour,
                         self.testTargetDirs[1] + fileFive,
                         ]

        #####
        # Check a previous state and find all the correct files in that state
        for item in filesOrig:
            itemFp = open(item, "w")
            itemFp.write("Hello World")
            itemFp.close()
            LIBC.sync()

        for item in filesStateOne:
            myfile = self.testMetaDirs[3] + item
            myfileFp = open(myfile, "w")
            myfileFp.write("Hello World")
            myfileFp.close()
            LIBC.sync()

        fileFiveFp = open(self.testTargetDirs[1] + fileFive, "w")
        fileFiveFp.write("Hello World!")
        fileFiveFp.close()
        LIBC.sync()

        states = ["stateAfter", "stateBefore"]

        success, _ = self.fsm.areFilesInStates(states, filesOrig)

        self.assertFalse(success, "Files in States check four succeeded...")

        #####
        # no state of files match
        for item in filesOrig:
            itemFp = open(item, "w")
            itemFp.write("Howdy!")
            itemFp.close()
            LIBC.sync()

        states = ["stateAfter", "stateBefore"]

        success, _ = self.fsm.areFilesInStates(states, filesOrig)

        self.assertFalse(success, "Files in States check five succeeded...")

        #####
        # In new list, not in old list
        fileSix = "/sixthTestFile"
        filesStateOne = [self.testTargetDirs[0] + fileOne,
                         self.testTargetDirs[1] + fileTwo,
                         self.testTargetDirs[2] + fileThree,
                         self.testTargetDirs[3] + fileFour,
                         self.testTargetDirs[1] + fileFive,
                         self.testTargetDirs[1] + fileSix,
                         ]

        #####
        # Check a previous state and find all the correct files in that state
        for item in filesOrig:
            itemFp = open(item, "w")
            itemFp.write("Greetings Traveler")
            itemFp.close()
            LIBC.sync()

        for item in filesStateOne:
            myfile = self.testMetaDirs[3] + item
            myfileFp = open(myfile, "w")
            myfileFp.write("Greetings Traveloer")
            myfileFp.close()
            LIBC.sync()

        states = ["stateAfter", "stateBefore"]

        success, _ = self.fsm.areFilesInStates(states, filesOrig)

        self.assertFalse(success, "Files in States check five succeeded...")

    ############################################################################

    def test_buildSearchList(self):
        """
        """
        #####
        # Set up and test for expected state check
        thirdTestFile = self.testTargetDirs[0] + "/thirdTestFile"

        fpBefore = open(self.testMetaDirs[0] + thirdTestFile, "w")
        fpAfter = open(self.testMetaDirs[1] + thirdTestFile, "w")
        anotherFpAfter = open(self.testMetaDirs[2] + thirdTestFile, "w")
        yetAnotherFpAfter = open(self.testMetaDirs[3] + thirdTestFile, "w")
        fpSecondTestFile = open(thirdTestFile, "w")

        for item in [fpSecondTestFile, fpBefore, fpAfter, anotherFpAfter, yetAnotherFpAfter]:
            item.write("Hello World!")
            item.close()
            LIBC.sync()

        searchList = self.fsm.buildSearchList(["stateBefore", "stateAfter"], thirdTestFile)

        self.logger.log(lp.DEBUG, "buildSearchList test list: " + str(searchList))

        expectedList = ['/tmp/stonixtest/1.2.4.5/stateAfter/tmp/stonixtest/testOne/thirdTestFile',
                        '/tmp/stonixtest/1.2.4.5/stateBefore/tmp/stonixtest/testOne/thirdTestFile',
                        '/tmp/stonixtest/1.2.3/stateAfter/tmp/stonixtest/testOne/thirdTestFile',
                        '/tmp/stonixtest/1.2.3/stateBefore/tmp/stonixtest/testOne/thirdTestFile']

        success = expectedList == searchList
        self.assertTrue(success, "Lists don't match, Houston, we have a problem...")

    ############################################################################

    def test_qsort(self):
        """
        """
        versions = ['1.4.3', '1.2.3', '0.9.6.42', '1.5.6']

        newVersions = self.fsm.qsort(versions)
        success = False
        successes = []

        i = 0

        for version in newVersions:
            if i == 0:
                i = i + 1
                continue
            elif LooseVersion(version) >= LooseVersion(newVersions[i-1]):
                successes.append(True)
            else:
                successes.append(False)
            i = i + 1

        if False in successes:
            success = False
        else:
            success = True

        self.logger.log(lp.DEBUG, "Successes: " + str(successes))
        self.logger.log(lp.DEBUG, "Success: " + str(success))

        #####
        # Assert that a Quick Sorted array is ordered
        self.assertTrue(success, "Quicksort did not correctly order the versions.")

        i = 0
        success = False
        successes = []

        for version in versions:
            if i == 0:
                i = i + 1
                continue
            elif LooseVersion(version) >= LooseVersion(versions[i-1]):
                successes.append(True)
            else:
                successes.append(False)
            i = i + 1

        if False in successes:
            success = False
        else:
            success = True

        self.logger.log(lp.DEBUG, "Successes: " + str(successes))
        self.logger.log(lp.DEBUG, "Success: " + str(success))

        #####
        # Assert that the unordered array is NOT ordered
        self.assertFalse(success, "Versions is correctly ordered.")

    ############################################################################

    def test_changeFileState(self):
        """
        """

        #####
        # Set two files as different
        fileName = self.testTargetDirs[0] + "/refFileOne"
        metaState = self.testMetaDirs[0]
        metaStateFile = self.testMetaDirs[0] + fileName

        fileNameFp = open(fileName, "w")
        fileNameFp.write("hello world")
        fileNameFp.close()

        metaStateFileFp = open(metaStateFile, "w")
        metaStateFileFp.write("Hello World!")
        metaStateFileFp.close()

        #####
        # Compare to assert they are different
        isSame = filecmp.cmp(metaStateFile, fileName)

        #####
        # Assert they are different
        self.assertFalse(isSame, "Files are not supposed to be the same, they are the same...")

        #####
        # Run the state change
        changeResult = self.fsm.changeFileState(metaStateFile, fileName)

        #####
        # check they are the same
        isSame = filecmp.cmp(metaStateFile, fileName)
        #####
        # assert the check returns that they are the same
        self.assertTrue(isSame == changeResult, "Files are supposed to be the same, they are not...")

    ############################################################################

    def test_changeFilesState(self):
        """
        """
        #####
        # Set two files as different
        fileOne   = "/firstTestFile"
        fileTwo   = "/secondTestFile"
        fileThree = "/thirdTestFile"
        fileFour  = "/fourthTestFile"
        fileFive  = "/fifthTestFile"

        filesOrig = [self.testTargetDirs[0] + fileOne,
                     self.testTargetDirs[1] + fileTwo,
                     self.testTargetDirs[2] + fileThree,
                     self.testTargetDirs[3] + fileFour,
                     self.testTargetDirs[1] + fileFive,
                     ]
        filesTargetState = [self.testMetaDirs[0] + filesOrig[0],
                            self.testMetaDirs[0] + filesOrig[1],
                            self.testMetaDirs[0] + filesOrig[2],
                            self.testMetaDirs[0] + filesOrig[3],
                            self.testMetaDirs[0] + filesOrig[4],
                            ]


        for item in filesOrig:
            itemFp = open(item, "w")
            itemFp.write("Hello World!")
            itemFp.close()
            LIBC.sync()

        for item in filesTargetState:
            itemFp = open(item, "w")
            itemFp.write("Bonjour Monde!")
            itemFp.close()
            LIBC.sync()

        #####
        # Compare to assert they are different
        success, _ = self.fsm.areFilesInStates(["beforeState", "afterState"], filesOrig)

        #####
        # Assert they are different
        self.assertFalse(success, "File sets don't match...")

        #####
        # Run the state change
        changed = self.fsm.changeFilesState("/tmp/stonixtest/1.2.3/stateBefore", filesOrig)

        #####
        # check they are the same
        compareList = []
        success = False

        for item in filesOrig:
            success = filecmp.cmp("/tmp/stonixtest/1.2.3/stateBefore" + item, item)
            compareList.append(success)
        if False in compareList:
            success = False
        else:
            success = True

        self.assertTrue(success, "We have a problem matching all the files...")

        #####
        # assert the check returns that they are the same
        self.assertTrue(changed, "Expected change failed...")

    ############################################################################

    def test_areFilesInState(self):
        """
        """
        #####
        # Set two files as different
        fileOne   = "/firstTestFile"
        fileTwo   = "/secondTestFile"
        fileThree = "/thirdTestFile"
        fileFour  = "/fourthTestFile"
        fileFive  = "/fifthTestFile"

        filesOrig = [self.testTargetDirs[0] + fileOne,
                     self.testTargetDirs[1] + fileTwo,
                     self.testTargetDirs[2] + fileThree,
                     self.testTargetDirs[3] + fileFour,
                     self.testTargetDirs[1] + fileFive,
                     ]

        metaState = self.fsm.getPrefix() + "/" +\
                    self.fsm.getVersion() + "/" +\
                    "stateAfter"

        self.logger.log(lp.DEBUG, "metaState: " + metaState)

        filesTargetState = [metaState + filesOrig[0],
                            metaState + filesOrig[1],
                            metaState + filesOrig[2],
                            metaState + filesOrig[3],
                            metaState + filesOrig[4],
                            ]

        for item in filesOrig:
            itemFp = open(item, "w")
            itemFp.write("Hello World!")
            itemFp.close()
            LIBC.sync()

        for item in filesTargetState:
            itemFp = open(item, "w")
            itemFp.write("Bonjour Monde!")
            itemFp.close()
            LIBC.sync()

        success = False
        success = self.fsm.areFilesInState(metaState, filesOrig)

        self.assertFalse(success, "Files aren't supposed to match here...")

        for item in filesTargetState:
            itemFp = open(item, "w")
            itemFp.write("Hello World!")
            itemFp.close()
            LIBC.sync()

        success = False
        success = self.fsm.areFilesInState(metaState, filesOrig)

        self.assertTrue(success, "Files need to match here...")

    ############################################################################


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
