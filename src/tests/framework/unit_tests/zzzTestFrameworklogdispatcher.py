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
Created on Sep 21, 2011


@author: scmcleni
@change: 2015/11/04 eball Refactored test to be functional
@change: 2016-02-10 roy - adding sys.path.append for both test framework and 
                          individual test runs.
'''
import sys
import unittest

sys.path.append("../../../..")
from src.stonix_resources.logdispatcher import LogDispatcher, LogPriority
import src.stonix_resources.environment as environment


class zzzTestFrameworklogdispatcher(unittest.TestCase):

    def setUp(self):
        self.environ = environment.Environment()
        self.environ.setdebugmode(True)
        self.logger = LogDispatcher(self.environ)
        self.priority = LogPriority()

    def tearDown(self):
        self.logger.closereports()

    def testLogCritical(self):
        try:
            self.logger.log(self.priority.CRITICAL, "Critical level message")
        except:
            self.fail("Failed to write CRITICAL to log file")

    def testLogError(self):
        try:
            self.logger.log(self.priority.ERROR, "Error level message")
        except:
            self.fail("Failed to write ERROR to log file")

    def testLogWarning(self):
        try:
            self.logger.log(self.priority.WARNING, "Warning level message")
        except:
            self.fail("Failed to write WARNING to log file")

    def testLogInfo(self):
        try:
            self.logger.log(self.priority.INFO, "Info level message")
        except:
            self.fail("Failed to write INFO to log file")

    def testLogDebug(self):
        try:
            self.logger.log(self.priority.DEBUG, "Debug level message")
        except:
            self.fail("Failed to write DEBUG to log file")

    def testFormatNoError(self):
        try:
            self.logger.log(self.priority.WARNING, ["WarningMessageTag",
                                                    "Warning message text"])
        except:
            self.fail("Failed to write formatted WARNING message")

    def testFormatWithError(self):
        try:
            self.logger.log(self.priority.ERROR, ["ErrorMessageTag",
                                                  "Error message text"])
        except:
            self.fail("Failed to write formatted ERROR message")

if __name__ == "__main__":
    unittest.main()
