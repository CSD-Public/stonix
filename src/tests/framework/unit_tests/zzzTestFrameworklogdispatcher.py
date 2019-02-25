#! /usr/bin/python

'''
Created on Sep 21, 2011

###############################################################################
#                                                                             #
# Copyright 2015-2019.  Los Alamos National Security, LLC. This material was       #
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
