#!/usr/bin/env python
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
'''
This is a Unit Test for Rule ConfigureAppleSoftwareUpdate

@author: ekkehard j. koch
@change: 2014-11-24 Original Implementation
'''
from __future__ import absolute_import
import unittest
from src.tests.lib.RuleTestTemplate import RuleTest
from src.stonix_resources.CommandHelper import CommandHelper
from src.tests.lib.logdispatcher_mock import LogPriority
from src.stonix_resources.rules.InstallCasperSuite import InstallCasperSuite

import os

class zzzTestRuleInstallCasperSuite(RuleTest):

    def setUp(self):
        RuleTest.setUp(self)
        self.rule = InstallCasperSuite(self.config, self.environ,
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
        '''
        Configure system for the unit test
        @param self: essential if you override this definition
        @return: boolean - If successful True; If failure False
        @author: ekkehard j. koch
        '''
        success = True
        return success

    def test_checkReportForRule(self, pCompliance, pRuleSuccess):
        '''
        check on whether report was correct
        @param self: essential if you override this definition
        @param pCompliance: the self.iscompliant value of rule
        @param pRuleSuccess: did report run successfully
        @return: boolean - If successful True; If failure False
        @author: ekkehard j. koch
        '''
        self.logdispatch.log(LogPriority.DEBUG, "pCompliance = " + \
                             str(pCompliance) + ".")
        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " + \
                             str(pRuleSuccess) + ".")
        success = True
        return success

    def test_checkFixForRule(self, pRuleSuccess):
        '''
        check on whether fix was correct
        @param self: essential if you override this definition
        @param pRuleSuccess: did report run successfully
        @return: boolean - If successful True; If failure False
        @author: ekkehard j. koch
        '''
        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " + \
                             str(pRuleSuccess) + ".")
        success = True
        return success

    def checkUndoForRule(self, pRuleSuccess):
        '''
        check on whether undo was correct
        @param self: essential if you override this definition
        @param pRuleSuccess: did report run successfully
        @return: boolean - If successful True; If failure False
        @author: ekkehard j. koch
        '''
        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " + \
                             str(pRuleSuccess) + ".")
        success = True
        return success

    def test_checkIfJamfBinaryExists(self):
        '''
        Check to see if the Jamf binary is installed
        @param self: essential if you override this definition
        @param pRuleSuccess: did report run successfully
        @return: boolean - If successful True; If failure False
        @author: Roy Nielsen
        '''
        success = os.path.isfile("/usr/local/bin/jamf")
        self.logdispatch.log(LogPriority.DEBUG, "")
        self.assertTrue(success)

    def test_checkIfSelfServiceAppExists(self):
        '''
        Check to see if the Lanl Self Service.app is installed
        @param self: essential if you override this definition
        @param pRuleSuccess: did report run successfully
        @return: boolean - If successful True; If failure False
        @author: Roy Nielsen
        '''
        success = os.path.isdir("/Applications/LANL Self Service.app")
        self.logdispatch.log(LogPriority.DEBUG, "Found Lanl Self Service.app")
        self.assertTrue(success)

    def test_checkIfSigOneExists(self):
        '''
        Check to see if the first signature (/etc/dds.txt) is installed
        @param self: essential if you override this definition
        @param pRuleSuccess: did report run successfully
        @return: boolean - If successful True; If failure False
        @author: Roy Nielsen
        '''
        success = os.path.isfile("/etc/dds.txt")
        self.logdispatch.log(LogPriority.DEBUG, "Found Lanl Self Service.app")
        self.assertTrue(success)

    def test_checkIfSelfSigTwoExists(self):
        '''
        Check to see if the second signature (/var/log/dds.log) is installed
        @param self: essential if you override this definition
        @param pRuleSuccess: did report run successfully
        @return: boolean - If successful True; If failure False
        @author: Roy Nielsen
        '''
        success = os.path.isfile("/var/log/dds.log")
        self.logdispatch.log(LogPriority.DEBUG, "Found Lanl Self Service.app")
        self.assertTrue(success)

    def test_checkJamfReconRun(self):
        '''
        Check to see if the jamf recon command works
        @param self: essential if you override this definition
        @param pRuleSuccess: did report run successfully
        @return: boolean - If successful True; If failure False
        @author: Roy Nielsen
        '''
        cmd = ["/usr/local/bin/jamf", "recon"]
        self.ch.executeCommand(cmd)
        return_code = self.ch.getReturnCode()
        self.logdispatch.log(LogPriority.DEBUG, "Return code from jamf recon command: " + str(return_code))
        self.assertEquals(str(0), str(return_code))

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
