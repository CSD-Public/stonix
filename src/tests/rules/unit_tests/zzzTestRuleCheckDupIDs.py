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
This is a Unit Test for Rule CheckDupIDs

@author: ekkehard j. koch
@change: 2013/03/18 Original Implementation
@change: 2015/10/28 Update name
@change: 2016/02/10 rsn Added sys.path.append for being able to unit test this
                        file as well as with the test harness.
@change: 2016/04/27 rsn Added use of ApplicableCheck class
@change: 2016/04/27 rsn Added use of precursor to manage_user class
@change: 2016/08/29 eball Added conditional to SkipTest for Python < v2.7
'''
from __future__ import absolute_import
import sys
import unittest

sys.path.append("../../../..")
from src.tests.lib.RuleTestTemplate import RuleTest
from src.tests.lib.manage_users.macos_users import MacOSUser
from src.stonix_resources.CheckApplicable import CheckApplicable
from src.tests.lib.logdispatcher_lite import LogPriority
from src.stonix_resources.rules.CheckDupIDs import CheckDupIDs


class zzzTestRuleCheckDupIDs(RuleTest):

    def setUp(self):
        RuleTest.setUp(self)
        self.rule = CheckDupIDs(self.config,
                                self.environ,
                                self.logdispatch,
                                self.statechglogger)
        self.rulename = self.rule.rulename
        self.rulenumber = self.rule.rulenumber
        self.users = MacOSUser()
        #####
        # Set up an applicable check class
        self.chkApp = CheckApplicable(self.environ, self.logdispatch)

    def tearDown(self):
        pass

    def test_rule(self):
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

    def checkReportForRule(self, pCompliance, pRuleSuccess):
        '''
        check on whether report was correct
        @param self: essential if you override this definition
        @param pCompliance: the self.iscompliant value of rule
        @param pRuleSuccess: did report run successfully
        @return: boolean - If successful True; If failure False
        @author: ekkehard j. koch
        '''
        self.logdispatch.log(LogPriority.DEBUG, "pCompliance = " +
                             str(pCompliance) + ".")
        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " +
                             str(pRuleSuccess) + ".")
        success = True
        return success

    def checkFixForRule(self, pRuleSuccess):
        '''
        check on whether fix was correct
        @param self: essential if you override this definition
        @param pRuleSuccess: did report run successfully
        @return: boolean - If successful True; If failure False
        @author: ekkehard j. koch
        '''
        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " +
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
        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " +
                             str(pRuleSuccess) + ".")
        success = True
        return success

    def test_checkForMacosDuplicateUser(self):
        """
        Tests the rule method that uses the /usr/bin/dscl command to
        check for duplicate User IDs in the local directory service
        """
        applicable = {'type': 'white',
                      'family': ['darwin']}

        isTestApplicableHere = self.chkApp.isapplicable(applicable)

        if not isTestApplicableHere:
            if sys.version_info < (2, 7):
                return
            else:
                raise unittest.SkipTest("CheckDupID's does not support this OS")

        uid = "7000"

        self.users.createBasicUser("AutoTestMacDuplicateUserOne")
        self.users.createBasicUser("AutoTestMacDuplicateUserTwo")

        successOne = self.users.setUserUid("AutoTestMacDuplicateUserOne",
                                           str(uid))
        successTwo = self.users.setUserUid("AutoTestMacDuplicateUserTwo",
                                           str(uid))
        self.assertTrue(successOne)
        self.assertTrue(successTwo)
        self.assertTrue(successOne == successTwo)

        self.users.rmUser("AutoTestMacDuplicateUserOne")
        self.users.rmUser("AutoTestMacDuplicateUserTwo")

if __name__ == "__main__":
    unittest.main()
