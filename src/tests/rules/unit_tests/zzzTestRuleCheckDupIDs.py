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
        '''Configure system for the unit test

        :param self: essential if you override this definition
        :returns: boolean - If successful True; If failure False
        @author: ekkehard j. koch

        '''
        success = True
        return success

    def checkReportForRule(self, pCompliance, pRuleSuccess):
        '''check on whether report was correct

        :param self: essential if you override this definition
        :param pCompliance: the self.iscompliant value of rule
        :param pRuleSuccess: did report run successfully
        :returns: boolean - If successful True; If failure False
        @author: ekkehard j. koch

        '''
        self.logdispatch.log(LogPriority.DEBUG, "pCompliance = " +
                             str(pCompliance) + ".")
        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " +
                             str(pRuleSuccess) + ".")
        success = True
        return success

    def checkFixForRule(self, pRuleSuccess):
        '''check on whether fix was correct

        :param self: essential if you override this definition
        :param pRuleSuccess: did report run successfully
        :returns: boolean - If successful True; If failure False
        @author: ekkehard j. koch

        '''
        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " +
                             str(pRuleSuccess) + ".")
        success = True
        return success

    def checkUndoForRule(self, pRuleSuccess):
        '''check on whether undo was correct

        :param self: essential if you override this definition
        :param pRuleSuccess: did report run successfully
        :returns: boolean - If successful True; If failure False
        @author: ekkehard j. koch

        '''
        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " +
                             str(pRuleSuccess) + ".")
        success = True
        return success

    @unittest.skipUnless(sys.platform.startswith("darwin"), "CheckDupID's does nto support this OS.")
    def test_checkForMacosDuplicateUser(self):
        '''Tests the rule method that uses the /usr/bin/dscl command to
        check for duplicate User IDs in the local directory service


        '''

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
