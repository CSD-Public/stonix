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
This is a Unit Test for Rule MinimizeAcceptedDHCPOptions

@author: Breen Malmberg - 6/13/2016
@change: Breen Malmberg - 8/19/2016 - re-factored all unit tests
to account for existance of any/none/all required files
'''


import os
import unittest
import sys
from shutil import copyfile

sys.path.append("../../../..")
from src.tests.lib.RuleTestTemplate import RuleTest
from src.stonix_resources.CommandHelper import CommandHelper
from src.tests.lib.logdispatcher_mock import LogPriority
from src.stonix_resources.rules.MinimizeAcceptedDHCPOptions import MinimizeAcceptedDHCPOptions


class zzzTestRuleMinimizeAcceptedDHCPOptions(RuleTest):

    def setUp(self):
        RuleTest.setUp(self)
        self.rule = MinimizeAcceptedDHCPOptions(self.config,
                              self.environ,
                              self.logdispatch,
                              self.statechglogger)
        self.rulename = self.rule.rulename
        self.rulenumber = self.rule.rulenumber
        self.ch = CommandHelper(self.logdispatch)

        self.rule.localize()

        if self.rule.filepaths:
            for fp in self.rule.filepaths:
                copyfile(fp, fp + '.stonixtestbak')

    def tearDown(self):
        if self.rule.filepaths:
            for fp in self.rule.filepaths:
                if os.path.exists(fp + '.stonixtestbak'):
                    copyfile(fp + '.stonixtestbak', fp)
                    os.remove(fp + '.stonixtestbak')

    def setConditionsForRule(self):
        '''Configure system for the unit test

        :param self: essential if you override this definition
        :returns: boolean - If successful True; If failure False
        @author: Breen Malmberg

        '''

        success = True
        return success

    def test_static(self):
        '''test with whatever the current system configuration
        is
        
        @author: Breen Malmberg


        '''

        if self.rule.filepaths:

            self.simpleRuleTest()
        else:
            pass

    def test_blankfile(self):
        '''run test with a blank dhclient.conf file present
        
        @author: Breen Malmberg


        '''

        if self.rule.filepaths:
            for fp in self.rule.filepaths:
                f = open(fp, 'w')
                f.write('')
                f.close()
            self.simpleRuleTest()
        else:
            pass

    def test_garbage(self):
        '''test with a file that has garbage contents
        
        @author: Breen Malmberg


        '''

        if self.rule.filepaths:
            for fp in self.rule.filepaths:
                f = open(fp, 'w')
                f.write(' (*#%HJSDnvlw jk34nrl24km \n\nrl23978Y*@$&G i4w\n')
                f.close()
            self.simpleRuleTest()
        else:
            pass

    def test_partialconfig(self):
        '''test with a partially configured file
        
        @author: Breen Malmberg


        '''

        if self.rule.filepaths:
            for fp in self.rule.filepaths:
                f = open(fp, 'w')
                f.write('supersede subnet-mask "example.com";\nsupersede domain-name "example.com";\nrequest broadcast-address;\nrequire broadcast-address;\n')
                f.close()
            self.simpleRuleTest()
        else:
            pass

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

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
