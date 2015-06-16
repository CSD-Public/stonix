'''
Created on Jun 9, 2015

@author: dwalker
'''
from __future__ import absolute_import
import unittest
import re
from src.stonix_resources.RuleTestTemplate import RuleTest
from src.stonix_resources.rules.ConfigurePasswordProfile import ConfigurePasswordProfile
from src.stonix_resources.CommandHelper import CommandHelper
from src.stonix_resources.logdispatcher import LogPriority


class zzzTestRuleConfigurePasswordProfile(RuleTest):

    def setUp(self):
        RuleTest.setUp(self)
        self.rule = ConfigurePasswordProfile(self.config, self.environ,
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
        success = True
        cmd = ["/usr/bin/profiles", "-L"]
        profilenum = "C873806E-E634-4E58-B960-62817F398E11"
        if self.ch.executeCommand(cmd):
            output = self.ch.getOutput()
            if output:
                for line in output:
                    if re.search(profilenum, line):
                        cmd = ["/usr/bin/profiles", "-r", profilenum]
                        if not self.ch.executeCommand(cmd):
                            success = False
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

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
