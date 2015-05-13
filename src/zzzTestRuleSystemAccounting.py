#!/usr/bin/env python
'''
This is a Unit Test for Rule SystemAccounting

@author: Breen Malmberg
'''
from __future__ import absolute_import
import unittest
import re
import os
from stonix_resources.RuleTestTemplate import RuleTest
from stonix_resources.CommandHelper import CommandHelper
from stonix_resources.logdispatcher import LogPriority
from stonix_resources.rules.SystemAccounting import SystemAccounting


class zzzTestRuleSystemAccounting(RuleTest):

    def setUp(self):
        RuleTest.setUp(self)
        self.rule = SystemAccounting(self.config,
                                        self.environ,
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
        @author: Breen Malmberg
        '''
        success = True

        try:

            f = open('/etc/rc.conf', 'w+')
            if os.path.exists('/etc/rc.conf'):
                contentlines = f.readlines()
                for line in contentlines:
                    if re.search('accounting_enable=', line):
                        contentlines = [c.replace(line, 'accounting_enable=NO\n') for c in contentlines]
                if 'accounting_enable=NO\n' not in contentlines:
                    contentlines.append('accounting_enable=NO\n')
                f.writelines(contentlines)
                f.close()

            if os.path.exists('/var/account/acct'):
                os.remove('/var/account/acct')

        except Exception:
            success = False
        return success

    def checkReportForRule(self, pCompliance, pRuleSuccess):
        '''
        check on whether report was correct
        @param self: essential if you override this definition
        @param pCompliance: the self.iscompliant value of rule
        @param pRuleSuccess: did report run successfully
        @return: boolean - If successful True; If failure False
        @author: Breen Malmberg
        '''
        self.logdispatch.log(LogPriority.DEBUG, "pCompliance = " + \
                             str(pCompliance) + ".")
        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " + \
                             str(pRuleSuccess) + ".")
        success = True
        return success

    def checkFixForRule(self, pRuleSuccess):
        '''
        check on whether fix was correct
        @param self: essential if you override this definition
        @param pRuleSuccess: did report run successfully
        @return: boolean - If successful True; If failure False
        @author: Breen Malmberg
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
        @author: Breen Malmberg
        '''
        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " + \
                             str(pRuleSuccess) + ".")
        success = True
        return success

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
