#!/usr/bin/env python
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
This is a Unit Test for Rule SystemAccounting

@author: Breen Malmberg
@change: 2015/09/25 eball Updated to enable CI so that rule runs during test
@change: 2015/09/25 eball Added Debian/Ubuntu setup
@change: 2015/10/09 eball Updated Deb setup to improve automated testing compat
@change: 2015/10/26 eball Comment fix, added informative text for test failure
@change: 2016/02/10 roy Added sys.path.append for being able to unit test this
                        file as well as with the test harness.
'''

import unittest
import re
import os
import sys

sys.path.append("../../../..")
from src.tests.lib.RuleTestTemplate import RuleTest
from src.stonix_resources.CommandHelper import CommandHelper
from src.stonix_resources.localize import PROXY
from src.tests.lib.logdispatcher_mock import LogPriority
from src.stonix_resources.rules.SystemAccounting import SystemAccounting


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
        self.rule.ci.updatecurrvalue(True)

    def tearDown(self):
        pass

    def runTest(self):
        result = self.simpleRuleTest()
        self.assertTrue(result, "SystemAccounting(9): rule.iscompliant() is " +
                        "'False' after rule.fix() and rule.report() have " +
                        "run. This may be due to a proxy error; if the " +
                        "proper proxy is not set in localize.py, set it and " +
                        "run this test again.")

    def setConditionsForRule(self):
        '''Configure system for the unit test

        :param self: essential if you override this definition
        :returns: boolean - If successful True; If failure False
        @author: Breen Malmberg

        '''
        success = True
        self.rule.ci.updatecurrvalue(True)
        try:
            if re.search("debian|ubuntu", self.environ.getostype().lower()):
                sysstat = "/etc/default/sysstat"
                if os.path.exists(sysstat):
                    settings = open(sysstat, "r").read()
                    settings = re.sub(r"ENABLED=.+\n", "ENABLED=false\n",
                                      settings)
                else:
                    settings = "ENABLED=false\n"
                open(sysstat, "w").write(settings)
                # apt does a very poor job installing packages when it hasn't
                # been updated in a while, which is problematic with VMs. These
                # next few lines are intended to deal with that issue.
                if not re.search("foo.bar", PROXY):
                    os.environ["http_proxy"] = PROXY
                    os.environ["https_proxy"] = PROXY
                cmd = ["/usr/bin/apt-get", "update"]
                self.ch.executeCommand(cmd)
            else:
                path1 = "/etc/rc.conf"
                path2 = "/var/account/acct"
                if os.path.exists(path1):
                    contentlines = open(path1, "r").readlines()
                    for line in contentlines:
                        if re.search('accounting_enable=', line):
                            contentlines = [c.replace(line,
                                                      'accounting_enable=NO\n')
                                            for c in contentlines]
                    if 'accounting_enable=NO\n' not in contentlines:
                        contentlines.append('accounting_enable=NO\n')
                    open(path1, "w").writelines(contentlines)

                if os.path.exists(path2):
                    os.remove(path2)

        except Exception:
            success = False
        return success

    def checkReportForRule(self, pCompliance, pRuleSuccess):
        '''check on whether report was correct

        :param self: essential if you override this definition
        :param pCompliance: the self.iscompliant value of rule
        :param pRuleSuccess: did report run successfully
        :returns: boolean - If successful True; If failure False
        @author: Breen Malmberg

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
        @author: Breen Malmberg

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
        @author: Breen Malmberg

        '''
        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " +
                             str(pRuleSuccess) + ".")
        success = True
        return success

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
