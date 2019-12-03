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


"""
This is a Unit Test for Rule SystemAccounting

@author: Breen Malmberg
@change: 2015/09/25 eball Updated to enable CI so that rule runs during test
@change: 2015/09/25 eball Added Debian/Ubuntu setup
@change: 2015/10/09 eball Updated Deb setup to improve automated testing compat
@change: 2015/10/26 eball Comment fix, added informative text for test failure
@change: 2016/02/10 roy Added sys.path.append for being able to unit test this
                        file as well as with the test harness.
"""

import unittest
import re
import os
import sys
import shutil

sys.path.append("../../../..")
from src.tests.lib.RuleTestTemplate import RuleTest
from src.stonix_resources.CommandHelper import CommandHelper
from src.stonix_resources.pkghelper import Pkghelper
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
        self.ph = Pkghelper(self.logdispatch, self.environ)
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

    def test_default_sysstat_empty(self):
        """
        test correction of /etc/default/sysstat if it has no entry in it

        :return:
        """

        file = "/etc/default/sysstat"
        backup = "/etc/default/sysstat.stonix_test_bak"

        if os.path.isfile(file):
            self._backup_file(file)
            f = open(file, "w")
            f.write("")
            f.close()

            self.rule._set_paths()
            self.assertFalse(self.rule._report_configuration())
            self.rule._fix_configuration()
            self.assertTrue(self.rule._report_configuration())

            self._restore_file(backup)
        else:
            return True

    def test_default_sysstat_comment(self):
        """
        test correction of /etc/default/sysstat if it has the entry commented out

        :return:
        """

        file = "/etc/default/sysstat"
        backup = "/etc/default/sysstat.stonix_test_bak"

        if os.path.isfile(file):
            self._backup_file(file)
            f = open(file, "w")
            f.write('# ENABLED="true"')
            f.close()

            self.rule._set_paths()
            self.assertFalse(self.rule._report_configuration())
            self.rule._fix_configuration()
            self.assertTrue(self.rule._report_configuration())

            self._restore_file(backup)
        else:
            return True

    def test_default_sysstat_wrongvalue(self):
        """
        test correction of /etc/default/sysstat if it has the entry set to the wrong value

        :return:
        """

        file = "/etc/default/sysstat"
        backup = "/etc/default/sysstat.stonix_test_bak"

        if os.path.isfile(file):
            self._backup_file(file)
            f = open(file, "w")
            f.write('ENABLED="false"')
            f.close()

            self.rule._set_paths()
            self.assertFalse(self.rule._report_configuration())
            self.rule._fix_configuration()
            self.assertTrue(self.rule._report_configuration())

            self._restore_file(backup)
        else:
            return True

    def test_default_sysstat_rightvalue(self):
        """
        test correction of /etc/default/sysstat if it has the entry set to the right value

        :return:
        """

        file = "/etc/default/sysstat"
        backup = "/etc/default/sysstat.stonix_test_bak"

        if os.path.isfile(file):
            self._backup_file(file)
            f = open(file, "w")
            f.write('ENABLED="true"')
            f.close()

            self.rule._set_paths()
            self.assertTrue(self.rule._report_configuration())
            self.rule._fix_configuration()
            self.assertTrue(self.rule._report_configuration())

            self._restore_file(backup)
        else:
            return True

    def test_installation_installed(self):
        """
        test installation report/fix if package already installed
        applies to Linux only

        :return:
        """

        if self.rule.ostype == "Mac OS X":
            return True

        package = "sysstat"

        if self.ph.check(package):
            self.rule._set_paths()
            self.assertTrue(self.rule._report_installation())
            self.rule._fix_installation()
            self.assertTrue(self.rule._report_installation())
        else:
            return True

    def test_installation_missing(self):
        """
        test installation report/fix if package not installed
        applies to Linux only

        :return:
        """

        if self.rule.ostype == "Mac OS X":
            return True

        package = "sysstat"

        if not self.ph.check(package):
            self.rule._set_paths()
            self.assertFalse(self.rule._report_installation())
            self.rule._fix_installation()
            self.assertTrue(self.rule._report_installation())
        else:
            return True

    def test_set_paths(self):
        """
        test that all paths and necessary variables for the class are able to be properly
        determined and set once package is installed

        :return:
        """

        package = "sysstat"

        self.ph.install(package)

        self.rule._set_paths()

        self.assertTrue(self.rule.sysstat_package)
        self.assertTrue(self.rule.sysstat_service_file)
        self.assertTrue(self.rule.sa1)
        self.assertTrue(self.rule.sa2)
        self.assertTrue(self.rule.sysstat_service_contents)
        self.assertTrue(self.rule.sysstat_cron_contents)
        self.assertTrue(self.rule.ostype)

        self.ph.remove(package)

    def _restore_file(self, backup):
        """

        :param backup:
        :return:
        """

        if os.path.isfile(backup):
            if re.search("\.stonix_test_bak", backup):
                shutil.copy2(backup, backup.replace(".stonix_test_bak", ""))

    def _backup_file(self, original):
        """

        :param original:
        :return:
        """

        if os.path.isfile(original):
            shutil.copy2(original, original + ".stonix_test_bak")

    def setConditionsForRule(self):
        """Configure system for the unit test

        :param self: essential if you override this definition
        :returns: boolean - If successful True; If failure False
        @author: Breen Malmberg

        """

        success = True
        self.rule.ci.updatecurrvalue(True)
        return success

    def checkReportForRule(self, pCompliance, pRuleSuccess):
        """check on whether report was correct

        :param self: essential if you override this definition
        :param pCompliance: the self.iscompliant value of rule
        :param pRuleSuccess: did report run successfully
        :returns: boolean - If successful True; If failure False
        @author: Breen Malmberg

        """
        self.logdispatch.log(LogPriority.DEBUG, "pCompliance = " +
                             str(pCompliance) + ".")
        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " +
                             str(pRuleSuccess) + ".")
        success = True
        return success

    def checkFixForRule(self, pRuleSuccess):
        """check on whether fix was correct

        :param self: essential if you override this definition
        :param pRuleSuccess: did report run successfully
        :returns: boolean - If successful True; If failure False
        @author: Breen Malmberg

        """
        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " +
                             str(pRuleSuccess) + ".")
        success = True
        return success

    def checkUndoForRule(self, pRuleSuccess):
        """check on whether undo was correct

        :param self: essential if you override this definition
        :param pRuleSuccess: did report run successfully
        :returns: boolean - If successful True; If failure False
        @author: Breen Malmberg

        """
        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " +
                             str(pRuleSuccess) + ".")
        success = True
        return success

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
