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
This is a Unit Test for Rule DisableGDMAutoLogin

"""

import unittest
import sys
import os
import re
import shutil

sys.path.append("../../../..")
from src.tests.lib.RuleTestTemplate import RuleTest
from src.stonix_resources.CommandHelper import CommandHelper
from src.tests.lib.logdispatcher_mock import LogPriority
from src.stonix_resources.rules.DisableGDMAutoLogin import DisableGDMAutoLogin

class zzzTestRuleDisableGDMAutoLogin(RuleTest):

    def setUp(self):
        RuleTest.setUp(self)
        self.rule = DisableGDMAutoLogin(self.config,
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

    def _restore_file(self, backup):
        """
​
        :param backup:
        :return:
        """

        if os.path.isfile(backup):
            if re.search("\.stonix_test_bak", backup):
                shutil.copy2(backup, backup.replace(".stonix_test_bak", ""))

    def _backup_file(self, original):
        """
    ​
        :param original:
        :return:
        """

        if os.path.isfile(original):
            shutil.copy2(original, original + ".stonix_test_bak")

    def test_gdm_not_present(self):
        """
        both report and fix should always return True if gdm not present

        :return:
        """

        if not os.path.isdir("/etc/gdm"):
            self.assertTrue(self.rule.report())
            self.assertTrue(self.rule.fix())
        else:
            return True

    def test_conffile_not_present(self):
        """

        :return:
        """

        if os.path.isdir("/etc/gdm"):
            if not os.path.isfile("/etc/gdm/custom.conf"):
                self.assertFalse(self.rule.report())

                self.rule.fix()
                self.assertTrue(self.rule.report())

    def test_confoption_incorrect(self):
        """
        report should return False if conf option is incorrect
        fix should still return True if conf option is incorrect

        :return:
        """

        if os.path.isdir("/etc/gmd"):
            self._backup_file("/etc/gdm/custom.conf")
            f = open("/etc/gdm/custom.conf", "w")
            incorrect_config = """[daemon]
    AutomaticLoginEnable=True
    """
            f.write(incorrect_config)
            f.close()

            self.assertFalse(self.rule.report())
            self.assertTrue(self.rule.fix())
            self._restore_file("/etc/gdm/custom.conf.stonix_test_bak")
        else:
            return True

    def test_confoption_missing(self):
        """
        report should return False if conf option is missing altogether
        fix should still return True

        :return:
        """

        if os.path.isdir("/etc/gmd"):
            self._backup_file("/etc/gdm/custom.conf")
            f = open("/etc/gdm/custom.conf", "w")
            incorrect_config = ""
            f.write(incorrect_config)
            f.close()

            self.assertFalse(self.rule.report())
            self.assertTrue(self.rule.fix())
            self._restore_file("/etc/gdm/custom.conf.stonix_test_bak")
        else:
            return True

    def test_confoption_commented(self):
        """
        report should return False if the config option is commented out

        :return:
        """

        if os.path.isdir("/etc/gmd"):
            self._backup_file("/etc/gdm/custom.conf")
            f = open("/etc/gdm/custom.conf", "w")
            incorrect_config = """[daemon]
# AutomaticLoginEnable=False
"""
            f.write(incorrect_config)
            f.close()

            self.assertFalse(self.rule.report())
            self.assertTrue(self.rule.fix())
            self._restore_file("/etc/gdm/custom.conf.stonix_test_bak")
        else:
            return True

    def test_confsection_missing(self):
        """
        report should return False if the config option is not under the right tag

        :return:
        """

        if os.path.isdir("/etc/gmd"):
            self._backup_file("/etc/gdm/custom.conf")
            f = open("/etc/gdm/custom.conf", "w")
            incorrect_config = "AutomaticLoginEnable=False"
            f.write(incorrect_config)
            f.close()

            self.assertFalse(self.rule.report())
            self.assertTrue(self.rule.fix())
            self._restore_file("/etc/gdm/custom.conf.stonix_test_bak")
        else:
            return True

    def test_confoption_correct(self):
        """
        report should return True if conf option is correct
        fix should always return True if conf option is already correct

        :return:
        """

        pass
        # backup file
        # write correct option
        # test report
        # test fix
        # restore backup

    def setConditionsForRule(self):
        """
        Configure system for the unit test

        :return: boolean - If successful True; If failure False

        """

        success = True
        return success

    def checkReportForRule(self, pCompliance, pRuleSuccess):
        """
        check on whether report was correct

        :param pCompliance: the self.iscompliant value of rule
        :param pRuleSuccess: did report run successfully
        :return: boolean - If successful True; If failure False

        """

        self.logdispatch.log(LogPriority.DEBUG, "pCompliance = " + \
                             str(pCompliance) + ".")
        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " + \
                             str(pRuleSuccess) + ".")
        success = True
        return success

    def checkFixForRule(self, pRuleSuccess):
        """
        check on whether fix was correct

        :param pRuleSuccess: did report run successfully
        :return: boolean - If successful True; If failure False

        """

        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " + \
                             str(pRuleSuccess) + ".")
        success = True
        return success

    def checkUndoForRule(self, pRuleSuccess):
        """
        check on whether undo was correct

        :param pRuleSuccess: did report run successfully
        :return: boolean - If successful True; If failure False

        """

        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " + \
                             str(pRuleSuccess) + ".")
        success = True
        return success

if __name__ == "__main__":
    unittest.main()
