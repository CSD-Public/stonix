#!/usr/bin/env python
###############################################################################
#                                                                             #
# Copyright 2015-2019.  Los Alamos National Security, LLC. This material was  #
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
"""
This is a Unit Test for Rule ConfigureKerberos

@author: Ekkehard J. Koch
@change: 04/02/2013 Original Implementation
@change: 07/14/2014 - Ekkehard - made testing more rigorous
@change: 07/28/2014 - Ekkehard - bug fixes
@change: 2015/12/18 - Eric Ball - Added eventids
@change: 2016/02/10 Roy Nielsen Added sys.path.append for being able to unit test this
        file as well as with the test harness.
"""

from __future__ import absolute_import
import os
import sys
import unittest

sys.path.append("../../../..")
from src.tests.lib.RuleTestTemplate import RuleTest
from src.stonix_resources.CommandHelper import CommandHelper
from src.tests.lib.logdispatcher_mock import LogPriority
from src.stonix_resources.rules.ConfigureKerberos import ConfigureKerberos


class zzzTestRuleConfigureKerberos(RuleTest):

    def setUp(self):
        """

        @return:
        """

        RuleTest.setUp(self)
        self.rule = ConfigureKerberos(self.config,
                                      self.environ,
                                      self.logdispatch,
                                      self.statechglogger)
        self.setCheckUndo(True)
        self.rulename = self.rule.rulename
        self.rulenumber = self.rule.rulenumber
        self.ch = CommandHelper(self.logdispatch)

        self.backupDict = {}
        self.possible_paths = ["/etc/krb5.conf", "/Library/Preferences/edu.mit.Kerberos",
                          "/Library/Preferences/edu.mit.Kerberos.krb5kdc.launchd",
                          "/Library/Preferences/edu.mit.Kerberos.kadmind.launchd"]
        for p in self.possible_paths:
            if os.path.exists(p):
                tp = p + ".stonixUT"
                self.backupDict = {p: tp}

    def tearDown(self):
        """
        restore any/all files to original versions

        @return: success
        @rtype: bool
        @author: Breen Malmberg
        """

        success = True

        try:
            if self.backupDict:
                for p in self.backupDict:
                    if os.path.exists(self.backupDict[p]):
                        os.rename(self.backupDict[p], p)
        except (OSError, IOError) as err:
            success = False
            self.logdispatch.log(LogPriority.DEBUG, str(err))

        return success

    def setConditionsForRule(self):
        """
        backup the krb5 conf file
        and write a new version with the contents:
        'test'

        @return: success
        @rtype: bool
        @author: Breen Malmberg
        """

        success = True

        try:
            if self.backupDict:
                for p in self.backupDict:
                    os.rename(p, self.backupDict[p])
                    open(p, "w").write("test\n")
        except (OSError, IOError) as err:
            self.logdispatch.log(LogPriority.DEBUG, str(err))
            success = False

        return success

    def runTest(self):
        """

        @return:
        """

        self.simpleRuleTest()

    def test_backup_dict(self):
        """

        @return:
        """

        self.assertNotEqual(self.backupDict, {})

    def test_init(self):
        """

        @return:
        """

        self.assertIsNotNone(self.rule.files)
        self.assertIsInstance(self.rule.files, dict)
        self.assertIsNotNone(self.rule.ch)
        self.assertIsNotNone(self.rule.fh)
        if self.environ.getosfamily() == "linux":
            self.assertIsNotNone(self.rule.ph)

    def test_fix_ci(self):
        """

        @return:
        """

        origcival = self.rule.ci.getcurrvalue()
        self.rule.ci.updatecurrvalue(False)
        falseci = self.rule.ci.getcurrvalue()
        self.assertEqual(falseci, self.rule.fix())
        self.rule.ci.updatecurrvalue(origcival)

    def checkReportForRule(self, pCompliance, pRuleSuccess):
        """
        check on whether report was correct

        @param pCompliance: the self.iscompliant value of rule
        @param pRuleSuccess: did report run successfully
        @return: boolean - If successful True; If failure False
        @author: Ekkehard J. Koch
        """

        self.logdispatch.log(LogPriority.DEBUG, "pCompliance = " +
                             str(pCompliance) + ".")
        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " +
                             str(pRuleSuccess) + ".")
        success = True
        return success

    def checkFixForRule(self, pRuleSuccess):
        """
        check on whether fix was correct

        @param pRuleSuccess: did report run successfully
        @return: boolean - If successful True; If failure False
        @author: Ekkehard J. Koch
        """
        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " +
                             str(pRuleSuccess) + ".")
        success = True
        return success

    def checkUndoForRule(self, pRuleSuccess):
        """
        check on whether undo was correct

        @param pRuleSuccess: did report run successfully
        @return: boolean - If successful True; If failure False
        @author: Ekkehard J. Koch
        """
        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " +
                             str(pRuleSuccess) + ".")
        success = True
        return success

if __name__ == "__main__":
    unittest.main()
