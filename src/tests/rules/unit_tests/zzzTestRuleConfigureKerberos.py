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
        ''' '''

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
        '''restore any/all files to original versions


        :returns: success

        :rtype: bool
@author: Breen Malmberg

        '''

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
        '''backup the krb5 conf file
        and write a new version with the contents:
        'test'


        :returns: success

        :rtype: bool
@author: Breen Malmberg

        '''

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
        ''' '''

        self.simpleRuleTest()

    def test_backup_dict(self):
        ''' '''

        self.assertNotEqual(self.backupDict, {})

    def test_init(self):
        ''' '''

        self.assertIsNotNone(self.rule.files)
        self.assertIsInstance(self.rule.files, dict)
        self.assertIsNotNone(self.rule.ch)
        self.assertIsNotNone(self.rule.fh)
        if self.environ.getosfamily() == "linux":
            self.assertIsNotNone(self.rule.ph)

    def test_fix_ci(self):
        ''' '''

        origcival = self.rule.ci.getcurrvalue()
        self.rule.ci.updatecurrvalue(False)
        falseci = self.rule.ci.getcurrvalue()
        self.assertEqual(falseci, self.rule.fix())
        self.rule.ci.updatecurrvalue(origcival)

    def checkReportForRule(self, pCompliance, pRuleSuccess):
        '''check on whether report was correct

        :param pCompliance: the self.iscompliant value of rule
        :param pRuleSuccess: did report run successfully
        :returns: boolean - If successful True; If failure False
        @author: Ekkehard J. Koch

        '''

        self.logdispatch.log(LogPriority.DEBUG, "pCompliance = " +
                             str(pCompliance) + ".")
        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " +
                             str(pRuleSuccess) + ".")
        success = True
        return success

    def checkFixForRule(self, pRuleSuccess):
        '''check on whether fix was correct

        :param pRuleSuccess: did report run successfully
        :returns: boolean - If successful True; If failure False
        @author: Ekkehard J. Koch

        '''
        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " +
                             str(pRuleSuccess) + ".")
        success = True
        return success

    def checkUndoForRule(self, pRuleSuccess):
        '''check on whether undo was correct

        :param pRuleSuccess: did report run successfully
        :returns: boolean - If successful True; If failure False
        @author: Ekkehard J. Koch

        '''
        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " +
                             str(pRuleSuccess) + ".")
        success = True
        return success

if __name__ == "__main__":
    unittest.main()
