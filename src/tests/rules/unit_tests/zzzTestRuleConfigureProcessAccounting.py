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
This is a Unit Test for Rule ConfigureProcessAccounting

@author: Eric Ball
@change: 2016/04/19 eball Original Implementation
@change: 2016/08/02 eball Added debug statements to the beginning of tests to
    make debug output more useful
@change: 2017/10/23 rsn - change to new service helper interface
'''
from __future__ import absolute_import
import unittest
import sys

sys.path.append("../../../..")
from src.tests.lib.RuleTestTemplate import RuleTest
from src.tests.lib.logdispatcher_mock import LogPriority
from src.stonix_resources.pkghelper import Pkghelper
from src.stonix_resources.ServiceHelper import ServiceHelper
from src.stonix_resources.rules.ConfigureProcessAccounting import \
    ConfigureProcessAccounting


class zzzTestRuleConfigureProcessAccounting(RuleTest):

    def setUp(self):
        RuleTest.setUp(self)
        self.rule = ConfigureProcessAccounting(self.config, self.environ,
                                               self.logdispatch,
                                               self.statechglogger)
        self.rulename = self.rule.rulename
        self.rulenumber = self.rule.rulenumber

        self.ph = Pkghelper(self.logdispatch, self.environ)
        self.sh = ServiceHelper(self.environ, self.logdispatch)
        self.rule.report()
        package = self.rule.package
        self.package = package

        self.pkgInstalled = False
        self.svcEnabled = False
        if self.ph.check(package):
            self.pkgInstalled = True
        if self.sh.auditservice(package, _="_"):
            self.svcEnabled = True

    def tearDown(self):
        package = self.package
        if self.pkgInstalled and not self.ph.check(package):
            self.ph.install(package)
        elif not self.pkgInstalled and self.ph.check(package):
            self.ph.remove(package)
        if self.svcEnabled and not self.sh.auditservice(package, _="_"):
            self.sh.enableservice(package, _="_")
        elif not self.svcEnabled and self.sh.auditservice(package, _="_"):
            self.sh.disableservice(package, _="_")

    def testPkghelperFunctions(self):
        self.logdispatch.log(LogPriority.DEBUG,
                             "Running testPkghelperFunctions")
        package = self.package
        if self.pkgInstalled:
            self.ph.remove(package)
            self.assertFalse(self.ph.check(package), "Pkghelper.check is " +
                             "not False after Pkghelper.remove")
            self.ph.install(package)
            self.assertTrue(self.ph.check(package), "Pkghelper.check is " +
                            "not True after Pkghelper.install")
        else:
            self.ph.install(package)
            self.assertTrue(self.ph.check(package), "Pkghelper.check is " +
                            "not True after Pkghelper.install")
            self.ph.remove(package)
            self.assertFalse(self.ph.check(package), "Pkghelper.check is " +
                             "not False after Pkghelper.remove")

    def testServiceHelperFunctions(self):
        self.logdispatch.log(LogPriority.DEBUG,
                             "Running testServiceHelperFunctions")
        package = self.package
        self.ph.install(package)
        if self.svcEnabled:
            self.sh.disableservice(package, _="_")
            self.assertFalse(self.sh.auditservice(package, _="_"),
                             "ServiceHelper.auditservice is not False " +
                             "after ServiceHelper.disableservice")
            self.sh.enableservice(package, _="_")
            self.assertTrue(self.sh.auditservice(package, _="_"),
                            "ServiceHelper.auditservice is not True after " +
                            "ServiceHelper.enableservice")
        else:
            self.sh.enableservice(package, _="_")
            self.assertTrue(self.sh.auditservice(package, _="_"),
                            "ServiceHelper.auditservice is not True after " +
                            "ServiceHelper.enableservice")
            self.sh.disableservice(package, _="_")
            self.assertFalse(self.sh.auditservice(package, _="_"),
                             "ServiceHelper.auditservice is not False " +
                             "after ServiceHelper.disableservice")

    def testReport(self):
        self.logdispatch.log(LogPriority.DEBUG,
                             "Running testReport")
        package = self.package
        if self.pkgInstalled:
            self.ph.remove(package)
        self.assertFalse(self.rule.report(), "Report was compliant, but" +
                         package + " shows as not being installed")
        self.ph.install(package)
        # Service may or may not be enabled at time of installation; should be
        # manually enabled to ensure correct setup
        self.sh.enableservice(package, _="_")
        self.assertTrue(self.rule.report(), "Report was non-compliant, but " +
                        package + " shows as installed and enabled")
        self.sh.disableservice(package, _="_")
        self.assertFalse(self.rule.report(), "Report was compliant, but " +
                         package + " was not enabled")

    def testFixAndUndoForServiceOnly(self):
        self.logdispatch.log(LogPriority.DEBUG,
                             "Running testFixAndUndoForServiceOnly")
        package = self.package
        if not self.pkgInstalled:
            self.ph.install(package)
        self.sh.disableservice(package, _="_")
        self.assertFalse(self.rule.report(), "Report was compliant, but " +
                         package + " was not enabled")
        originalResults = self.rule.detailedresults
        self.assertTrue(self.rule.fix(), "Fix was not successful with " +
                        package + " installed but not enabled")
        self.assertTrue(self.sh.auditservice(package, _="_"),
                        package + " service does not appear to be running")
        self.assertTrue(self.rule.report(), "Report was NCAF")
        self.assertTrue(self.rule.undo(), "Undo was not successful")
        self.assertFalse(self.rule.report(), "Report is still compliant " +
                         "after undo")
        self.assertEqual(originalResults, self.rule.detailedresults,
                         "Report results are not the same after undo as " +
                         "they were before fix")

    def testFixAndUndoForServiceAndPackage(self):
        self.logdispatch.log(LogPriority.DEBUG,
                             "Running testFixAndUndoForServiceAndPackage")
        package = self.package
        if self.pkgInstalled:
            self.ph.remove(package)
        self.assertFalse(self.rule.report(), "Report was compliant, but " +
                         package + " is not installed")
        originalResults = self.rule.detailedresults
        self.assertTrue(self.rule.fix(), "Fix was not successful with " +
                        package + " not installed")
        self.assertTrue(self.ph.check(package),
                        package + " does not appear to be installed")
        self.assertTrue(self.sh.auditservice(package, _="_"),
                        package + " service does not appear to be running")
        self.assertTrue(self.rule.report(), "Report was NCAF")
        self.assertTrue(self.rule.undo(), "Undo was not successful")
        self.assertFalse(self.rule.report(), "Report is still compliant " +
                         "after undo")
        self.assertEqual(originalResults, self.rule.detailedresults,
                         "Report results are not the same after undo as " +
                         "they were before fix")

    def runTest(self):
        self.simpleRuleTest()

    def setConditionsForRule(self):
        '''
        Configure system for the unit test
        @param self: essential if you override this definition
        @return: boolean - If successful True; If failure False
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

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
