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
This is a Unit Test for Rule ConfigureAppleSoftwareUpdate

@author: Breen Malmberg
@change: 03/18/2013 Original Implementation
@change: 2016/02/10 roy Added sys.path.append for being able to unit test this
                        file as well as with the test harness.
@change: 2016/09/19 Breen Added individual configuration tests.
'''

from __future__ import absolute_import
import unittest
import sys
import os

from shutil import copyfile

sys.path.append("../../../..")
from src.tests.lib.RuleTestTemplate import RuleTest
from src.stonix_resources.CommandHelper import CommandHelper
from src.tests.lib.logdispatcher_mock import LogPriority
from src.stonix_resources.rules.SecureCUPS import SecureCUPS


class zzzTestRuleSecureCUPS(RuleTest):

    def setUp(self):
        RuleTest.setUp(self)
        self.rule = SecureCUPS(self.config,
                               self.environ,
                               self.logdispatch,
                               self.statechglogger)
        self.rulename = self.rule.rulename
        self.rulenumber = self.rule.rulenumber
        self.ch = CommandHelper(self.logdispatch)
        self.testnum = 0  
        self.cupsdconf = ""
        cupsdconflocs = ['/etc/cups/cupsd.conf',
                         '/private/etc/cups/cupsd.conf']
        self.cupsdconfbak = ""
        for loc in cupsdconflocs:
            if os.path.exists(loc):
                self.cupsdconf = loc
        self.cupsdconfbak = self.cupsdconf + ".bak"
        if os.path.exists(self.cupsdconf):
            copyfile(self.cupsdconf, self.cupsdconfbak)

    def tearDown(self):
        '''
        '''

        pass

    def setConditionsForRule(self):
        '''
        Configure system for the unit test

        @return: success
        @rtype: bool
        @author: Breen Malmberg
        '''

        success = True

        try:

            # turn on all CIs by default
            self.rule.SecureCUPS.updatecurrvalue(True)
            self.rule.DisableCUPS.updatecurrvalue(True)
            self.rule.DisableGenericPort.updatecurrvalue(True)
            self.rule.SetDefaultAuthType.updatecurrvalue(True)
            self.rule.SetupDefaultPolicyBlocks.updatecurrvalue(True)

        except Exception:
            success = False
        return success

    def test_secure_print_browse_on(self):
        '''
        disableprintbrowsing and printbrowsesubnet are mutually
        exclusive CIs and must be tested in separate configurations

        @author: Breen Malmberg
        '''

        self.setConditionsForRule
        self.testnum += 1
        self.rule.DisablePrintBrowsing.updatecurrvalue(False)
        self.rule.PrintBrowseSubnet.updatecurrvalue(True)
        self.simpleRuleTest()
        if os.path.exists(self.cupsdconf):
            copyfile(self.cupsdconf, self.cupsdconf + "_test" + str(self.testnum))
            if os.path.exists(self.cupsdconfbak):
                copyfile(self.cupsdconfbak, self.cupsdconf)

    def test_secure_print_browse_off(self):
        '''
        disableprintbrowsing and printbrowsesubnet are mutually
        exclusive CIs and must be tested in separate configurations

        @author: Breen Malmberg
        '''

        self.setConditionsForRule
        self.testnum += 1
        self.rule.PrintBrowseSubnet.updatecurrvalue(False)
        self.rule.DisablePrintBrowsing.updatecurrvalue(True)
        self.simpleRuleTest()
        if os.path.exists(self.cupsdconf):
            copyfile(self.cupsdconf, self.cupsdconf + "_test" + str(self.testnum))
            if os.path.exists(self.cupsdconfbak):
                copyfile(self.cupsdconfbak, self.cupsdconf)

    def test_disable(self):
        '''
        test rule with only disablecups CI enabled

        @author: Breen Malmberg
        '''

        self.setConditionsForRule
        self.testnum += 1
        self.rule.SecureCUPS.updatecurrvalue(False)
        self.rule.DisableCUPS.updatecurrvalue(True)
        self.rule.DisablePrintBrowsing.updatecurrvalue(False)
        self.rule.DisableGenericPort.updatecurrvalue(False)
        self.rule.SetDefaultAuthType.updatecurrvalue(False)
        self.rule.SetupDefaultPolicyBlocks.updatecurrvalue(False)
        self.rule.PrintBrowseSubnet.updatecurrvalue(False)
        self.simpleRuleTest()
        if os.path.exists(self.cupsdconf):
            copyfile(self.cupsdconf, self.cupsdconf + "_test" + str(self.testnum))
            if os.path.exists(self.cupsdconfbak):
                copyfile(self.cupsdconfbak, self.cupsdconf)

    def checkReportForRule(self, pCompliance, pRuleSuccess):
        '''
        check on whether report was correct
        @param self: essential if you override this definition
        @param pCompliance: the self.iscompliant value of rule
        @param pRuleSuccess: did report run successfully
        @return: success
        @rtype: bool
        @author: ekkehard j. koch
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
        @return: success
        @rtype: bool
        @author: ekkehard j. koch
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
        @return: success
        @rtype: bool
        @author: ekkehard j. koch
        '''
        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " + \
                             str(pRuleSuccess) + ".")
        success = True
        return success

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
