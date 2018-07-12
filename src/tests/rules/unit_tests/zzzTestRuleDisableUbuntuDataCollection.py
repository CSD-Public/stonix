#!/usr/bin/env python
###############################################################################
#                                                                             #
# Copyright 2015-2018.  Los Alamos National Security, LLC. This material was       #
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
Created On: 2018/07/11

This is a Unit Test for Rule DisableUbuntuDataCollection

@author: ekkehard j. koch, Breen Malmberg
'''

from __future__ import absolute_import

import sys
import unittest

sys.path.append("../../../..")

from src.tests.lib.RuleTestTemplate import RuleTest
from src.tests.lib.logdispatcher_mock import LogPriority
from src.stonix_resources.rules.DisableUbuntuDataCollection import DisableUbuntuDataCollection
from src.stonix_resources.pkghelper import Pkghelper


class zzzTestRuleDisableUbuntuDataCollection(RuleTest):

    def setUp(self):
        '''

        @return: None
        @author: ekkehard j. koch, Breen Malmberg
        '''

        RuleTest.setUp(self)
        self.rule = DisableUbuntuDataCollection(self.config, self.environ, self.logdispatch, self.statechglogger)
        self.rulename = self.rule.rulename
        self.rulenumber = self.rule.rulenumber
        self.ph = Pkghelper(self.logdispatch, self.environ)
        self.datacollectionpkgs = ["popularity-contest", "apport", "ubuntu-report"]
        self.teardownpkgs = []

    def tearDown(self):
        '''

        @return: None
        '''

        for pkg in self.teardownpkgs:
            self.ph.remove(pkg)
            self.teardownpkgs.remove(pkg)

    def runTest(self):
        '''

        @return: None
        '''

        self.simpleRuleTest()

    def setConditionsForRule(self):
        '''
        Configure system for the unit test

        @return: success
        @rtype: bool
        @author: ekkehard j. koch, Breen Malmberg
        '''

        success = True
        self.rule.enabledCI.updatecurrvalue(True)

        for pkg in self.datacollectionpkgs:
            if not self.ph.check(pkg):
                self.ph.install(pkg)
                self.teardownpkgs.append(pkg)
        return success

    def checkReportForRule(self, pCompliance, pRuleSuccess):
        '''
        check on whether report was correct

        @param pCompliance: the self.iscompliant value of rule
        @param pRuleSuccess: did report run successfully
        @return: success
        @rtype: bool
        @author: ekkehard j. koch
        '''

        self.logdispatch.log(LogPriority.DEBUG, "pCompliance = " + str(pCompliance) + ".")
        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " + str(pRuleSuccess) + ".")
        success = True
        return success

    def checkFixForRule(self, pRuleSuccess):
        '''
        check on whether fix was correct

        @param pRuleSuccess: did report run successfully
        @return: success
        @rtype: bool
        @author: ekkehard j. koch
        '''

        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " + str(pRuleSuccess) + ".")
        success = True
        return success

    def checkUndoForRule(self, pRuleSuccess):
        '''
        check on whether undo was correct

        @param pRuleSuccess: did report run successfully
        @return: success
        @rtype: bool
        @author: ekkehard j. koch
        '''

        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " + str(pRuleSuccess) + ".")
        success = True
        return success

if __name__ == "__main__":
    unittest.main()
