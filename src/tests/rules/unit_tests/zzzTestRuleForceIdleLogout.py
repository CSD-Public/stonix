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
This is a Unit Test for Rule ForceIdleLogout

@author: Eric Ball
@change: 2016/08/25 Original Implementation
'''
from __future__ import absolute_import
import unittest
import sys

sys.path.append("../../../..")
from src.tests.lib.RuleTestTemplate import RuleTest
from src.tests.lib.logdispatcher_mock import LogPriority
from src.stonix_resources.rules.ForceIdleLogout import ForceIdleLogout
from src.stonix_resources.pkghelper import Pkghelper


class zzzTestRuleForceIdleLogout(RuleTest):

    def setUp(self):
        RuleTest.setUp(self)
        self.rule = ForceIdleLogout(self.config,
                                    self.environ,
                                    self.logdispatch,
                                    self.statechglogger)
        self.logger = self.logdispatch
        self.rulename = self.rule.rulename
        self.rulenumber = self.rule.rulenumber
        self.rule.filci.updatecurrvalue(True)
        self.checkUndo = True
        self.ph = Pkghelper(self.logger, self.environ)

    def tearDown(self):
        pass

    def runTest(self):
        self.simpleRuleTest()

    def setConditionsForRule(self):
        '''
        Configure system for the unit test
        @param self: essential if you override this definition
        @return: boolean - If successful True; If failure False
        @author: ekkehard j. koch
        '''
        success = True
        desktopmgr = False
        desktopmgrs = ["gdm", "gdm3", "kdm", "kde-workspace"]
        if self.ph.check("gdm") or self.ph.check("gdm3"):
            desktopmgr = True
            success = self.setgnome3()
        if self.ph.check("kdm") or self.ph.check("kde-workspace"):
            desktopmgr = True
            success = self.setkde()
        if not desktopmgr:
            for mgr in desktopmgrs:
                if self.ph.checkAvailable(mgr):
                    if self.ph.install(mgr):
                        desktopmgr = True
            if not desktopmgr:
                success = False
                debug = "Unable to install a desktop manager for testing\n"
                self.logger.log(LogPriority.DEBUG, debugt)
        return success

    def setgnome3(self):

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
    unittest.main()
