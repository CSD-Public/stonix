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
This is a Unit Test for Rule ConfigureAppleSoftwareUpdate

@author: ekkehard j. koch
@change: 03/18/2013 Original Implementation
@change: 2016/02/10 roy Added sys.path.append for being able to unit test this
                        file as well as with the test harness.
'''
from __future__ import absolute_import
import unittest
import sys
import os
import re

sys.path.append("../../../..")
from src.tests.lib.RuleTestTemplate import RuleTest
from src.stonix_resources.CommandHelper import CommandHelper
from src.tests.lib.logdispatcher_mock import LogPriority
from src.stonix_resources.rules.DisableIPV6 import DisableIPV6


class zzzTestRuleDisableIPV6(RuleTest):

    def setUp(self):
        RuleTest.setUp(self)
        self.rule = DisableIPV6(self.config,
                                self.environ,
                                self.logdispatch,
                                self.statechglogger)
        self.logger = self.logdispatch
        self.rulename = self.rule.rulename
        self.rulenumber = self.rule.rulenumber
        self.ch = CommandHelper(self.logdispatch)

    def tearDown(self):
        pass

    def runTest(self):
        self.simpleRuleTest()

    def setConditionsForRule(self):
        '''Configure system for the unit test

        :param self: essential if you override this definition
        :returns: boolean - If successful True; If failure False
        @author: ekkehard j. koch

        '''
        success = True
        if self.environ.getosfamily() == "linux":
            success = self.setLinuxConditions()
        elif self.environ.getosfamily() == "darwin":
            success = self.setMacConditions()
        return success

    def setLinuxConditions(self):
        self.sysctl = ""
        debug = ""
        success = True
        sysctllocs = ["/sbin/sysctl", "/usr/sbin/sysctl"]
        for loc in sysctllocs:
            if os.path.exists(loc):
                self.sysctl = loc
        directives = ["net.ipv6.conf.all.disable_ipv6=0",
                      "net.ipv6.conf.default.disable_ipv6=0"]
        if self.sysctl:
            for d in directives:
                setbadopt = self.sysctl + " -w " + d
                self.ch.executeCommand(setbadopt)
                retcode = self.ch.getReturnCode()
                if retcode != 0:
                    success = False
                    debug = "Failed to write configuration change: " + d + "\n"
                    self.logger.log(LogPriority.DEBUG, debug)
        else:
            debug = "sysctl command not found on system\n"
            self.logger.log(LogPriority.DEBUG, debug)
            success =  False
        return success

    def setMacConditions(self):
        success = True
        debug = ""
        networksetup = "/usr/sbin/networksetup"
        listnetworkservices = networksetup + " -listallnetworkservices"
        ipv6status = "^IPv6:\s+On"
        getinfo = networksetup + " -getinfo"
        self.ch.executeCommand(listnetworkservices)
        retcode = self.ch.getReturnCode()
        if retcode != 0:
            success = False
            debug = "Failed to get list of network services"
            self.logger.log(LogPriority.DEBUG, debug)
        else:
            networkservices = self.ch.getOutput()
            for ns in networkservices:
                # ignore non-network service output lines
                if re.search("denotes that", ns, re.IGNORECASE):
                    continue
                else:
                    self.ch.executeCommand(networksetup + ' -setv6automatic ' + '"' + ns + '"')
                    retcode = self.ch.getReturnCode()
                    if retcode != 0:
                        success = False
                        debug = "Failed to get information for network service: " + ns
                        self.logger.log(LogPriority.DEBUG, debug)
        return success

    def checkReportForRule(self, pCompliance, pRuleSuccess):
        '''check on whether report was correct

        :param self: essential if you override this definition
        :param pCompliance: the self.iscompliant value of rule
        :param pRuleSuccess: did report run successfully
        :returns: boolean - If successful True; If failure False
        @author: ekkehard j. koch

        '''
        self.logdispatch.log(LogPriority.DEBUG, "pCompliance = " + \
                             str(pCompliance) + ".")
        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " + \
                             str(pRuleSuccess) + ".")
        success = True
        return success

    def checkFixForRule(self, pRuleSuccess):
        '''check on whether fix was correct

        :param self: essential if you override this definition
        :param pRuleSuccess: did report run successfully
        :returns: boolean - If successful True; If failure False
        @author: ekkehard j. koch

        '''
        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " + \
                             str(pRuleSuccess) + ".")
        success = True
        return success

    def checkUndoForRule(self, pRuleSuccess):
        '''check on whether undo was correct

        :param self: essential if you override this definition
        :param pRuleSuccess: did report run successfully
        :returns: boolean - If successful True; If failure False
        @author: ekkehard j. koch

        '''
        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " + \
                             str(pRuleSuccess) + ".")
        success = True
        return success

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
