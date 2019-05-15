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
This is a Unit Test for Rule SecureMDNS

@author: ekkehard j. koch
@change: 03/18/2013 Original Implementation
@change: 2016/02/10 roy Added sys.path.append for being able to unit test this
                        file as well as with the test harness.
@change: 2016/05/10 eball Removed PListBuddy delete command, which was deleting
    important information from the plist. Also moved plist for Mac test to a
    temporary location, and copied it back after test is complete.
@change: 2017/10/23 rsn - change to new service helper interface
'''
from __future__ import absolute_import
import os
import re
import sys
import unittest

sys.path.append("../../../..")
from src.tests.lib.RuleTestTemplate import RuleTest
from src.stonix_resources.CommandHelper import CommandHelper
from src.stonix_resources.KVEditorStonix import KVEditorStonix
from src.tests.lib.logdispatcher_mock import LogPriority
from src.stonix_resources.pkghelper import Pkghelper
from src.stonix_resources.ServiceHelper import ServiceHelper
from src.stonix_resources.stonixutilityfunctions import readFile, writeFile
from src.stonix_resources.rules.SecureMDNS import SecureMDNS


class zzzTestRuleSecureMDNS(RuleTest):

    def setUp(self):
        RuleTest.setUp(self)
        self.rule = SecureMDNS(self.config,
                               self.environ,
                               self.logdispatch,
                               self.statechglogger)
        self.rulename = self.rule.rulename
        self.rulenumber = self.rule.rulenumber
        self.ch = CommandHelper(self.logdispatch)
        self.plb = "/usr/libexec/PlistBuddy"
        self.sh = ServiceHelper(self.environ, self.logdispatch)
        self.service = ""
        self.serviceTarget=""

    def tearDown(self):
        if os.path.exists(self.service + ".stonixtmp"):
            os.rename(self.service + ".stonixtmp", self.service)

    def runTest(self):
        self.simpleRuleTest()

    def setConditionsForRule(self):
        '''Configure system for the unit test

        :param self: essential if you override this definition
        :returns: boolean - If successful True; If failure False
        @author: ekkehard j. koch

        '''
        success = True
        if self.environ.getosfamily() == "darwin":
            success = False
            osxversion = str(self.environ.getosver())
            if osxversion.startswith("10.10.0") or \
               osxversion.startswith("10.10.1") or \
               osxversion.startswith("10.10.2") or \
               osxversion.startswith("10.10.3"):
                debug = "Using discoveryd LaunchDaemon"
                self.logdispatch.log(LogPriority.DEBUG, debug)
                service = \
                    "/System/Library/LaunchDaemons/com.apple.discoveryd.plist"
                servicename = "com.apple.networking.discoveryd"
                parameter = "--no-multicast"
                plistText = readFile(service, self.logdispatch)
                newPlistText = re.sub("<string>" + parameter + "</string>",
                                      "", "".join(plistText))
                success = True
            else:
                debug = "Using mDNSResponder LaunchDaemon"
                self.logdispatch.log(LogPriority.DEBUG, debug)
                service = "/System/Library/LaunchDaemons/" + \
                    "com.apple.mDNSResponder.plist"
                if osxversion.startswith("10.10"):
                    servicename = "com.apple.mDNSResponder.reloaded"
                    parameter = "-NoMulticastAdvertisements"
                else:
                    servicename = "com.apple.mDNSResponder"
                    parameter = "-NoMulticastAdvertisements"
                plistText = readFile(service, self.logdispatch)
                newPlistText = re.sub("<string>" + parameter + "</string>",
                                      "", "".join(plistText))
                success = True
            self.service = service
            if success and self.sh.auditService(service, serviceTarget=servicename):
                success = writeFile(service + ".stonixtmp", "".join(plistText),
                                    self.logdispatch)
                success = writeFile(service, newPlistText, self.logdispatch)
            if success and self.sh.auditService(service, serviceTarget=servicename):
                success = self.sh.reloadService(service, serviceTarget=servicename)
        else:
            ph = Pkghelper(self.logdispatch, self.environ)
            package = "avahi-daemon"
            service = "avahi-daemon"
            if (ph.determineMgr() == "yum" or ph.determineMgr() == "dnf"):
                package = "avahi"
                path = "/etc/sysconfig/network"
                if os.path.exists(path):
                    tmppath = path + ".tmp"
                    data = {"NOZEROCONF": "yes"}
                    editor = KVEditorStonix(self.statechglogger,
                                            self.logdispatch, "conf",
                                            path, tmppath, data,
                                            "notpresent", "closedeq")
                    if not editor.report():
                        if editor.fix():
                            if not editor.commit():
                                success = False
                        else:
                            success = False
            elif ph.determineMgr() == "zypper":
                package = "avahi"
            if not ph.check(package) and ph.checkAvailable(package):
                success = ph.install(package)
            if success and not self.sh.auditService(service, serviceTarget=self.serviceTarget):
                self.sh.enableService(service, serviceTarget=self.serviceTarget)
        return success

    def checkReportForRule(self, pCompliance, pRuleSuccess):
        '''check on whether report was correct

        :param self: essential if you override this definition
        :param pCompliance: the self.iscompliant value of rule
        :param pRuleSuccess: did report run successfully
        :returns: boolean - If successful True; If failure False
        @author: ekkehard j. koch

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
        @author: ekkehard j. koch

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
        @author: ekkehard j. koch

        '''
        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " +
                             str(pRuleSuccess) + ".")
        success = True
        return success

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
