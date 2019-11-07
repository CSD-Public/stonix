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


'''
This is a Unit Test for Rule SetTFTPD
Created on Jun 8, 2016

@author: dwalker
'''


import unittest
import sys

sys.path.append("../../../..")
from src.tests.lib.RuleTestTemplate import RuleTest
from src.stonix_resources.CommandHelper import CommandHelper
from src.stonix_resources.stonixutilityfunctions import setPerms, checkPerms
from src.stonix_resources.stonixutilityfunctions import readFile, writeFile
from src.stonix_resources.pkghelper import Pkghelper
from src.tests.lib.logdispatcher_mock import LogPriority
from src.stonix_resources.rules.SecureSquidProxy import SecureSquidProxy
from shutil import copyfile
import os
import re

class zzzTestRuleSecureSquidProxy(RuleTest):

    def setUp(self):
        RuleTest.setUp(self)
        self.rule = SecureSquidProxy(self.config,
                                        self.environ,
                                        self.logdispatch,
                                        self.statechglogger)
        self.rulename = self.rule.rulename
        self.rulenumber = self.rule.rulenumber
        self.ch = CommandHelper(self.logdispatch)
        self.ph = Pkghelper(self.logdispatch, self.environ)
        self.fileexisted = True

    def tearDown(self):
        pass

    def runTest(self):
        self.simpleRuleTest()

    def setConditionsForRule(self):
        '''Configure system for the unit test

        :param self: essential if you override this definition
        :returns: boolean - If successful True; If failure False
        @author: dwalker

        '''
        success = True
        if self.ph.check("squid"):
            if self.ph.manager == "apt-get":
                self.squidfile = "/etc/squid3/squid.conf"
            else:
                self.squidfile = "/etc/squid/squid.conf"
            self.backup = self.squidfile + ".original"
            self.data1 = {"ftp_passive": "on",
                          "ftp_sanitycheck": "on",
                          "check_hostnames": "on",
                          "request_header_max_size": "20 KB",
                          "reply_header_max_size": "20 KB",
                          "cache_effective_user": "squid",
                          "cache_effective_group": "squid",
                          "ignore_unknown_nameservers": "on",
                          "allow_underscore": "off",
                          "httpd_suppress_version_string": "on",
                          "forwarded_for": "off",
                          "log_mime_hdrs": "on",
                          "http_access": "deny to_localhost"}

            #make sure these aren't in the file
            self.denied = ["acl Safe_ports port 70",
                           "acl Safe_ports port 210",
                           "acl Safe_ports port 280",
                           "acl Safe_ports port 488",
                           "acl Safe_ports port 591",
                           "acl Safe_ports port 777"]
            if os.path.exists(self.squidfile):
                if checkPerms(self.squidfile, [0, 0, 420], self.logdispatch):
                    if not setPerms(self.squidfile, [0, 0, 416], self.logdispatch):
                        success = False
                copyfile(self.squidfile, self.backup)
                tempstring = ""
                contents = readFile(self.squidfile, self.logdispatch)
                if contents:
                    for line in contents:
                        if re.search("^ftp_passive", line.strip()):
                            '''Delete this line'''
                            continue
                        else:
                            tempstring += line
                '''insert line with incorrect value'''
                tempstring += "request_header_max_size 64 KB\n"
                '''insert line with no value'''
                tempstring += "ignore_unknown_nameservers\n"
                '''insert these two lines we don't want in there'''
                tempstring += "acl Safe_ports port 70\nacl Safe_ports port 210\n"
                if not writeFile(self.squidfile, tempstring, self.logdispatch):
                    success = False
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
        if not self.fileexisted:
            os.remove(self.path)
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

