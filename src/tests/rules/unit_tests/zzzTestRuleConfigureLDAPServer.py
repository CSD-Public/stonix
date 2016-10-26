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
from src.stonix_resources.pkghelper import Pkghelper

'''
Created on Sep 16, 2015

@author: dwalker
@change: 2016/02/10 roy Added sys.path.append for being able to unit test this
                        file as well as with the test harness.
'''
from __future__ import absolute_import
import unittest
import os
import re
import sys
import traceback
import glob

sys.path.append("../../../..")
from src.tests.lib.RuleTestTemplate import RuleTest
from src.stonix_resources.CommandHelper import CommandHelper
from src.tests.lib.logdispatcher_mock import LogPriority
from src.stonix_resources.rules.ConfigureLDAPServer import ConfigureLDAPServer
from src.stonix_resources import pkghelper
from src.stonix_resources.stonixutilityfunctions import setPerms


class zzzTestRuleConfigureLDAPServer(RuleTest):

    def setUp(self):
        RuleTest.setUp(self)
        self.rule = ConfigureLDAPServer(self.config, self.environ,
                                        self.logdispatch, self.statechglogger)
        self.rulename = self.rule.rulename
        self.rulenumber = self.rule.rulenumber
        self.ch = CommandHelper(self.logdispatch)
        self.logger = self.logdispatch

    def tearDown(self):
        pass

    def runTest(self):
        self.simpleRuleTest()

    def setConditionsForRule(self):
        '''
        Configure system for the unit test
        @param self: essential if you override this definition
        @return: boolean - If successful True; If failure False
        @author: dwalker
        '''
        success = True
        self.ph = Pkghelper(self.logger, self.environ)
        if self.ph.manager == "apt-get":
            self.ldap = "slapd"
        elif self.ph.manager == "zypper":
            self.ldap = "openldap2"
        else:
            self.ldap = "openldap-servers"
        if self.ph.check(self.ldap):
            slapd = "/etc/openldap/slapd.conf"
            if os.path.exists(slapd):
                if not setPerms(slapd, [0, 0, 511], self.logger):
                    success = False

            slapdd = "/etc/openldap/slapd.d/"
            if os.path.exists(slapdd):
                dirs = glob.glob(slapdd + "*")
                for loc in dirs:
                    if not os.path.isdir(loc):
                        if not setPerms(loc, [0, 0, 511], self.logger):
                            success = False

            cnconfig = "/etc/openldap/slapd.d/cn=config/"
            if os.path.exists(cnconfig):
                dirs = glob.glob(cnconfig + "*")
                for loc in dirs:
                    if not os.path.isdir(loc):
                        if not setPerms(loc, [0, 0, 511], self.logger):
                            success = False

            pki = "/etc/pki/tls/ldap/"
            if os.path.exists(pki):
                dirs = glob.glob(pki + "*")
                for loc in dirs:
                    if not os.path.isdir():
                        if not setPerms(loc, [0, 0, 511], self.logger):
                            success = False

            if os.path.exists("/etc/pki/tls/CA/"):
                dirs = glob.glob("/etc/pki/tls/CA/*")
                for loc in dirs:
                    if not os.path.isdir():
                        if not setPerms(loc, [0, 0, 511], self.logger):
                            success = False
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
        @return: boolean - If successful True; If failure False
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
        @return: boolean - If successful True; If failure False
        @author: ekkehard j. koch
        '''
        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " + \
                             str(pRuleSuccess) + ".")
        success = True
        return success
