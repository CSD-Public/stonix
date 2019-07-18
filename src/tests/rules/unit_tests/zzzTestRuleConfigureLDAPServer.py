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


from src.stonix_resources.pkghelper import Pkghelper

'''
Created on Sep 16, 2015

@author: dwalker
@change: 2016/02/10 roy Added sys.path.append for being able to unit test this
                        file as well as with the test harness.
'''

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
        '''Configure system for the unit test

        :param self: essential if you override this definition
        :returns: boolean - If successful True; If failure False
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
