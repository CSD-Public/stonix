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
This is a Unit Test for Rule SecureSSH

@author: ekkehard j. koch
@change: 03/18/2013 Original Implementation
@change: 2016/02/10 roy Added sys.path.append for being able to unit test this
                        file as well as with the test harness.
@change: 2019/06/11 dwalker - updated unit test to set preconditions
    system fuzzing
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
from src.stonix_resources.rules.SecureSSH import SecureSSH
from src.stonix_resources.stonixutilityfunctions import createFile, checkPerms, setPerms
from src.stonix_resources.KVEditorStonix import KVEditorStonix


class zzzTestRuleSecureSSH(RuleTest):

    def setUp(self):
        RuleTest.setUp(self)
        self.rule = SecureSSH(self.config,
                              self.environ,
                              self.logdispatch,
                              self.statechglogger)
        self.logger = self.logdispatch
        self.rulename = self.rule.rulename
        self.rulenumber = self.rule.rulenumber
        self.ch = CommandHelper(self.logdispatch)
        self.checkUndo = True

        self.client = {"Host": "*",
                       "Protocol": "2",
                       "GSSAPIAuthentication": "yes",
                       "GSSAPIDelegateCredentials": "yes"}
        # This dictionary intentionally contains the incorrect values for each key
        # to fuzz the file
        self.server = {"Protocol": "4",
                       "SyslogFacility": "AUTHPRIVY",
                       "PermitRootLogin": "yes",
                       "MaxAuthTries": "4",
                       "RhostsRSAAuthentication": "yes",
                       "HostbasedAuthentication": "yes",
                       "IgnoreRhosts": "no",
                       "PermitEmptyPasswords": "yes",
                       "PasswordAuthentication": "no",
                       "ChallengeResponseAuthentication": "no",
                       "KerberosAuthentication": "no",
                       "GSSAPIAuthentication": "no",
                       "GSSAPICleanupCredentials": "no",
                       "UsePAM": "no",
                       "Ciphers": "aes128-ctrs,aes192-ctrs,aes256-ctrs,aes128-cbcs,3des-cbcs,aes192-cbcs,aes256-cbcs",
                       "PermitUserEnvironment": "yes"}


    def tearDown(self):
        pass

    def runTest(self):
        self.simpleRuleTest()

    def setConditionsForRule(self):
        '''Configure system for the unit test
        Intentionally fuzz certain files, turn off certain services, etc.

        :param self: essential if you override this definition
        :returns: boolean - If successful True; If failure False
        @author: dwalker

        '''
        success = True
        if self.environ.getostype() == "Mac OS X":
            self.serverfile = '/private/etc/ssh/sshd_config'
            self.clientfile = '/private/etc/ssh/ssh_config'
            if self.rule.mac_piv_auth_CI.getcurrvalue():
                self.server["ChallengeResponseAuthentication"] = "yes"
                self.server["PasswordAuthentication"] = "yes"
        else:
            self.serverfile = "/etc/ssh/sshd_config"  # server file
            self.clientfile = "/etc/ssh/ssh_config"  # client file
        if not self.setCommonConditions(self.serverfile, self.server):
            success = False
        if not self.setCommonConditions(self.clientfile, self.client):
            success = False
        return success

    def setCommonConditions(self, sshfile, directives):
        '''Common system pre condition setting

        :param self: essential if you override this definition
        :param sshfile: ssh file to be fuzzed
        :param directives: intentionally incorrect directives to fuzz file with
        :returns: boolean - If successful True; If failure False
        @author: dwalker

        '''
        # In this method, unlike the methods inside the rule, we don't
        # need a portion for Ubuntu to make sure directives aren't present
        # because we can put those directives in the file(s) to fuzz them
        success = True
        directives = dict(directives)
        tpath = sshfile + ".tmp"
        if not os.path.exists(sshfile):
            if not createFile(sshfile, self.logger):
                success = False
                debug = "Unable to create " + sshfile + " for setting " + \
                    "pre-conditions"
                self.logger.log(LogPriority.DEBUG, debug)
                return False
        editor = KVEditorStonix(self.statechglogger,
                                self.logger, "conf",
                                sshfile, tpath,
                                directives, "present",
                                "space")
        if not editor.report():
            if not editor.fix():
                success = False
                debug = "Kveditor fix for file " + sshfile + " not successful"
                self.logger.log(LogPriority.DEBUG, debug)
            elif not editor.commit():
                success = False
                debug = "Kveditor commit for file " + sshfile + " not successful"
                self.logger.log(LogPriority.DEBUG, debug)
        if checkPerms(sshfile, [0, 0, 0o755], self.logger):
            if not setPerms(sshfile, [0, 0, 0o755], self.logger):
                success = False
                debug = "Unable to set incorrect permissions on " + \
                    sshfile + " for setting pre-conditions"
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
