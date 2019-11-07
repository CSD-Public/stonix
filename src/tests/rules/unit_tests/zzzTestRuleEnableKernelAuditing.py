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
This is a Unit Test for Rule EnableKernelAuditing

@author: Breen Malmberg
@change: 2016/02/10 roy Added sys.path.append for being able to unit test this
                        file as well as with the test harness.
@change: 2017/10/23 rsn - removed unused service helper
'''

import unittest
import re
import os
import sys

sys.path.append("../../../..")
from src.tests.lib.RuleTestTemplate import RuleTest
from src.stonix_resources.CommandHelper import CommandHelper
from src.tests.lib.logdispatcher_mock import LogPriority
from src.stonix_resources.rules.EnableKernelAuditing import EnableKernelAuditing


class zzzTestRuleEnableKernelAuditing(RuleTest):

    def setUp(self):
        RuleTest.setUp(self)
        self.rule = EnableKernelAuditing(self.config,
                                    self.environ,
                                    self.logdispatch,
                                    self.statechglogger)
        self.rulename = self.rule.rulename
        self.rulenumber = self.rule.rulenumber
        self.ch = CommandHelper(self.logdispatch)

    def tearDown(self):
        # restore backups of original files, made before testing
#         if self.environ.getosfamily() == 'darwin':
#             auditcontrolbak = '/etc/security/audit_control.stonixbak'
#             audituserbak = '/etc/security/audit_user.stonixbak'
#             if os.path.exists(auditcontrolbak):
#                 os.rename(auditcontrolbak, '/etc/security/audit_control')
#             if os.path.exists(audituserbak):
#                 os.rename(audituserbak, '/etc/security/audit_user')
#         else:
#             auditdbaks =['/etc/audit/auditd.conf.stonixbak', '/etc/auditd.conf.stonixbak'] 
#             auditrulesbaks = ['/etc/audit/audit.rules.stonixbak', '/etc/audit/rules.d/audit.rules.stonixbak']
#             for bak in auditdbaks:
#                 if os.path.exists(bak):
#                     os.rename(bak, bak[:-10])
#             for bak in auditrulesbaks:
#                 if os.path.exists(bak):
#                     os.rename(bak, bak[:-10])
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
# 
#         # make backups of any original files, before testing
#         if self.environ.getosfamily() == 'darwin':
#             if os.path.exists('/etc/security/audit_control'):
#                 os.rename('/etc/security/audit_control', '/etc/security/audit_control.stonixbak')
#             if os.path.exists('/etc/security/audit_user'):
#                 os.rename('/etc/security/audit_user', '/etc/security/audit_user.stonixbak')
#         else:
#             auditdpaths = ['/etc/audit/auditd.conf', '/etc/auditd.conf']
#             for path in auditdpaths:
#                 if os.path.exists(path):
#                     os.rename(path, path + '.stonixbak')
#             if os.path.exists('/etc/audisp/audispd.conf'):
#                 os.rename('/etc/audisp/audispd.conf', '/etc/audisp/audispd.conf.stonixbak')
#             auditruleslocs = ['/etc/audit/audit.rules', '/etc/audit/rules.d/audit.rules']
#             for loc in auditruleslocs:
#                 if os.path.exists(loc):
#                     os.rename(loc, loc + '.stonixbak')
        return success

    def test_freqci_in_range(self):
        '''test if the frequency ci value is within range
        
        @author: Breen Malmberg


        '''

        allowable_freq_range = list(range(1,100))
        self.assertTrue(self.rule.freqci.getcurrvalue() in allowable_freq_range)

    def test_flushtype_valid(self):
        '''test if the flush type ci value is a valid flush type
        
        @author: Breen Malmberg


        '''

        allowable_flush_types = ['data', 'incremental', 'sync']
        self.assertTrue(self.rule.flushtypeci.getcurrvalue() in allowable_flush_types)

    def test_get_system_arch(self):
        '''test the command to get the system arch
        @author: Breen Malmberg


        '''

        found = False

        self.ch.executeCommand('/usr/bin/uname -m')
        self.assertEqual(0, self.ch.getReturnCode())
        outputlines = self.ch.getOutput()
        self.assertFalse(outputlines == '')
        for line in outputlines:
            if re.search('^x86\_64', line):
                found = True
        for line in outputlines:
            if re.search('^x86', line):
                found = True
        self.assertEqual(found, True)

    def test_get_suid_files(self):
        '''test the command to find suid files
        @author: Breen Malmberg


        '''

        self.ch.executeCommand('/usr/bin/find / -xdev -type f -perm -4000 -o -type f -perm -2000')
        self.assertEqual(0, self.ch.getReturnCode())

    def test_release_file_exists(self):
        '''does at least one of the release file paths that the code relies on exist?
        linux-only
        @author: Breen Malmberg


        '''

        if self.environ.getosfamily() == 'darwin':
            return True

        found = False

        releasefilelocs = ['/etc/os-release', '/etc/redhat-release']
        for loc in releasefilelocs:
            if os.path.exists(loc):
                found = True
        self.assertEqual(found, True)

    def test_grub_cfg_file_exists(self):
        '''does at least one of the grub config file paths that the code relies on exist?
        linux-only
        @author: Breen Malmberg


        '''

        if self.environ.getosfamily() == 'darwin':
            return True

        found = False

        grubcfglocs = ['/boot/grub/grub.conf', '/etc/default/grub']
        for loc in grubcfglocs:
            if os.path.exists(loc):
                found = True
        self.assertEqual(found, True)

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
