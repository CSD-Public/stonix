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
@change: 2016/02/10 roy Added sys.path.append for being able to unit test this
                        file as well as with the test harness.
'''
from __future__ import absolute_import
import unittest
import os
import sys

sys.path.append("../../../..")
from src.tests.lib.RuleTestTemplate import RuleTest
from src.stonix_resources.CommandHelper import CommandHelper
from src.tests.lib.logdispatcher_mock import LogPriority
from src.stonix_resources.rules.EnableKernelAuditing import EnableKernelAuditing


class zzzTestRuleConsoleRootOnly(RuleTest):

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
        '''
        Configure system for the unit test
        @param self: essential if you override this definition
        @return: boolean - If successful True; If failure False
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

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
