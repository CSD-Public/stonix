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
This is a Unit Test for Rule DisableGUILogon

@author: Eric Ball
@change: 07/20/2015 Original Implementation
'''
from __future__ import absolute_import
import unittest
import os
import re
from stonix_resources.stonixutilityfunctions import readFile, writeFile
from stonix_resources.RuleTestTemplate import RuleTest
from stonix_resources.CommandHelper import CommandHelper
from stonix_resources.logdispatcher import LogPriority
from stonix_resources.rules.DisableGUILogon import DisableGUILogon
from stonix_resources.pkghelper import Pkghelper
from stonix_resources.ServiceHelper import ServiceHelper


class zzzTestRuleDisableGUILogon(RuleTest):

    def setUp(self):
        RuleTest.setUp(self)
        self.rule = DisableGUILogon(self.config, self.environ,
                                     self.logdispatch, self.statechglogger)
        self.rulename = self.rule.rulename
        self.rulenumber = self.rule.rulenumber
        self.ch = CommandHelper(self.logdispatch)
        self.ph = Pkghelper(self.logdispatch, self.environ)
        self.sh = ServiceHelper(self.environ, self.logdispatch)

    def tearDown(self):
        pass

    def runTest(self):
        self.simpleRuleTest()

    def setConditionsForRule(self):
        '''
        Configure system for the unit test
        @param self: essential if you override this definition
        @return: boolean - If successful True; If failure False
        @author: Eric Ball
        '''
        success = True
        # Enable CIs
        self.rule.ci1.updatecurrvalue(True)
        self.rule.ci2.updatecurrvalue(True)
        self.rule.ci3.updatecurrvalue(True)
        
        # Ensure GUI logon is enabled
        self.myos = self.environ.getostype().lower()
        if os.path.exists("/bin/systemctl"):
            cmd = ["systemctl", "set-default", "graphical.target"]
            if not self.ch.executeCommand(cmd):
                success = False
        elif re.search("debian", self.myos):
            if not self.sh.enableservice("gdm3"):
                if not self.sh.enableservice("gdm"):
                    if not self.sh.enableservice("kdm"):
                        if not self.sh.enableservice("xdm"):
                            if not self.sh.enableservice("lightdm"):
                                success = False
        elif re.search("ubuntu", self.myos):
            ldmover = "/etc/init/lightdm.override"
            grub = "/etc/default/grub"
            
        else:
            self.initver = "inittab"
            compliant, results = self.reportInittab()
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
        # Cleanup: put original perms files back
        if os.path.exists(self.path1) and os.path.exists(self.tmpfile1):
            os.remove(self.path1)
            os.rename(self.tmpfile1, self.path1)
        if os.path.exists(self.path2) and os.path.exists(self.tmpfile2):
            os.remove(self.path2)
            os.rename(self.tmpfile2, self.path2)
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
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
