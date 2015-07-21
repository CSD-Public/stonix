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
import traceback
from stonix_resources.RuleTestTemplate import RuleTest
from stonix_resources.CommandHelper import CommandHelper
from stonix_resources.logdispatcher import LogPriority
from stonix_resources.rules.DisableGUILogon import DisableGUILogon
from stonix_resources.ServiceHelper import ServiceHelper
from stonix_resources.KVEditorStonix import KVEditorStonix


class zzzTestRuleDisableGUILogon(RuleTest):

    def setUp(self):
        RuleTest.setUp(self)
        self.rule = DisableGUILogon(self.config, self.environ,
                                    self.logdispatch, self.statechglogger)
        self.rulename = self.rule.rulename
        self.rulenumber = self.rule.rulenumber
        self.ch = CommandHelper(self.logdispatch)
        self.sh = ServiceHelper(self.environ, self.logdispatch)
        self.inittab = False

    def tearDown(self):
        if self.inittab:
            tmppath = self.inittab + ".utmp"
            try:
                os.rename(tmppath, self.inittab)
            except Exception:
                self.logdispatch.log(LogPriority.ERROR, traceback.format_exc())

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
        # CI 3 is REMOVEX, which will remove X Windows entirely. STONIX unit
        # tests should generally only be run in virtual environments anyway,
        # but due to the severity of the changes caused by this rule, it is
        # disabled by default. To enable, simply set it to True instead.
        self.rule.ci3.updatecurrvalue(False)
        
        # Ensure GUI logon is enabled
        self.myos = self.environ.getostype().lower()
        self.logdispatch.log(LogPriority.DEBUG, self.myos)
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
            if os.path.exists(ldmover):
                if not os.remove(ldmover):
                    success = False
            if os.path.exists(grub):
                tmppath = grub + ".tmp"
                data = {"GRUB_CMDLINE_LINUX_DEFAULT": '"quiet splash"'}
                editor = KVEditorStonix(self.statechglogger, self.logdispatch,
                                        "conf", grub, tmppath, data,
                                        "present", "closedeq")
                editor.report()
                if editor.fixables:
                    if editor.fix():
                        if not editor.commit():
                            success = False
                    else:
                        success = False
        else:
            self.inittab = "/etc/inittab"
            if os.path.exists(self.inittab):
                tmppath = self.inittab + ".utmp"
                try:
                    os.rename(self.inittab, tmppath)
                    open(self.inittab, "w").write("id:5:initdefault:")
                except Exception:
                    success = False
                    self.logdispatch.log(LogPriority.ERROR,
                                         traceback.format_exc())
            else:
                self.logdispatch.log(LogPriority.ERROR, self.inittab +
                                     " not found, init system unknown")
                self.inittab = False
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
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
