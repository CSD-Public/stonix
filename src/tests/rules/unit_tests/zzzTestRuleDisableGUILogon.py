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
@change: 2015/07/20 eball - Original Implementation
@change: 2015/09/21 eball - Removed file backup and added undo() to tearDown
@change: 2015/10/26 eball - Added feedback to inform user about expected
    failure, and changed how ci3 is handled. Removed disabling of ci3, so that
    a custom stonix.conf can make this True.
@change: 2016/02/10 roy Added sys.path.append for being able to unit test this
                        file as well as with the test harness.
@change: 2016/07/06 eball Bypassed simpleRuleTest, since this will always be
    false due to keeping REMOVEX CI disabled.
@change: 2016/07/22 eball Added destructive testing
@change: 2017/10/23 rsn - change to new service helper interface
'''
from __future__ import absolute_import
import unittest
import os
import re
import sys

sys.path.append("../../../..")
from src.tests.lib.RuleTestTemplate import RuleTest
from src.stonix_resources.CommandHelper import CommandHelper
from src.tests.lib.logdispatcher_mock import LogPriority
from src.stonix_resources.rules.DisableGUILogon import DisableGUILogon
from src.stonix_resources.pkghelper import Pkghelper
from src.stonix_resources.ServiceHelper import ServiceHelper
from src.stonix_resources.KVEditorStonix import KVEditorStonix


class zzzTestRuleDisableGUILogon(RuleTest):

    def setUp(self):
        RuleTest.setUp(self)
        self.rule = DisableGUILogon(self.config, self.environ,
                                    self.logdispatch, self.statechglogger)
        self.rulename = self.rule.rulename
        self.rulenumber = self.rule.rulenumber
        self.ch = CommandHelper(self.logdispatch)
        self.sh = ServiceHelper(self.environ, self.logdispatch)
        self.destructive = self.runDestructive()
        self.ph = Pkghelper(self.logdispatch, self.environ)
        self.serviceTarget=""
        # The checkPackages list can be expanded if important packages are
        # found to be removed by REMOVEX fix
        checkPackages = ["dbus-x11", "gdm", "gdm3"]
        self.reinstall = []
        for pkg in checkPackages:
            if self.ph.check(pkg):
                self.reinstall.append(pkg)

    def tearDown(self):
        self.rule.undo()
        # Some packages may need to be reinstalled, since the REMOVEX fix
        # cannot be undone.
        for pkg in self.reinstall:
            self.ph.install(pkg)

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
        # CI 3 is REMOVEX, which will remove X Windows entirely.
        if self.destructive:
            self.rule.ci3.updatecurrvalue(True)

        # Ensure GUI logon is enabled
        self.myos = self.environ.getostype().lower()
        self.logdispatch.log(LogPriority.DEBUG, self.myos)
        if os.path.exists("/bin/systemctl"):
            cmd = ["systemctl", "set-default", "graphical.target"]
            if not self.ch.executeCommand(cmd):
                success = False
        elif re.search("debian", self.myos):
            if not self.sh.auditService("gdm3", serviceTarget=self.serviceTarget) and \
               not self.sh.enableService("gdm3", serviceTarget=self.serviceTarget):
                if not self.sh.auditService("gdm", serviceTarget=self.serviceTarget) and \
                   not self.sh.enableService("gdm", serviceTarget=self.serviceTarget):
                    if not self.sh.auditService("kdm", serviceTarget=self.serviceTarget) and \
                       not self.sh.enableService("kdm", serviceTarget=self.serviceTarget):
                        if not self.sh.auditService("xdm", serviceTarget=self.serviceTarget) and \
                           not self.sh.enableService("xdm", serviceTarget=self.serviceTarget):
                            if not self.sh.auditService("lightdm", serviceTarget=self.serviceTarget) and \
                               not self.sh.enableService("lightdm", serviceTarget=self.serviceTarget):
                                success = False
                                self.logdispatch.log(LogPriority.DEBUG,
                                                     "Could not find an " +
                                                     "active DM")
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
            inittab = "/etc/inittab"
            if not os.path.exists(inittab):
                self.logdispatch.log(LogPriority.ERROR, inittab +
                                     " not found, init system unknown")
                success = False
        return success

    def testRule(self):
        self.assertTrue(self.setConditionsForRule(),
                        "setConditionsForRule was not successful")
        self.rule.report()
        self.assertTrue(self.rule.fix(), "DisableGUILogon.fix failed")
        self.rule.report()
        # This test does not attempt to remove the core X11 components, so this
        # result can be considered a false positive and removed.
        if not self.destructive:
            results = re.sub("Core X11 components are present\n", "",
                             self.rule.detailedresults)
            splitresults = results.splitlines()
            # Results will always have a header line, which can be removed. If
            # the results consist only of the header line, we will consider the
            # test to be compliant
            if len(splitresults) > 1:
                # Remove header line
                results = "\n".join(splitresults[1:])
                self.assertFalse(re.search(r"[^\s]", results),
                                 "After running DisableGUILogon.fix, the " +
                                 "following issues were present: " + results)


if __name__ == "__main__":
    unittest.main()
