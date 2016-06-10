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
This is a Unit Test for Rule RestrictMounting

@author: Eric Ball
@change: 07/07/2015 Original Implementation
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
from src.stonix_resources.rules.RestrictMounting import RestrictMounting
from src.stonix_resources.pkghelper import Pkghelper
from src.stonix_resources.ServiceHelper import ServiceHelper


class zzzTestRuleRestrictMounting(RuleTest):

    def setUp(self):
        RuleTest.setUp(self)
        self.rule = RestrictMounting(self.config, self.environ,
                                     self.logdispatch, self.statechglogger)
        self.rulename = self.rule.rulename
        self.rulenumber = self.rule.rulenumber
        self.ch = CommandHelper(self.logdispatch)
        self.ph = Pkghelper(self.logdispatch, self.environ)
        self.sh = ServiceHelper(self.environ, self.logdispatch)
        self.setConditionsForRule()

        # Enable CIs
        datatype = "bool"
        key = "RESTRICTCONSOLEACCESS"
        instructions = "Unit test"
        default = True
        self.rule.consoleCi = self.rule.initCi(datatype, key, instructions,
                                               default)
        key = "DISABLEAUTOFS"
        self.rule.autofsCi = self.rule.initCi(datatype, key, instructions,
                                              default)
        key = "DISABLEGNOMEAUTOMOUNT"
        self.rule.gnomeCi = self.rule.initCi(datatype, key, instructions,
                                             default)

        self.path1 = "/etc/security/console.perms.d/50-default.perms"
        self.path2 = "/etc/security/console.perms"
        self.data1 = ["<floppy>=/dev/fd[0-1]* \\",
                      "<scanner>=/dev/scanner* /dev/usb/scanner*",
                      "<flash>=/mnt/flash* /dev/flash*",
                      "# permission definitions",
                      "<console>  0660 <floppy>     0660 root.floppy",
                      "<console>  0600 <scanner>    0600 root",
                      "<console>  0600 <flash>      0600 root.disk\n"]
        self.data2 = ["<console>=tty[0-9][0-9]* vc/[0-9][0-9]* :[0-9]+\.[0-9]+ :[0-9]+",
                      "<xconsole>=:[0-9]+\.[0-9]+ :[0-9]+\n"]
        if os.path.exists(self.path1):
            self.tmpfile1 = self.path1 + ".tmp"
            os.rename(self.path1, self.tmpfile1)
            try:
                defaultPermsFile = open(self.path1, "w")
            except IOError:
                debug = "Could not open file " + self.path1 + "\n"
                self.logger.log(LogPriority.DEBUG, debug)
            try:
                defaultPermsFile.writelines(self.data1)
            except IOError:
                debug = "Could not write to file " + self.path1 + "\n"
                self.logger.log(LogPriority.DEBUG, debug)
        if os.path.exists(self.path2):
            self.tmpfile2 = self.path2 + ".tmp"
            os.rename(self.path2, self.tmpfile2)
            try:
                permsFile = open(self.path2, "w")
            except IOError:
                debug = "Could not open file " + self.path2 + "\n"
                self.logger.log(LogPriority.DEBUG, debug)
            try:
                permsFile.writelines(self.data2)
            except IOError:
                debug = "Could not write to file " + self.path2 + "\n"
                self.logger.log(LogPriority.DEBUG, debug)

        # If autofs is installed, enable and start it. If it is not
        # installed, it will not be tested.
        if self.ph.check("autofs"):
            if not self.sh.enableservice("autofs"):
                debug = "Could not enable autofs\n"
                self.logger.log(LogPriority.DEBUG, debug)

        cmd = ["gconftool-2", "--direct", "--config-source",
               "xml:readwrite:/etc/gconf/gconf.xml.mandatory",
               "--type", "bool", "--set",
               "/desktop/gnome/volume_manager/automount_media",
               "true"]
        cmdSuccess = self.ch.executeCommand(cmd)
        cmd = ["gconftool-2", "--direct", "--config-source",
               "xml:readwrite:/etc/gconf/gconf.xml.mandatory",
               "--type", "bool", "--set",
               "/desktop/gnome/volume_manager/automount_drives",
               "true"]
        cmdSuccess &= self.ch.executeCommand(cmd)

    def tearDown(self):
        # Cleanup: put original perms files back
        if os.path.exists(self.path1) and os.path.exists(self.tmpfile1):
            os.remove(self.path1)
            os.rename(self.tmpfile1, self.path1)
        if os.path.exists(self.path2) and os.path.exists(self.tmpfile2):
            os.remove(self.path2)
            os.rename(self.tmpfile2, self.path2)

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

        return success

    def testFixAndUndo(self):
        self.assertFalse(self.rule.report(), "Report was compliant before " +
                         "the fix ran")
        originalResults = self.rule.detailedresults
        self.assertTrue(self.rule.fix(), "Fix was not successful")
        self.assertTrue(self.rule.report(), "Rule is NCAF")
        self.assertTrue(self.rule.undo(), "Undo was not successful")
        self.assertFalse(self.rule.report(), "Report is still compliant " +
                         "after undo")
        self.assertEqual(originalResults, self.rule.detailedresults,
                         "Report results are not the same after undo as " +
                         "they were before fix.\nOriginal: " + originalResults +
                         "\nPost-undo results: " + self.rule.detailedresults)

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
