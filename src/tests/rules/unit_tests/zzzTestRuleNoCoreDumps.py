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
This is a Unit Test for Rule NoCoreDumps

@author: ekkehard j. koch
@change: 03/18/2013 Original Implementation
@change: 2016/02/10 roy Added sys.path.append for being able to unit test this
                        file as well as with the test harness.
@change: 2016/09/09 eball Added self.checkUndo = True
@change: 2019/01/30 dwalker - updated setConditionsForRule method to
    take out desired contents from file and to make permissions incorrect.
'''
from __future__ import absolute_import
import unittest
import sys
import os
import re

sys.path.append("../../../..")
from src.tests.lib.RuleTestTemplate import RuleTest
from src.tests.lib.logdispatcher_mock import LogPriority
from src.stonix_resources.rules.NoCoreDumps import NoCoreDumps
from src.stonix_resources.stonixutilityfunctions import readFile, writeFile, checkPerms, setPerms
from src.stonix_resources.CommandHelper import CommandHelper


class zzzTestRuleNoCoreDumps(RuleTest):

    def setUp(self):
        RuleTest.setUp(self)
        self.rule = NoCoreDumps(self.config,
                                self.environ,
                                self.logdispatch,
                                self.statechglogger)
        self.logger = self.logdispatch
        self.rulename = self.rule.rulename
        self.rulenumber = self.rule.rulenumber
        self.checkUndo = True
        self.ch = CommandHelper(self.logger)
    def tearDown(self):
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
        if self.environ.getosfamily() == "linux":
            if not self.setLinuxConditions():
                success = False
        elif self.environ.getostype() == "mac":
            if not self.setMacConditions():
                success = False
        return success

    def setMacConditions(self):
        success = True
        self.ch.executeCommand("/usr/bin/launchctl limit core")
        retcode = self.ch.getReturnCode()
        if retcode != 0:
            self.detailedresults += "\nFailed to run launchctl command to get current value of core dumps configuration"
            errmsg = self.ch.getErrorString()
            self.logger.log(LogPriority.DEBUG, errmsg)
        else:
            output = self.ch.getOutputString()
            if output:
                if not re.search("1", output):
                    self.ch.executeCommand("/usr/bin/launchctl limit core 1 1")

    def setLinuxConditions(self):
        success = True
        path1 = "/etc/security/limits.conf"
        if os.path.exists(path1):
            lookfor1 = "(^\*)\s+hard\s+core\s+0?"
            contents = readFile(path1, self.logger)
            if contents:
                tempstring = ""
                for line in contents:
                    if not re.search(lookfor1, line.strip()):
                        tempstring += line
                if not writeFile(path1, tempstring, self.logger):
                    debug = "unable to write incorrect contents to " + path1 + "\n"
                    self.logger.log(LogPriority.DEBUG, debug)
                    success = False
            if checkPerms(path1, [0, 0, 0o644], self.logger):
                if not setPerms(path1, [0, 0, 0o777], self.logger):
                    debug = "Unable to set incorrect permissions on " + path1 + "\n"
                    self.logger.log(LogPriority.DEBUG, debug)
                    success = False
                else:
                    debug = "successfully set incorrect permissions on " + path1 + "\n"
                    self.logger.log(LogPriority.DEBUG, debug)

        self.ch.executeCommand("/sbin/sysctl fs.suid_dumpable")
        retcode = self.ch.getReturnCode()

        if retcode != 0:
            self.detailedresults += "Failed to get value of core dumps configuration with sysctl command\n"
            errmsg = self.ch.getErrorString()
            self.logger.log(LogPriority.DEBUG, errmsg)
            success = False
        else:
            output = self.ch.getOutputString()
            if output.strip() != "fs.suid_dumpable = 1":
                if not self.ch.executeCommand("/sbin/sysctl -w fs.suid_dumpable=1"):
                    debug = "Unable to set incorrect value for fs.suid_dumpable"
                    self.logger.log(LogPriority.DEBUG, debug)
                    success = False
                elif not self.ch.executeCommand("/sbin/sysctl -p"):
                    debug = "Unable to set incorrect value for fs.suid_dumpable"
                    self.logger.log(LogPriority.DEBUG, debug)
                    success = False
        profile = ""
        if os.path.exists("/etc/profile.d"):
            profile = "/etc/profile.d/stonix_no_core_dumps.sh"
            if not os.path.exists(profile):
                profile = ""
        elif os.path.exists("/etc/profile"):
            profile = "/etc/profile"
        if profile:
            contents = readFile(profile, self.logger)
            tempstring = ""
            found = False
            for line in contents:
                if not re.search("^ulimit\s+\-S\s+\-c\s+1", line.strip()):
                    tempstring += line
                else:
                    found = True
            if found:
                tempstring += "ulimit -S -c 0\n"
                if not writeFile(profile, tempstring, self.logger):
                    debug = "Unable to write incorrect contents to " + profile + "\n"
                    self.logger.log(LogPriority.DEBUG, debug)
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

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
