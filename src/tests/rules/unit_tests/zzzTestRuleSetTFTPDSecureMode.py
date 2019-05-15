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
This is a Unit Test for Rule SetTFTPD
Created on Jun 8, 2016

@author: dwalker
'''

from __future__ import absolute_import
import unittest
import sys

sys.path.append("../../../..")
from src.tests.lib.RuleTestTemplate import RuleTest
from src.stonix_resources.CommandHelper import CommandHelper
from src.tests.lib.logdispatcher_mock import LogPriority
from src.stonix_resources.pkghelper import Pkghelper
from src.stonix_resources.stonixutilityfunctions import readFile, setPerms
from src.stonix_resources.stonixutilityfunctions import checkPerms, writeFile
from src.stonix_resources.rules.SetTFTPDSecureMode import SetTFTPDSecureMode
import os, re

class zzzTestRuleSetTFTPDSecureMode(RuleTest):

    def setUp(self):
        RuleTest.setUp(self)
        self.rule = SetTFTPDSecureMode(self.config,
                                        self.environ,
                                        self.logdispatch,
                                        self.statechglogger)
        self.logger = self.logdispatch
        self.rulename = self.rule.rulename
        self.rulenumber = self.rule.rulenumber
        self.ch = CommandHelper(self.logdispatch)

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
        if not self.environ.getostype() == "Mac OS X":
            self.ph = Pkghelper(self.logger, self.environ)
            if self.ph.manager == "apt-get":
                self.tftpfile = "/etc/default/tftpd-hpa"
                tmpfile = self.tftpfile + ".tmp"
                if os.path.exists(self.tftpfile):
                    contents = readFile(self.tftpfile, self.logger)
                    tempstring = ""
                    for line in contents:
                        '''Take TFTP_OPTIONS line out of file'''
                        if re.search("TFTP_OPTIONS", line.strip()):
                            continue
                        elif re.search("TFTP_DIRECTORY", line.strip()):
                            tempstring += 'TFTP_DIRECTORY="/var/lib/tftpbad"'
                            continue
                        else:
                            tempstring += line
                    if not writeFile(tmpfile, tempstring, self.logger):
                        success = False
                    else:
                        os.rename(tmpfile, self.tftpfile)
                        os.chown(self.tftpfile, 0, 0)
                        os.chmod(self.tftpfile, 400)
            else:
                #if server_args line found, remove to make non-compliant
                self.tftpfile = "/etc/xinetd.d/tftp"
                tftpoptions, contents2 = [], []
                if os.path.exists(self.tftpfile):
                    i = 0
                    contents = readFile(self.tftpfile, self.logger)
                    if checkPerms(self.tftpfile, [0, 0, 420], self.logger):
                        setPerms(self.tftpfile, [0, 0, 400], self.logger)  
                    try:
                        for line in contents:
                            if re.search("service tftp", line.strip()):
                                contents2 = contents[i+1:]
                            else:
                                i += 1
                    except IndexError:
                        pass
                    if contents2:
                        if contents2[0].strip() == "{":
                            del(contents2[0])
                        if contents2:
                            i = 0
                            while i <= len(contents2) and contents2[i].strip() != "}" and contents2[i].strip() != "{":
                                tftpoptions.append(contents2[i])
                                i += 1
                            if tftpoptions:
                                for line in tftpoptions:
                                    if re.search("server_args", line):
                                        contents.remove(line)
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

