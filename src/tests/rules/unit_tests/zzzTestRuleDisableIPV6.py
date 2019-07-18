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
This is a Unit Test for Rule ConfigureAppleSoftwareUpdate

@author: ekkehard j. koch
@change: 03/18/2013 Original Implementation
@change: 2016/02/10 roy Added sys.path.append for being able to unit test this
                        file as well as with the test harness.
@change: 2019/06/05 dwalker - Add set conditions portion to fuzz up rule for
    testing
'''

import unittest
import sys
import os
import re
import glob

sys.path.append("../../../..")
from src.tests.lib.RuleTestTemplate import RuleTest
from src.stonix_resources.CommandHelper import CommandHelper
from src.tests.lib.logdispatcher_mock import LogPriority
from src.stonix_resources.rules.DisableIPV6 import DisableIPV6
from src.stonix_resources.pkghelper import Pkghelper
from src.stonix_resources.stonixutilityfunctions import readFile, writeFile
from src.stonix_resources.KVEditorStonix import KVEditorStonix


class zzzTestRuleDisableIPV6(RuleTest):

    def setUp(self):
        RuleTest.setUp(self)
        self.rule = DisableIPV6(self.config,
                                self.environ,
                                self.logdispatch,
                                self.statechglogger)
        self.logger = self.logdispatch
        self.rulename = self.rule.rulename
        self.rulenumber = self.rule.rulenumber
        self.ch = CommandHelper(self.logdispatch)
        self.checkUndo = True

    def tearDown(self):
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
        if self.environ.getosfamily() == "linux":
            success = self.setLinuxConditions()
        elif self.environ.getosfamily() == "darwin":
            success = self.setMacConditions()
        return success

    def setLinuxConditions(self):
        success = True
        self.ph = Pkghelper(self.logger, self.environ)
        if not self.messupNetconfigFile():
            success = False
        if not self.messupSysctl():
            success = False
        if not self.messupModprobeFiles():
            success = False
        if not self.messupInterfaceFile():
            success = False
        if self.ph.manager == "apt-get":
            if not self.messupSSHDFile():
                success = False
        return success

    def setMacConditions(self):
        success = True
        debug = ""
        networksetup = "/usr/sbin/networksetup"
        listnetworkservices = networksetup + " -listallnetworkservices"
        ipv6status = "^IPv6:\s+On"
        getinfo = networksetup + " -getinfo"
        self.ch.executeCommand(listnetworkservices)
        retcode = self.ch.getReturnCode()
        if retcode != 0:
            success = False
            debug = "Failed to get list of network services"
            self.logger.log(LogPriority.DEBUG, debug)
        else:
            networkservices = self.ch.getOutput()
            for ns in networkservices:
                # ignore non-network service output lines
                if re.search("denotes that", ns, re.IGNORECASE):
                    continue
                else:
                    self.ch.executeCommand(networksetup + ' -setv6automatic ' + '"' + ns + '"')
                    retcode = self.ch.getReturnCode()
                    if retcode != 0:
                        success = False
                        debug = "Failed to get information for network service: " + ns
                        self.logger.log(LogPriority.DEBUG, debug)
        return success

    def messupNetconfigFile(self):
        success = True
        # stig portion, check netconfig file for correct contents
        if self.ph.manager == "apt-get":
            nfspkg = "nfs-common"
        else:
            nfspkg = "nfs-utils.x86_64"
        if self.ph.check(nfspkg):
            if not self.ph.remove(nfspkg):
                success = False
                debug = "Unable to remove nfs package for preconditions"
                self.logger.log(LogPriority.DEBUG, debug)
        if os.path.exists("/etc/netconfig"):
            item1 = "udp6 tpi_clts v inet6 udp - -"
            item2 = "tcp6 tpi_cots_ord v inet6 tcp - -"
            item1found, item2found, fixFile = False, False, False
            writestring = ""
            contents = readFile("/etc/netconfig", self.logger)
            for line in contents:
                writestring += line
                line = re.sub("\s+", " ", line.strip())
                if re.search(item1, line):
                    item1found = True
                if re.search(item2, line):
                    item2found = True
            if not item1found:
                writestring += item1
                fixFile = True
            if not item2found:
                writestring += item2
                fixFile = True
            if fixFile:
                if not writeFile("/etc/netconfig", writestring, self.logger):
                    success = False
                    debug = "Unable tomess up /etc/netconfig file for preconditions"
                    self.logger.log(LogPriority.DEBUG, debug)
        return success

    def messupSysctl(self):
        success = True
        sysctlcmd = ""
        sysctl = "/etc/sysctl.conf"
        directives = ["net.ipv6.conf.all.disable_ipv6=0",
                      "net.ipv6.conf.default.disable_ipv6=0"]
        filedirectives = {"net.ipv6.conf.all.disable_ipv6": "0",
                        "net.ipv6.conf.default.disable_ipv6": "0"}
        tmpfile = sysctl + ".tmp"

        if os.path.exists(sysctl):
            editor = KVEditorStonix(self.statechglogger, self.logger, "conf", sysctl,
                                    tmpfile, filedirectives, "present", "openeq")
            if not editor.report():
                if not editor.fix():
                    success = False
                    debug = "Unable to mess up " + sysctl + " file for preconditions"
                    self.logger.log(LogPriority.DEBUG, debug)
                elif not editor.commit():
                    success = False
                    debug = "Unable to mess up " + sysctl + " file for preconditions"
                    self.logger.log(LogPriority.DEBUG, debug)
        sysctllocs = ["/sbin/sysctl", "/usr/sbin/sysctl"]
        for loc in sysctllocs:
            if os.path.exists(loc):
                sysctlcmd = loc

        if sysctlcmd:
            for d in directives:
                setbadopt = sysctlcmd + " -w " + d
                self.ch.executeCommand(setbadopt)
                retcode = self.ch.getReturnCode()
                if retcode != 0:
                    success = False
                    debug = "Failed to write configuration change: " + d + "\n"
                    self.logger.log(LogPriority.DEBUG, debug)
        else:
            debug = "sysctl command not found on system\n"
            self.logger.log(LogPriority.DEBUG, debug)
            success = False
        return success

    def messupModprobeFiles(self):
        success = True
        modprobes = {"options": "ipv6 disable=1",
                     "install": "ipv6 /bin/true",
                     "helloworld": ""}
        if os.path.exists("/etc/modprobe.d/"):
            modprobefiles = glob.glob("/etc/modprobe.d/*")
            for modfile in modprobefiles:
                tmpfile = modfile + ".tmp"
                editor = KVEditorStonix(self.statechglogger, self.logger, "conf",
                                        modfile, tmpfile, modprobes, "notpresent",
                                        "space")
                if not editor.report():
                    if not editor.fix():
                        success = False
                        debug = "Unable to mess up " + modfile + " file for preconditions"
                        self.logger.log(LogPriority.DEBUG, debug)
                    elif not editor.commit():
                        success = False
                        debug = "Unable to mess up " + modfile + " file for preconditions"
                        self.logger.log(LogPriority.DEBUG, debug)
        return success

    def messupInterfaceFile(self):
        success = True
        interface = {"IPV6INIT": '"yes"',
                     "NETWORKING_IPV6": '"yes"'}
        # Check for existence of interface and network files to be configured
        if self.ph.manager == "yum":
            ifacefile = "/etc/sysconfig/network-scripts/"
            if not os.path.exists(ifacefile):
                ifacefile = ""
            netwrkfile = "/etc/sysconfig/network"
            if not os.path.exists(netwrkfile):
                netwrkfile = ""
        elif self.ph.manager == "zypper":
            ifacefile = "/etc/sysconfig/network/"
            if not os.path.exists(ifacefile):
                ifacefile = ""
        if ifacefile:
            dirs = glob.glob(ifacefile + "*")
            for loc in dirs:
                contents = []
                if re.search('^' + ifacefile + 'ifcfg', loc):
                    tmpfile = loc + ".tmp"
                    editor = KVEditorStonix(self.statechglogger, self.logger,
                                            "conf", loc, tmpfile, interface,
                                            "present", "closedeq")
                    if not editor.report():
                        if not editor.fix():
                            success = False
                            debug = "Unable to mess up " + loc + " file for preconditions"
                            self.logger.log(LogPriority.DEBUG, debug)
                        elif not editor.commit():
                            success = False
                            debug = "Unable to mess up " + loc + " file for preconditions"
                            self.logger.log(LogPriority.DEBUG, debug)
        return success

    def messupSSHDFile(self):
        success = True
        sshfile = "/etc/ssh/sshd_config"
        if os.path.exists(sshfile):
            tmpfile = sshfile + ".tmp"
            data = {"AddressFamily": "inet"}
            editor = KVEditorStonix(self.statechglogger, self.logger,
                                    "conf", sshfile, tmpfile,
                                    data, "notpresent", "space")
            if not editor.report():
                if not editor.fix():
                    success = False
                    debug = "Unable to mess up " + sshfile + " file for preconditions"
                    self.logger.log(LogPriority.DEBUG, debug)
                elif not editor.commit():
                    success = False
                    debug = "Unable to mess up " + sshfile + " file for preconditions"
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
