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
This is a Unit Test for Rule DisableRemoveableStorage

@author: Breen Malmberg
@change: 2016/02/10 roy Added sys.path.append for being able to unit test this
                        file as well as with the test harness.
@change: 1/17/2019 Derek Walker - update to set pre conditions
    for linux portion
'''
from __future__ import absolute_import
import unittest
import sys
import os
import re
import glob
sys.path.append("../../../..")
from src.tests.lib.RuleTestTemplate import RuleTest
from src.stonix_resources.CommandHelper import CommandHelper
from src.tests.lib.logdispatcher_mock import LogPriority
from src.stonix_resources.rules.DisableRemoveableStorage import DisableRemoveableStorage
from src.stonix_resources.stonixutilityfunctions import checkPerms, readFile, writeFile, setPerms
from src.stonix_resources.pkghelper import Pkghelper

class zzzTestRuleDisableRemoveableStorage(RuleTest):

    def setUp(self):
        RuleTest.setUp(self)
        self.rule = DisableRemoveableStorage(self.config,
                                             self.environ,
                                             self.logdispatch,
                                             self.statechglogger)
        self.rulename = self.rule.rulename
        self.rulenumber = self.rule.rulenumber
        self.ch = CommandHelper(self.logdispatch)
        self.rule.storageci.updatecurrvalue(True)
        self.logger = self.logdispatch
        self.ignoreresults = True
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
        if self.environ.getostype() == "Mac OS X":
            success = self.setConditionsForMac()
        else:
            success = self.setConditionsForLinux()
        return success

    def setConditionsForMac(self):
        '''
        Method to configure mac non compliant for unit test
        @author: dwalker
        @return: boolean
        '''
        success = True
        daemonpath = os.path.abspath(os.path.join(os.path.dirname(sys.argv[0]))) + "/src/stonix_resources/disablestorage"
        plistpath = "/Library/LaunchDaemons/gov.lanl.stonix.disablestorage.plist"
        self.rule.daemonpath = daemonpath
        if re.search("^10.11", self.environ.getosver()):
            usb = "IOUSBMassStorageDriver"
        else:
            usb = "IOUSBMassStorageClass"
        kernelmods = [usb,
                      "IOFireWireFamily",
                      "AppleThunderboltUTDM",
                      "AppleSDXC"]
        check = "/usr/sbin/kextstat"
        load = "/sbin/kextload"
        '''Remove plist file for launch job if exists'''
        if os.path.exists(plistpath):
            os.remove(plistpath)
        '''Remove daemon file if exists'''
        if os.path.exists(daemonpath):
            os.remove(daemonpath)
        for kmod in kernelmods:
            cmd = check + "| grep " + kmod
            self.ch.executeCommand(cmd)
            if self.ch.getReturnCode() != 0:
                '''kernel mod is not loaded, load to make non-compliant'''
                cmd = load + " /System/Library/Extensions/" + kmod + ".kext"
                if not self.ch.executeCommand(cmd):
                    debug = "Unable to load kernel module " + kmod + " for unit test\n"
                    self.logdispatch.log(LogPriority.DEBUG, debug)
                    success = False
        return success

    def setConditionsForLinux(self):
        '''
        Method to configure mac non compliant for unit test
        @author: dwalker
        @return: boolean
        '''
        success = True
        self.ph = Pkghelper(self.logger, self.environ)
        # check compliance of grub file(s) if files exist
        if re.search("Red Hat", self.environ.getostype()) and \
                re.search("^6", self.environ.getosver()):
            self.grubperms = [0, 0, 0o600]
        elif self.ph.manager is "apt-get":
            self.grubperms = [0, 0, 0o400]
        else:
            self.grubperms = [0, 0, 0o644]
        grubfiles = ["/boot/grub2/grub.cfg",
                     "/boot/grub/grub.cfg"
                     "/boot/grub/grub.conf"]
        for grub in grubfiles:
            if os.path.exists(grub):
                if self.grubperms:
                    if checkPerms(grub, self.grubperms, self.logger):
                        if not setPerms(grub, [0, 0, 0o777], self.logger):
                            success = False
                contents = readFile(grub, self.logger)
                if contents:
                    for line in contents:
                        if re.search("^kernel", line.strip()) or re.search("^linux", line.strip()) \
                                or re.search("^linux16", line.strip()):
                            if re.search("\s+nousb\s*", line):
                                if not re.sub("nousb", "", line):
                                    success = False
                            if re.search("\s+usbcore\.authorized_default=0\s*", line):
                                if not re.sub("usbcore\.authorized_default=0", "", line):
                                    success = False

        pcmcialist = ['pcmcia-cs', 'kernel-pcmcia-cs', 'pcmciautils']
        # check for existence of certain usb packages, non-compliant
        # if any exist
        for item in pcmcialist:
            if not self.ph.check(item):
                self.ph.install(item)

        removeables = []
        found1 = True
        blacklist = {"blacklist usb_storage": False,
                     "install usbcore /bin/true": False,
                     "install usb-storage /bin/true": False,
                     "blacklist uas": False,
                     "blacklist firewire-ohci": False,
                     "blacklist firewire-sbp2": False}
        if os.path.exists("/etc/modprobe.d"):
            dirs = glob.glob("/etc/modprobe.d/*")
            for directory in dirs:
                if os.path.isdir(directory):
                    continue
                tempstring = ""
                contents = readFile(directory, self.logger)
                for line in contents:
                    if line.strip() in blacklist:
                        continue
                    else:
                        tempstring += line
                if not writeFile(directory, tempstring, self.logger):
                    success = False
        if os.path.exists("/etc/modprobe.conf"):
            contents = readFile("/etc/modprobe.conf", self.logger)
            tempstring = ""
            for line in contents:
                if line.strip() in blacklist:
                    continue
                else:
                    tempstring += line
            if not writeFile("/etc/modprobe.conf", tempstring, self.logger):
                success = False

        udevfile = "/etc/udev/rules.d/10-local.rules"
        if os.path.exists(udevfile):
            if checkPerms(udevfile, [0, 0, 0o644], self.logger):
                if not setPerms(udevfile, [0 ,0, 0o777], self.logger):
                    success = False
            contents = readFile(udevfile, self.logger)
            tempstring = ""
            for line in contents:
                if re.search("ACTION\=\=\"add\"\, SUBSYSTEMS\=\=\"usb\"\, RUN\+\=\"/bin/sh \-c \'for host in /sys/bus/usb/devices/usb\*\; do echo 0 \> \$host/authorized\_default\; done\'\"",
                        line.strip()):
                    continue
                else:
                    tempstring += line
            if not writeFile(udevfile, tempstring, self.logger):
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
