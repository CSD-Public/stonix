###############################################################################
#                                                                             #
# Copyright 2015-2018.  Los Alamos National Security, LLC. This material was  #
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
Created on Mar 4, 2013

Disable removeable storage. This rule is optional, and disables USB, thunderbolt and firewire
storage devices from accessing, or being accessed, by the system.

@author: Breen Malmberg
@change: 02/14/2014 ekkehard Implemented self.detailedresults flow
@change: 02/14/2014 ekkehard Implemented isapplicable
@change: 02/14/2014 ekkehard blacklisted darwin no os x implementation
@change: 03/20/2014 dwalker Complete rule refactor
@change: 06/19/2014 ekkehard Commented out destructive removal of extension
@change: 06/19/2014 ekkehard fix whitelist & blacklist so this does only run on
OS X Mavericks not Mountain Lion, Lion, etc.
@change: 2014/08/26 dkennel Switched CI values to default of False as this is
    an optional rule designed for very high security environments.
@change: 2014/10/17 ekkehard OS X Yosemite 10.10 Update
@change: 2015/04/15 dkennel updated for new isApplicable
@change: 2015/10/07 eball Help text/PEP8 cleanup
@change: 2016/03/01 ekkehard cgi default value set to False
@change: 2017/03/30 dkennel Added fisma = high to applicable dictionary
@change: 2017/07/07 ekkehard - make eligible for macOS High Sierra 10.13
@change 2017/08/28 rsn Fixing to use new help text methods
@change: 2017/11/13 ekkehard - make eligible for OS X El Capitan 10.11+
@change: 2018/4/17 dwalker - added additional measures to ensure
    disablement of removable storage.  Cleaned up code
'''

from __future__ import absolute_import

import os
import re
import traceback
import glob
import sys

from ..CommandHelper import CommandHelper
from ..rule import Rule
from ..stonixutilityfunctions import readFile, setPerms, createFile
from ..stonixutilityfunctions import checkPerms, iterate, writeFile, resetsecon
from ..logdispatcher import LogPriority
from ..pkghelper import Pkghelper


class DisableRemoveableStorage(Rule):
    '''
    Disable removeable storage. This rule is optional, and disables USB, thunderbolt and firewire
    storage devices from accessing, or being accessed, by the system.
    '''

    def __init__(self, config, environ, logger, statechglogger):
        '''

        @param config:
        @param environ:
        @param logger:
        @param statechglogger:
        '''
        Rule.__init__(self, config, environ, logger, statechglogger)

        self.logger = logger
        self.rulenumber = 29
        self.rulename = 'DisableRemoveableStorage'
        self.mandatory = False
        self.formatDetailedResults("initialize")
        self.guidance = ['NSA 2.2.2.2, CIS, NSA(2.2.2.2), cce-4006-3,4173-1']
        self.applicable = {'type': 'white',
                           'family': ['linux', 'solaris', 'freebsd'],
                           'os': {'Mac OS X': ['10.11', 'r', '10.13.10']},
                           'fisma': 'high'}

        # configuration item instantiation
        datatype = "bool"
        key = "DISABLEREMOVEABLESTORAGE"
        instructions = "To disable removeable storage devices on this system, set the value of DISABLEREMOVEABLESTORAGE to True"
        default = False
        self.storageci = self.initCi(datatype, key, instructions, default)

        self.pcmcialist = ['pcmcia-cs', 'kernel-pcmcia-cs', 'pcmciautils']
        self.pkgremovedlist = []
        self.iditerator = 0
        self.created = False
        self.daemonpath = os.path.abspath(os.path.join(os.path.dirname(sys.argv[0]))) + "/stonix_resources/disablestorage"
        self.sethelptext()

    def report(self):
        '''
        report the current rule-compliance status of this system. update
        self.rulesuccess if method does not succeed. self.compliant if
        rule succeeds and reports true.

        @return: self.compliant
        @rtype: bool

        @author: Breen Malmberg

        @change: dwalker - implementing kveditor and completely revamped rule
            logic. added event deletion at the beginning of the fix
        @change: dwalker 8/13/2014 changed name of rule to
            DisableRemoveableStorage and rule now supports disabling other
            ports such thunderbolt and firewire
        '''

        try:
            # defaults
            compliant = True
            self.detailedresults = ""
            if self.environ.getostype() == "Mac OS X":
                compliant = self.reportMac()
            else:
                self.udevfile = "/etc/udev/rules.d/10-local.rules"
                lsmodcmd = ""
                self.mvcmd = "/bin/mv"
                if os.path.exists("/sbin/lsmod"):
                    lsmodcmd = "/sbin/lsmod"
                elif os.path.exists("/usr/bin/lsmod"):
                    lsmodcmd = "/usr/bin/lsmod"
                self.lsmod = False
                removeables = []
                usbmods = ["usb_storage",
                           "usb-storage"]
                self.grubfiles = ["/boot/grub2/grub.cfg",
                             "/boot/grub/grub.cfg"
                             "/boot/grub/grub.conf"]
                self.ph = Pkghelper(self.logger, self.environ)
                self.ch = CommandHelper(self.logger)
                self.detailedresults = ""
                self.grubperms = ""
                if re.search("Red Hat", self.environ.getostype()) and \
                        re.search("^6", self.environ.getosver()):
                    self.grubperms = [0 ,0,  0o600]
                elif self.ph.manager is "apt-get":
                    self.grubperms = [0, 0, 0o400]
                else:
                    self.grubperms = [0, 0, 0o644]
                # check compliance of grub file(s) if exists
                for grub in self.grubfiles:
                    if os.path.exists(grub):
                        if self.grubperms:
                            if not checkPerms(grub, self.grubperms, self.logger):
                                compliant = False
                                self.detailedresults += "Permissions " + \
                                    "incorrect on " + grub + " file\n"
                        contents = readFile(grub, self.logger)
                        if contents:
                            for line in contents:
                                if re.search("^kernel", line.strip()) or re.search("^linux", line.strip()) \
                                    or re.search("^linux16", line.strip()):
                                    if not re.search("\s+nousb\s+", line):
                                        debug = grub + " file doesn't " + \
                                            "contain nousb kernel option\n"
                                        self.detailedresults += grub + " file doesn't " + \
                                            "contain nousb kernel option\n"
                                        self.logger.log(LogPriority.DEBUG,
                                                        debug)
                                        compliant = False
                                    if not re.search("\s+usbcore\.authorized_default=0\s+", line):
                                        debug = grub + " file doesn't " + \
                                            "contain usbcore.authorized_default=0 " + \
                                            "kernel option\n"
                                        self.detailedresults += grub + " file doesn't " + \
                                            "contain usbcore.authorized_default=0 " + \
                                            "kernel option\n"
                                        compliant = False
                # check for existence of certain usb packages, non-compliant
                # if any exist
                for item in self.pcmcialist:
                    if self.ph.check(item):
                        self.detailedresults += item + " is installed " + \
                            "and shouldn't be\n"
                        compliant = False
                if lsmodcmd:
                    for usb in usbmods:
                        cmd = [lsmodcmd, "|", "grep", usb]
                        self.ch.executeCommand(cmd)
                        if self.ch.getReturnCode() == "0":
                            compliant = False
                            self.detailedresults += "lsmod command shows usb not disabled\n"
                            break
                found1 = True
                self.blacklist = {"blacklist usb_storage": False,
                                  "install usbcore /bin/true": False,
                                  "install usb-storage /bin/true": False,
                                  "blacklist uas": False,
                                  "blacklist firewire-ohci": False,
                                  "blacklist firewire-sbp2": False}
                if os.path.exists("/etc/modprobe.d"):
                    dirs = glob.glob("/etc/modprobe.d/*")
                    # since file name doesn't matter
                    # i.e. all files are read and treated the same in
                    # modprobe.d, if directives are found in any of
                    # the files inside this directory, where they don't
                    # have to be in the same file, the system is compliant
                    for directory in dirs:
                        contents = readFile(directory, self.logger)
                        for item in self.blacklist:
                            for line in contents:
                                if re.search("^" + item, line.strip()):
                                    self.blacklist[item] = True
                    # if we don't find directives in any of the files in
                    # modprobe.d, we will now check /etc/modprobe.conf
                    # we will still keep track of whether we already found
                    # one directive in one of the files in modprobe.d
                    for item in self.blacklist:
                        if not self.blacklist[item]:
                            found1 = False
                else:
                    found1 = False
                if not found1:
                    if os.path.exists("/etc/modprobe.conf"):
                        contents = readFile("/etc/modprobe.conf")
                        if contents:
                            for item in self.blacklist:
                                for line in contents:
                                    if re.search("^" + item,
                                                 line.strip()):
                                        self.blacklist[item] = True
                    for item in self.blacklist:
                        if not self.blacklist[item]:
                            debug = "modprobe.conf nor blacklist " + \
                                "files contain " + item + "\n"
                            self.logger.log(LogPriority.DEBUG, debug)
                            compliant = False
                for item in self.blacklist:
                    if self.blacklist[item]:
                        removeables.append(item)
                for item in removeables:
                    del(self.blacklist[item])
                found2 = False
                if os.path.exists(self.udevfile):
                    if not checkPerms(self.udevfile, [0, 0, 0o644], self.logger):
                        self.detailedresults += "Permissions not correct " + \
                            "on " + self.udevfile + "\n"
                        compliant = False
                    contents = readFile(self.udevfile, self.logger)
                    for line in contents:
                        if re.search("ACTION\=\=\"add\"\, SUBSYSTEMS\=\=\"usb\"\, RUN\+\=\"/bin/sh \-c \'for host in /sys/bus/usb/devices/usb\*\; do echo 0 \> \$host/authorized\_default\; done\'\"", line.strip()):
                            found2 = True
                    if not found2:
                        self.detailedresults += "Udev rule not found to disable usb at boot\n"
                        debug = "Udev rule not found to disable usb at boot\n"
                        self.logger.log(LogPriority.DEBUG, debug)
                        compliant = False
                else:
                    self.detailedresults += "Udev file doesn't exist to disable usb at boot\n"
                    debug = "Udev file doesn't exist to disable usb at boot\n"
                    self.logger.log(LogPriority.DEBUG, debug)
                    compliant = False
            self.compliant = compliant
        except OSError:
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant
###############################################################################

    def reportMac(self):
        self.detailedresults = ""
        compliant = True
        self.cronfile = "/usr/lib/cron/tabs/root"
        if os.path.exists(self.cronfile):
            #for this file we don't worry about permissions, SIP protected
            contents = readFile(self.cronfile, self.logger)
            found = False
            for line in contents:
                if re.search("\@reboot /bin/launchctl unload /System/Library/LaunchDaemons/com\.apple\.diskarbitrationd\.plist", line):
                    found = True
                    break
            if not found:
                compliant = False
                self.detailedresults += "Didn't find the correct contents " + \
                    "in crontab file\n"
        else:
            self.detailedresults += self.cronfile + " doesn't exist\n"
            compliant = False
        return compliant

###############################################################################

    def fix(self):
        '''
        attempt to perform necessary operations to bring the system into
        compliance with this rule.

        @author Breen Malmberg
        @change: dwalker - implemented event deletion at the beginning of fix,
            also implemented a check for the ci value to see if fix should
            even be run.
        '''

        try:
            success = True
            self.detailedresults = ""
            # clear out event history so only the latest fix is recorded
            self.iditerator = 0
            eventlist = self.statechglogger.findrulechanges(self.rulenumber)
            for event in eventlist:
                self.statechglogger.deleteentry(event)
            if not self.storageci.getcurrvalue():
                self.detailedresults += "Rule not enabled so nothing was done\n"
                self.logger.log(LogPriority.DEBUG, 'Rule was not enabled, so nothing was done')
                return
            if self.environ.getostype() == "Mac OS X":
                success = self.fixMac()
            else:
                created = False
                changed = False
                tempstring = ""
                grubfilefound = False
                blacklistf = "/etc/modprobe.d/stonix-blacklist.conf"
                for grub in self.grubfiles:
                    if os.path.exists(grub):
                        grubfilefound = True
                        if self.grubperms:
                            if not checkPerms(grub, self.grubperms, self.logger):
                                self.iditerator += 1
                                myid = iterate(self.iditerator, self.rulenumber)
                                if not setPerms(grub, self.grubperms, self.logger,
                                                self.statechglogger, myid):
                                    success = False
                        contents = readFile(grub, self.logger)
                        kernellinefound = False
                        if contents:
                            for line in contents:
                                if re.search("^kernel", line.strip()) or re.search("^linux", line.strip()) \
                                    or re.search("^linux16", line.strip()):
                                    kernellinefound = True
                                    if not re.search("\s+nousb\s+", line):
                                        changed = True
                                        tempstring += line + " nousb"
                                    elif not re.search("\s+usbcore\.authorized_default=0\s+", line):
                                        changed = True
                                        tempstring += line + " usbcore.authroized_default=0"
                                    tempstring += "\n"
                                else:
                                    tempstring += line
                        if not kernellinefound:
                            changed = False
                            self.detailedresults += "The grub file doesn't contain kernel line\n" + \
                                "Unable to fully implement fixes in this rule\n"
                            success = False
                        if changed:
                            tmpfile = grub + ".tmp"
                            if writeFile(tmpfile, tempstring, self.logger):
                                self.iditerator += 1
                                myid = iterate(self.iditerator, self.rulenumber)
                                event = {"eventtype": "conf",
                                         "filepath": grub}
                                self.statechglogger.recordchgevent(myid, event)
                                self.statechglogger.recordfilechange(grub, tmpfile,
                                                                     myid)
                                os.rename(tmpfile, grub)
                                os.chown(grub, 0, 0)
                                os.chmod(grub, 384)
                            else:
                                success = False
                if not grubfilefound:
                    self.detailedresults += "No grub configuration file found\n" + \
                        "Unable to fully fix system for this rule\n"
                    success = False
                tempstring = ""
                    # Check if self.blacklist still contains values, if it
                    # does, then we didn't find all the blacklist values
                    # in report
                if self.blacklist:
                    # didn't find one or both directives in the files
                    # inside modprobe.d so we now check an alternate
                    # so create stonixblacklist file if it doesn't
                    # exist and put remaining unfound blacklist
                    # items there
                    if not os.path.exists(blacklistf):
                        createFile(blacklistf, self.logger)
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        event = {"eventtype": "creation",
                                 "filepath": blacklistf}
                        self.statechglogger.recordchgevent(myid, event)
                    else:
                        if not checkPerms(blacklistf, [0, 0, 420],
                                          self.logger):
                            self.iditerator += 1
                            myid = iterate(self.iditerator,
                                           self.rulenumber)
                            if not setPerms(blacklistf, [0, 0, 420],
                                            self.logger,
                                            self.statechglogger, myid):
                                success = False
                    for item in self.blacklist:
                        tempstring += item + "\n"
                    tmpfile = blacklistf + ".tmp"
                    if writeFile(tmpfile, tempstring,
                                 self.logger):
                        self.iditerator += 1
                        myid = iterate(self.iditerator,
                                       self.rulenumber)
                        event = {"eventtype": "conf",
                                 "filepath": blacklistf}
                        self.statechglogger.recordchgevent(myid, event)
                        self.statechglogger.recordfilechange(blacklistf,
                                                             tmpfile, myid)
                        os.rename(tmpfile, blacklistf)
                        os.chown(blacklistf, 0, 0)
                        os.chmod(blacklistf, 420)
                        resetsecon(blacklistf)
                    if self.ph.manager == "apt-get":
                        cmd = ["/usr/sbin/update-initramfs", "-u"]
                        if not self.ch.executeCommand(cmd):
                            success = False
                            self.detailedresults += "Unable to run update-initramfs command\n"
                for item in self.pcmcialist:
                    if self.ph.check(item):
                        self.ph.remove(item)
                        self.pkgremovedlist.append(item)
                if not os.path.exists(self.udevfile):
                    if not createFile(self.udevfile, self.logger):
                        self.detailedresults += "Unable to create " + \
                            self.udevfile + " file\n"
                        success = False
                    else:
                        created = True
                if os.path.exists(self.udevfile):
                    if not checkPerms(self.udevfile, [0, 0, 0o644], self.logger):
                        if created:
                            if not setPerms(self.udevfile, [0, 0, 0o644],
                                            self.logger):
                                success = False
                                self.detailedresults += "Unable to set " + \
                                    "permissions on " + self.udevfile + "\n"
                        else:
                            self.iditerator += 1
                            myid = iterate(self.iditerator,
                                           self.rulenumber)
                            if not setPerms(self.udevfile, [0, 0, 0o644],
                                            self.logger,
                                            self.statechglogger, myid):
                                success = False
                                self.detailedresults += "Unable to set " + \
                                    "permissions on " + self.udevfile + "\n"
                    found = False
                    contents = readFile(self.udevfile, self.logger)
                    tempstring = ""
                    for line in contents:
                        if re.search("ACTION==\"add\"\, SUBSYSTEMS==\"usb\"\, RUN+=\"/bin/sh -c \'for host in /sys/bus/usb/devices/usb\*\; do echo 0 > \$host/authorized_default; done\'\"", line.strip()):
                            found = True
                        tempstring += line
                    if not found:
                        tempstring += "ACTION==\"add\", SUBSYSTEMS==\"usb\", RUN+=\"/bin/sh -c \'for host in /sys/bus/usb/devices/usb*; do echo 0 > $host/authorized_default; done\'\""
                        tmpfile = self.udevfile + ".tmp"
                        if writeFile(tmpfile, tempstring,
                                 self.logger):
                            if not created:
                                self.iditerator += 1
                                myid = iterate(self.iditerator,
                                               self.rulenumber)
                                event = {"eventtype": "conf",
                                         "filepath": self.udevfile}
                                self.statechglogger.recordchgevent(myid, event)
                                self.statechglogger.recordfilechange(self.udevfile,
                                                                     tmpfile, myid)
                            os.rename(tmpfile, self.udevfile)
                            os.chown(self.udevfile, 0, 0)
                            os.chmod(self.udevfile, 0o644)
                            resetsecon(self.udevfile)
                        else:
                            success = False
                            self.detailedresults += "Unable to write changes " + \
                                "to " + self.udevfile + "\n"
            self.rulesuccess = success
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.rulesuccess

###############################################################################

    def fixMac(self):
        '''This method will attempt to disable certain storage ports by moving
        certain kernel extensions.  If the check box is checked we will
        move the kernel (if present) associated with that storage port/device
        into a folder designated for those disabled extensions.  If the
        check box is unchecked, we will assume the user doesn't want this
        disabled and if the kernel is no longer where it should be, we will
        check the disabled extensions folder to see if it was previously
        disabled.  If it's in that folder, we will move it back.
        @author: Breen Malmberg
        @return: bool
        @change: dwalker 8/19/2014
        '''
        debug = ""
#         check = "/usr/sbin/kextstat "
#         unload = "/sbin/kextunload "
#         load = "/sbin/kextload "
#         filepath = "/System/Library/Extensions/"
        success = True
        #created1 = False
#         created2 = False
        croncreated = False
        if not os.path.exists(self.cronfile):
            createFile(self.cronfile, self.logger)
            croncreated = True
            self.iditerator += 1
            myid = iterate(self.iditerator, self.rulenumber)
            event = {"eventtype": "creation",
                     "filepath": self.cronfile}
            self.statechglogger.recordchgevent(myid, event)
        if os.path.exists(self.cronfile):
            #for this file we don't worry about permissions, SIP protected
            contents = readFile(self.cronfile, self.logger)
            found = False
            badline = False
            tempstring = ""
            for line in contents:
                if not re.search("^\@reboot /bin/launchctl unload /System/Library/LaunchDaemons/com\.apple\.diskarbitrationd\.plist$", line.strip()):
                    tempstring += line
                elif re.search("^@reboot /bin/launchctl load /System/Library/LaunchDaemons/com\.apple\.diskarbitrationd\.plist$", line.strip()):
                    badline = True
                    continue
                else:
                    tempstring += line
                    found = True
            if not found:
                tempstring += "@reboot /bin/launchctl unload /System/Library/LaunchDaemons/com.apple.diskarbitrationd.plist\n"
            if not found or badline:
                tmpfile = self.cronfile + ".tmp"
                if not writeFile(tmpfile, tempstring, self.logger):
                    success = False
                else:
                    if not croncreated:
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        event = {"eventtype": "conf",
                                 "filepath": self.cronfile}
                        self.statechglogger.recordchgevent(myid, event)
                        self.statechglogger.recordfilechange(self.cronfile,
                                                                     tmpfile, myid)
                        if not checkPerms(self.cronfile, [0, 0, 0o644], self.logger):
                            self.iditerator += 1
                            myid = iterate(self.iditerator, self.rulenumber)
                            if not setPerms(self.cronfile, [0, 0, 0o644],
                                            self.logger,
                                            self.statechglogger, myid):
                                success = False
                    else:
                        if not checkPerms(self.cronfile, [0, 0, 0o644], self.logger):
                            if not setPerms(self.cronfile, [0, 0, 0o644],
                                            self.logger):
                                success = False
                    os.rename(tmpfile, self.cronfile)
        if debug:
            self.logger.log(LogPriority.DEBUG, debug)
        return success

