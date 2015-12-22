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
Created on Mar 4, 2013

Disable USB storage. This rule is optional, and disables USB storage devices
from accessing, or being able to be accessed from the system.

@author: bemalmbe
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
'''

from __future__ import absolute_import
import os
import re
import traceback
import glob
from ..CommandHelper import CommandHelper
from ..rule import Rule
from ..stonixutilityfunctions import readFile, setPerms, createFile, getUserGroupName
from ..stonixutilityfunctions import checkPerms, iterate, writeFile, resetsecon
from ..logdispatcher import LogPriority
from ..pkghelper import Pkghelper
import cmd
import stat
import pwd
import grp


class DisableRemoveableStorage(Rule):
    '''
    classdocs
    '''

    def __init__(self, config, environ, logger, statechglogger):
        Rule.__init__(self, config, environ, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 29
        self.rulename = 'DisableRemoveableStorage'
        self.mandatory = False
        self.formatDetailedResults("initialize")
        self.helptext = "This optional rule disables USB storage devices " + \
            "from accessing, or being accessed from, the system."
        self.guidance = ['NSA 2.2.2.2, CIS, NSA(2.2.2.2), cce-4006-3,4173-1']
        self.applicable = {'type': 'white',
                           'family': ['linux', 'solaris', 'freebsd'],
                           'os': {'Mac OS X': ['10.9', 'r', '10.11.10']}}

        # configuration item instantiation
        datatype = "bool"
        key = "DISABLEUSB"
        instructions = "To disable usb storage devices on this system, " + \
            "set the value of DISABLEUSB to True"
        default = False
        self.usbci = self.initCi(datatype, key, instructions, default)

        datatype = "bool"
        key = "DISABLEFIREWIRE"
        instructions = "To disable Firewire storage devices on this " + \
            "system set the value of DISABLEFIREWIRE to True."
        default = False
        self.fwci = self.initCi(datatype, key, instructions, default)

        if self.environ.getostype() == "Mac OS X":
            datatype = "bool"
            key = "DISABLETHUNDER"
            instructions = "To disable thunderbolt storage devices on " + \
                "this system set the value of DISABLETHUNDER to True."
            default = False
            self.tbci = self.initCi(datatype, key, instructions, default)

            datatype = "bool"
            key = "DISABLESDCARD"
            instructions = "To disable SD card functionality on this " + \
                "system set the value of DISABLESDCARD to True"
            default = False
            self.sdci = self.initCi(datatype, key, instructions, default)

        self.pcmcialist = ['pcmcia-cs', 'kernel-pcmcia-cs', 'pcmciautils']
        self.pkgremovedlist = []
        self.iditerator = 0
        self.created = False

    def report(self):
        '''
        report the current rule-compliance status of this system. update
        self.rulesuccess if method does not succeed. update self.currstate and
        self.compliant if rule succeeds and reports true.

        @return bool
        @author bemalmbe
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
                output = ""
                removeables = []
                self.ph = Pkghelper(self.logger, self.environ)
                self.ch = CommandHelper(self.logger)
                self.detailedresults = ""
                # check compliance of grub file if exists
                if self.ph.manager == "apt-get" or self.ph.manager == "zypper":
                    if os.path.exists('/etc/grub'):
                        contents = readFile("/etc/grub", self.logger)
                        if contents:
                            for line in contents:
                                if re.search("^kernel", line):
                                    if not re.search("\s+nousb\s+", line):
                                        debug = "/etc/grub file doesn't " + \
                                            "contain line with nousb\n"
                                        self.detailedresults += "/etc/grub" + \
                                            " file doesn't contain line with " + \
                                            "nousb\n"
                                        self.logger.log(LogPriority.DEBUG,
                                                        debug)
                                        compliant = False

                # check if usb kernel module exists, non compliant if yes
                self.ch.wait = False
                self.ch.executeCommand("uname -r")
                self.ch.wait = True
                output = self.ch.getOutput()
                if output:
                    output = output[0].strip()
                    if os.path.exists("/lib/modules/" + output +
                                      "/kernel/drivers/usb/storage/usb-storage.ko"):
                        debug = "Kernel module exists but shouldn't\n"
                        self.detailedresults += "Kernel module exists " + \
                            "but shouldn't\n"
                        self.logger.log(LogPriority.DEBUG, debug)
                        compliant = False

                # check for existence of certain usb packages, non-compliant
                # if any exist
                for item in self.pcmcialist:
                    if self.ph.check(item):
                        self.detailedresults += item + " is installed " + \
                            "and shouldn't be\n"
                        compliant = False
                found = True
                self.blacklist = {}
                # directives are different for different distros
                if self.usbci.getcurrvalue():
                    if self.ph.manager == "apt-get" or \
                       self.ph.manager == "zypper":
                        self.blacklist["blacklist usb_storage"] = False
                        self.blacklist["install usbcore /bin/true"] = False
                    elif self.ph.manager == "yum":
                        self.blacklist["blacklist usb-storage"] = False
                        self.blacklist["install usb-storage /bin/true"] = False
                # first check for files in modprobe.d, first choice
                if self.fwci.getcurrvalue():
                    self.blacklist["blacklist firewire-ohci"] = False
                    self.blacklist["blacklist firewire-sbp2"] = False
                if os.path.exists("/etc/modprobe.d"):
                    # for zypper the file name is important, directives must be
                    # placed in /etc/modprobe.d/50-blacklist.conf
                    if self.ph.manager == "zypper":
                        if os.path.exists("/etc/modprobe.d/50-blacklist.conf"):
                            contents = readFile("/etc/modprobe.d/50-blacklist.conf", self.logger)
                            for item in self.blacklist:
                                for line in contents:
                                    if re.search("^" + item, line.strip()):
                                        self.blacklist[item] = True

                            for item in self.blacklist:
                                if not self.blacklist[item]:
                                    compliant = False
                        else:
                            # this file should be present but if not, create it
                            # and set a var self.created = True, this var keeps
                            # track of whether the file was already there or
                            # not for statechlogger purposes
                            if createFile("/etc/modprobe.d/50-blacklist.conf"):
                                self.created = True
                            debug += "/etc/modrobe.d/50-blacklist.conf " + \
                                "file doesn't exist\n"
                            self.logger.log(LogPriority.DEBUG, debug)
                            compliant = False
                    else:
                        dirs = glob.glob("/etc/modprobe.d/*")
                        # since file name doesn't matter for non zypper systems
                        # i.e. all files are read and treated the same in
                        # modprobe.d, if both directives are found in any of
                        # the files inside this directory, where both don't
                        # have to be in the same file, the system is compliant
                        for directory in dirs:
                            contents = readFile(directory, self.logger)
                            for item in self.blacklist:
                                for line in contents:
                                    if re.search("^" + item, line.strip()):
                                        self.blacklist[item] = True
                        # if we don't find both in any of the files in
                        # modprobe.d, we will now check /etc/modprobe.conf
                        # we will still keep track of whether we already found
                        # one directive in one of the files in modprobe.d
                        for item in self.blacklist:
                            if not self.blacklist[item]:
                                found = False
                        if not found:
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

                elif os.path.exists("/etc/modprobe.conf"):
                    contents = readFile("/etc/modprobe.conf", self.logger)
                    if contents:
                        for item in self.blacklist:
                            for line in contents:
                                if re.search("^" + item, line.strip()):
                                    self.blacklist[item] = True
                    for item in self.blacklist:
                        if not self.blacklist[item]:
                            debug = "modprobe.conf doesn't contain " + item + \
                                "\n"
                            compliant = False
                for item in self.blacklist:
                    if self.blacklist[item]:
                        removeables.append(item)
                for item in removeables:
                    del(self.blacklist[item])
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
        debug = ""
        self.detailedresults = ""
        compliant = True
        self.plistpath = "/Library/LaunchDaemons/gov.lanl.stonix.disabelstorage.plist"
        self.plistcontents = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
     <key>Label</key>
     <string>gov.lanl.stonix.disablestorage</string>
     <key>Program</key>
         <string>/Applications/stonix4mac.app/Contents/Resources/stonix.app/Contents/MacOS/stonix_resources/disablestorage.py</string>
     <key>RunAtLoad</key>
         <true/>
     <key>StartInterval</key>
         <integer>300</integer>
</dict>
</plist>'''
        self.daemonpath = "/Applications/stonix4mac.app/Contents/Resources/stonix.app/Contents/MacOS/stonix_resources/disablestorage.py"
        if os.path.exists(self.plistpath):
            statdata = os.stat(self.plistpath)
            mode = stat.S_IMODE(statdata.st_mode)
            ownergrp = getUserGroupName(self.plistpath)
            owner = ownergrp[0]
            group = ownergrp[1]
            if mode != 420:
                compliant = False
                self.detailedresults += "permissions on " + self.plistpath + \
                    "aren't 644\n"
                debug = "permissions on " + self.plistpath + " aren't 644\n"
                self.logger.log(LogPriority.DEBUG, debug)
            if owner != "root":
                compliant = False
                self.detailedresults += "Owner of " + self.plistpath + \
                    " isn't root\n"
                debug = "Owner of " + self.plistpath + \
                    " isn't root\n"
                self.logger.log(LogPriority.DEBUG, debug)
            if group != "wheel":
                compliant = False
                self.detailedresults += "Group of " + self.plistpath + \
                    " isn't wheel\n"
                debug = "Group of " + self.plistpath + \
                    " isn't wheel\n"
                self.logger.log(LogPriority.DEBUG, debug)
            contents = readFile(self.plistpath, self.logger)
            contentstring = ""
            for line in contents:
                contentstring += line
            if not re.search("^" + self.plistcontents + "?", contentstring):
                compliant = False
                self.detailedresults += "plist file doesn't contain the " + \
                    "correct contents\n"
        else:
            compliant = False
            self.detailedresults += "daemon plist file doesn't exist\n"
        if not os.path.exists(self.daemonpath):
            compliant = False
            self.detailedresults += "daemon python file doesn't exist\n"
        check = "/usr/sbin/kextstat "
        self.ch = CommandHelper(self.logger)
        usb = "IOUSBMassStorageClass"
        cmd = check + "| grep " + usb
        self.ch.executeCommand(cmd)

        # if return code is 0, the kernel module is loaded, thus we need
        # to disable it
        if self.ch.getReturnCode() == 0:
            compliant = False
            debug += "USB Kernel module is loaded\n"
            self.detailedresults += "USB Kernel module is loaded\n"

        fw = "IOFireWireSerialBusProtocolTransport"
        cmd = check + "| grep " + fw
        self.ch.executeCommand(cmd)
        # if return code is 0, the kernel module is loaded, thus we need
        # to disable it
        if self.ch.getReturnCode() == 0:
            compliant = False
            debug += "Firewire kernel module is loaded\n"
            self.detailedresults += "Firewire kernel module is loaded\n"

        tb = "AppleThunderboltUTDM"
        cmd = check + "| grep " + tb
        self.ch.executeCommand(cmd)
        # if return code is 0, the kernel module is loaded, thus we need
        # to disable it
        if self.ch.getReturnCode() == 0:
            compliant = False
            debug += "Thunderbolt kernel module is loaded\n"
            self.detailedresults += "Thunderbolt kernel module is loaded\n"

        sd = "AppleSDXC"
        cmd = check + "| grep " + sd
        self.ch.executeCommand(cmd)
        # if return code is 0, the kernel module is loaded, thus we need
        # to disable it
        if self.ch.getReturnCode() == 0:
            compliant = False
            debug += "SD card kernel module is loaded\n"
            self.detailedresults += "SD card kernel module is loaded\n"
        if debug:
            self.logger.log(LogPriority.DEBUG, debug)
        return compliant
###############################################################################

    def fix(self):
        '''
        attempt to perform necessary operations to bring the system into
        compliance with this rule.

        @author bemalmbe
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
            if self.environ.getostype() == "Mac OS X":
                self.rulesuccess = self.fixMac()
            else:
                output = ""
                changed = False
                tempstring = ""
                grub = "/etc/grub.conf"
                blacklistf = "/etc/modprobe.d/stonix-blacklist.conf"
                if os.path.exists(grub):
                    if not checkPerms(grub, [0, 0, 384], self.logger):
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        if not setPerms(grub, [0, 0, 384], self.logger, "",
                                        self.statechglogger, myid):
                            success = False
                    contents = readFile(grub, self.logger)
                    if contents:
                        for line in contents:
                            if re.search("^kernel", line):
                                if not re.search("\s+nousb\s+", line):
                                    tempstring += line.strip() + " nousb\n"
                                    changed = True
                            else:
                                tempstring += line
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
                tempstring = ""
                # this portion only for zypper based systems (opensuse)
                if self.ph.manager == "zypper":
                    if self.blacklist:
                        modfile = "/etc/modprobe.d/50-blacklist.conf"
                        contents = readFile(modfile, self.logger)
                        if self.created:
                            self.iditerator += 1
                            myid = iterate(self.iditerator, self.rulenumber)
                            event = {"eventtype": "creation",
                                     "filepath": modfile}
                            self.statechglogger.recordchgevent(myid, event)
                        else:
                            if not checkPerms(modfile, [0, 0, 420],
                                              self.logger):
                                self.iditerator += 1
                                myid = iterate(self.iditerator,
                                               self.rulenumber)
                                if not setPerms(modfile, [0, 0, 420],
                                   self.logger, self.statechglogger, myid):
                                    success = False
                            for line in contents:
                                tempstring += line
                        for item in self.blacklist:
                            tempstring += item + "\n"
                        tmpfile = modfile + ".tmp"
                        if writeFile(tmpfile, tempstring, self.logger):
                            if not self.created:
                                self.iditerator += 1
                                myid = iterate(self.iditerator,
                                               self.rulenumber)
                                event = {"eventtype": "conf",
                                         "filepath": modfile}
                                self.statechglogger.recordchgevent(myid,
                                                                   event)
                                self.statechglogger.recordfilechange(modfile,
                                                                     tmpfile,
                                                                     myid)
                            os.rename(tmpfile, modfile)
                            os.chown(modfile, 0, 0)
                            os.chmod(modfile, 420)
                            resetsecon(modfile)
                else:
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
                # get the current version of the kernel
                self.wait = False
                self.ch.executeCommand("uname -r")
                self.wait = True
                output = self.ch.getOutput()
                if output:
                    output = output[0].strip()
                    if os.path.exists("/lib/modules/" + output +
                                      "/kernel/drivers/usb/storage/usb-storage.ko"):
                        os.rename("/lib/modules/" + output +
                                  "/kernel/drivers/usb/storage/usb-storage.ko",
                                  "/usb-storage.ko")

                for item in self.pcmcialist:
                    if self.ph.check(item):
                        self.ph.remove(item)
                        self.pkgremovedlist.append(item)
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
        @author: bemalmbe
        @return: bool
        @change: dwalker 8/19/2014
        '''
        debug = ""
        check = "/usr/sbin/kextstat "
        unload = "/sbin/kextunload "
        load = "/sbin/kextload "
        filepath = "/System/Library/Extensions/"
        success = True
        if self.usbci.getcurrvalue():
            created1, created2 = False, False
            usb = "IOUSBMassStorageClass"
            cmd = check + "| grep " + usb
            self.ch.executeCommand(cmd)

            # if return code is 0, the kernel module is loaded, thus we need
            # to disable it
            if self.ch.getReturnCode() == 0:
                cmd = unload + filepath + usb + ".kext/"
                if not self.ch.executeCommand(cmd):
                    debug += "Unable to disable USB\n"
                    success = False
                else:
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    undo = load + filepath + usb + ".kext/"
                    event = {"eventtype": "comm",
                             "command": undo}
                    self.statechglogger.recordchgevent(myid, event)
            if not os.path.exists(self.plistpath):
                if createFile(self.plistpath, self.logger):
                    created1 = True
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    event = {"eventtype": "creation",
                             "filepath": self.plistpath}
                    self.statechglogger.recordchgevent(myid, event)
            if os.path.exists(self.plistpath):
                if not created1:
                    statdata = os.stat(self.plistpath)
                    mode = stat.S_IMODE(statdata.st_mode)
                    ownergrp = getUserGroupName(self.plistpath)
                    owner = ownergrp[0]
                    group = ownergrp[1]
                    if mode != 420 or owner != "root" or group != "wheel":
                        origuid = statdata.st_uid
                        origgid = statdata.st_gid
                        if grp.getgrnam("wheel")[2] != "":
                            if pwd.getpwnam("root")[2] != "":
                                gid = grp.getgrnam("wheel")[2]
                                uid = pwd.getpwnam("root")[2]
                                self.iditerator += 1
                                myid = iterate(self.iditerator,
                                               self.rulenumber)
                                event = {"eventtype": "perm",
                                         "startstate": [origuid,
                                                        origgid, mode],
                                         "endstate": [uid, gid, 420],
                                         "filepath": self.plistpath}
                contents = readFile(self.plistpath, self.logger)
                contentstring = ""
                for line in contents:
                    contentstring += line
                if not re.search("^" + self.plistcontents + "?", contentstring):
                    tmpfile = self.plistpath + ".tmp"
                    if not writeFile(tmpfile, contentstring, self.logger):
                        success = False
                    elif not created1:
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        event = {"eventtype": "conf",
                                 "filepath": self.plistpath}
                        self.statechglogger.recordchgevent(myid, event)
                        self.statechglogger.recordfilechange(self.plistpath,
                                                             tmpfile, myid)
        if self.fwci.getcurrvalue():
            fw = "IOFireWireSerialBusProtocolTransport"
            cmd = check + "| grep " + fw
            self.ch.executeCommand(cmd)

            # if return code is 0, the kernel module is loaded, thus we need
            # to disable it
            if self.ch.getReturnCode() == 0:
                cmd = unload + filepath + fw + ".kext/"
                if not self.ch.executeCommand(cmd):
                    debug += "Unable to disable Firewire\n"
                    success = False
                else:
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    undo = load + filepath + fw + ".kext/"
                    event = {"eventtype": "comm",
                             "command": undo}
                    self.statechglogger.recordchgevent(myid, event)
        if self.tbci.getcurrvalue():
            tb = "AppleThunderboltUTDM"
            cmd = check + "| grep " + tb
            self.ch.executeCommand(cmd)

            # if return code is 0, the kernel module is loaded, thus we need
            # to disable it
            if self.ch.getReturnCode() == 0:
                cmd = unload + "/System/Library/Extensions/" + tb + ".kext/"
                if not self.ch.executeCommand(cmd):
                    debug += "Unable to disable Thunderbolt\n"
                    success = False
                else:
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    undo = load + filepath + tb + ".kext/"
                    event = {"eventtype": "comm",
                             "command": undo}
                    self.statechglogger.recordchgevent(myid, event)
        if self.sdci.getcurrvalue():
            sd = "AppleSDXC"
            cmd = check + "| grep " + sd
            self.ch.executeCommand(cmd)

            # if return code is 0, the kernel module is loaded, thus we need
            # to disable it
            if self.ch.getReturnCode() == 0:
                cmd = unload + "/System/Library/Extensions/" + sd + ".kext/"
                if not self.ch.executeCommand(cmd):
                    debug += "Unable to disable SD Card functionality\n"
                    success = False
                else:
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    undo = load + filepath + sd + ".kext/"
                    event = {"eventtype": "comm",
                             "command": undo}
                    self.statechglogger.recordchgevent(myid, event)
        if debug:
            self.logger.log(LogPriority.DEBUG, debug)
        return success
