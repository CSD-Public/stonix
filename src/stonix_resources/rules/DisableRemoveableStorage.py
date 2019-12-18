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
@change: 2017/08/28 rsn Fixing to use new help text methods
@change: 2017/11/13 ekkehard - make eligible for OS X El Capitan 10.11+
@change: 2018/4/17 dwalker - added additional measures to ensure
    disablement of removable storage.  Cleaned up code
@change: 2018/06/08 ekkehard - make eligible for macOS Mojave 10.14
@change: 2019/03/12 ekkehard - make eligible for macOS Sierra 10.12+
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
from ..KVEditorStonix import KVEditorStonix

class DisableRemoveableStorage(Rule):
    '''Disable removeable storage. This rule is optional, and disables USB, thunderbolt and firewire
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
                           'os': {'Mac OS X': ['10.12', 'r', '10.14.10']},
                           'fisma': 'high'}

        # configuration item instantiation
        datatype = "bool"
        key = "DISABLEREMOVEABLESTORAGE"
        instructions = "To disable removeable storage devices on this system, set the value of DISABLEREMOVEABLESTORAGE to True"
        default = False
        self.storageci = self.initCi(datatype, key, instructions, default)

        #global variables
        self.grubfiles = ["/boot/grub2/grub.cfg",
                          "/boot/grub/grub.cfg",
                          "/boot/grub/grub.conf"]
        self.pcmcialist = ['pcmcia-cs', 'kernel-pcmcia-cs', 'pcmciautils']
        self.pkgremovedlist = []
        self.iditerator = 0
        self.created = False
        self.daemonpath = os.path.abspath(os.path.join(os.path.dirname(sys.argv[0]))) + "/stonix_resources/disablestorage.py"
        self.sethelptext()
        self.grubperms = ""
        self.ph = Pkghelper(self.logger, self.environ)
        self.ch = CommandHelper(self.logger)

    def report(self):
        '''report the current rule-compliance status of this system. update
        self.rulesuccess if method does not succeed. self.compliant if
        rule succeeds and reports true.


        :returns: self.compliant

        :rtype: bool

@author: Breen Malmberg

@change: dwalker - implementing kveditor and completely revamped rule
    logic. added event deletion at the beginning of the fix
@change: dwalker 8/13/2014 changed name of rule to
    DisableRemoveableStorage and rule now supports disabling other
    ports such thunderbolt and firewire

        '''

        try:
            self.detailedresults = ""
            if self.environ.getostype() == "Mac OS X":
                compliant = self.reportMac()
            else:
                compliant = self.reportLinux()
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

    def reportLinux(self):
        '''sub method for linux portion of compliance reporting
        @author: dwalker


        :returns: compliant

        :rtype: boolean

        '''
        compliant = True
        lsmodcmd = ""

        # determine location of lsmod binary
        if os.path.exists("/sbin/lsmod"):
            lsmodcmd = "/sbin/lsmod"
        elif os.path.exists("/usr/bin/lsmod"):
            lsmodcmd = "/usr/bin/lsmod"

        usbmods = ["usb_storage",
                   "usb-storage"]
        # run lsmod command and look for any of the items from
        # usbmods list in the output.  If item exists in output
        # then that usb module is not disabled.  This is for
        # reporting only.  There is no fix using lsmod command.
        if lsmodcmd:
            for usb in usbmods:
                cmd = [lsmodcmd, "|", "grep", usb]
                self.ch.executeCommand(cmd)
                if self.ch.getReturnCode() == "0":
                    compliant = False
                    self.detailedresults += "lsmod command shows usb not disabled\n"
                    break

        # check compliance of grub file(s) if files exist
        if re.search("Red Hat", self.environ.getostype()) and \
                re.search("^6", self.environ.getosver()):
            self.grubperms = [0, 0, 0o600]
        elif self.ph.manager is "apt-get":
            self.grubperms = [0, 0, 0o400]
        else:
            self.grubperms = [0, 0, 0o644]
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
                            if not re.search("\s+nousb\s*", line):
                                debug = grub + " file doesn't " + \
                                        "contain nousb kernel option\n"
                                self.detailedresults += grub + " file doesn't " + \
                                                        "contain nousb kernel option\n"
                                self.logger.log(LogPriority.DEBUG,
                                                debug)
                                compliant = False
                            if not re.search("\s+usbcore\.authorized_default=0\s*", line):
                                debug = grub + " file doesn't " + \
                                        "contain usbcore.authorized_default=0 " + \
                                        "kernel option\n"
                                self.detailedresults += grub + " file doesn't " + \
                                                        "contain usbcore.authorized_default=0 " + \
                                                        "kernel option\n"
                                self.logger.log(LogPriority.DEBUG,
                                                debug)
                                compliant = False
        # check for existence of certain usb packages, non-compliant
        # if any exist
        for item in self.pcmcialist:
            if self.ph.check(item):
                self.detailedresults += item + " is installed " + \
                                        "and shouldn't be\n"
                compliant = False

        # check modprobe files inside modprobe.d directory for
        # contents inside self.blacklist variable
        removeables = []
        found1 = True
        # self.blacklist dictionary contains the directives
        # and the value we're looking for (key) and contains
        # a default value of False for each one.  Upon finding
        # each directive and value pair e.g. blacklist usb_storage
        # the dictionary is updated with a True value.  This keeps
        # track of the directives we didnt find or that had
        # incorrect values
        self.blacklist = {"blacklist usb_storage": False,
                          "install usbcore /bin/true": False,
                          "install usb-storage /bin/true": False,
                          "blacklist uas": False,
                          "blacklist firewire-ohci": False,
                          "blacklist firewire-sbp2": False}
        #check if /etc/modprobe.d directory exists
        if os.path.exists("/etc/modprobe.d"):
            #extract all files inside modprobe.d
            dirs = glob.glob("/etc/modprobe.d/*")
            # since file name doesn't matter
            # i.e. all files are read and treated the same in
            # modprobe.d, if directives are found in any of
            # the files inside this directory, where they don't
            # have to be in the same file, the system is compliant
            for directory in dirs:
                if os.path.isdir(directory):
                    continue
                contents = readFile(directory, self.logger)
                for item in self.blacklist:
                    for line in contents:
                        if re.search("^" + item, line.strip()):
                            self.blacklist[item] = True
            # if we don't find all directives in any of the files in
            # modprobe.d, we will now check /etc/modprobe.conf as
            # they are all equivalent. We will still keep track of
            # whether we already found one directive in one of the
            # files in modprobe.d
            for item in self.blacklist:
                if not self.blacklist[item]:
                    found1 = False
        else:
            found1 = False

        # either not all directives inside self.blacklist were found
        # or /etc/modprobe.d didn't exist.  Now we check /etc/modprobe.conf
        # for any remaining unfound directives.
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
        # any directives that were found we remove from self.blacklist
        # We must add to a variable called removeables first then
        # iterate through removeables and remove each item self.blacklist
        for item in self.blacklist:
            if self.blacklist[item]:
                removeables.append(item)
        for item in removeables:
            del (self.blacklist[item])

        # check the contents of the udev file for a certain desired line
        self.udevfile = "/etc/udev/rules.d/10-local.rules"
        found2 = False
        if os.path.exists(self.udevfile):
            if not checkPerms(self.udevfile, [0, 0, 0o644], self.logger):
                self.detailedresults += "Permissions not correct " + \
                                        "on " + self.udevfile + "\n"
                compliant = False
            contents = readFile(self.udevfile, self.logger)
            for line in contents:
                if re.search("ACTION\=\=\"add\"\, SUBSYSTEMS\=\=\"usb\"\, RUN\+\=\"/bin/sh \-c \'for host in /sys/bus/usb/devices/usb\*\; do echo 0 \> \$host/authorized\_default\; done\'\"",
                        line.strip()):
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
        return compliant

    def reportMac(self):
        '''


        :returns: compliant

        :rtype: bool

        '''

        self.detailedresults = ""
        compliant = True
        self.setvars()
        if not self.usbprofile:
            self.detailedresults += "Could not locate the appropriate usb disablement profile for your system.\n"
            compliant = False
            self.formatDetailedResults("report", compliant, self.detailedresults)
            self.logdispatch.log(LogPriority.INFO, self.detailedresults)
            return compliant
        self.usbdict = {"com.apple.systemuiserver": {"harddisk-external": {"val": ["deny", "eject"],
                                                                           "type": "",
                                                                           "accept": "",
                                                                           "result": False}}}
        self.usbeditor = KVEditorStonix(self.statechglogger, self.logger,
                                       "profiles", self.usbprofile, "",
                                       self.usbdict, "", "")
        if not self.usbeditor.report():
            if self.usbeditor.badvalues:
                self.detailedresults += self.usbeditor.badvalues + "\n"
            self.detailedresults += "USB Disablement profile either not installed or values are incorrect\n"
            compliant = False
        return compliant

    def setvars(self):
        self.usbprofile = ""
        #baseconfigpath = "/Applications/stonix4mac.app/Contents/Resources/stonix.app/Contents/MacOS/stonix_resources/files/"
        #self.usbprofile = baseconfigpath + "stonix4macDisableUSB.mobileconfig"

        # the following path and dictionaries are for testing on local vm's
        # without installing stonix package each time.  DO NOT DELETE
        basetestpath = "/Users/dwalker/stonix/src/stonix_resources/files/"
        self.usbprofile = basetestpath + "stonix4macDisableUSB.mobileconfig"
        if not os.path.exists(self.usbprofile):
            self.logger.log(LogPriority.DEBUG, "Could not locate appropriate usb disablement profile\n")
            self.usbprofile = ""

    def fix(self):
        '''attempt to perform necessary operations to bring the system into
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
                self.rulesuccess = False
                self.formatDetailedResults("fix", self.rulesuccess, self.detailedresults)
                self.logdispatch.log(LogPriority.INFO, self.detailedresults)
                return self.rulesuccess
            if self.environ.getostype() == "Mac OS X":
                success = self.fixMac()
            else:
                success = self.fixLinux()
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


        :returns: bool
        @change: dwalker 8/19/2014

        '''
        success = True
        if not self.usbprofile:
            return False
        if not self.usbeditor.report():
            if self.usbeditor.fix():
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                self.usbeditor.setEventID(myid)
                if not self.usbeditor.commit():
                    success = False
                    self.detailedresults += "Unable to install " + self.usbprofile + " profile\n"
                    self.logdispatch.log(LogPriority.DEBUG, "Kveditor commit failed")
            else:
                success = False
                self.detailedresults += "Unable to install " + self.passprofile + "profile\n"
                self.logdispatch.log(LogPriority.DEBUG, "Kveditor fix failed")
        else:
            success = False
            self.detailedresults += "Password CI was not enabled.\n"
        return success

    def fixLinux(self):
        '''sub method for linux portion of compliance fixing
        @author: dwalker


        :returns: success

        :rtype: boolean

        '''
        success = True
        created1, created2 = False, False
        changed = False
        tempstring = ""
        grubfilefound = False

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
                            if not re.search("\s+nousb\s*", line):
                                changed = True
                                tempstring += line.strip() + " nousb"
                            if not re.search("\s+usbcore\.authorized_default=0\s+", line):
                                changed = True
                                tempstring += line.strip() + " usbcore.authorized_default=0"
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
                        if not setPerms(grub, self.grubperms, self.logger):
                            success = False
                            self.detailedresults += "Unable to set permissions on " + \
                                                    grub + " file\n"
                    else:
                        success = False
        if not grubfilefound:
            self.detailedresults += "No grub configuration file found\n" + \
                                    "Unable to fully fix system for this rule\n"
            success = False
        blacklistf = "/etc/modprobe.d/stonix-blacklist.conf"
        tempstring = ""
        # Check if self.blacklist still contains values, if it
        # does, then we didn't find all the blacklist values
        # in report
        if self.blacklist:
            # didn't find one or more directives in the files
            # inside modprobe.d so we now check an alternate file
            # we create stonixblacklist file if it doesn't
            # exist and put remaining unfound blacklist
            # items there
            if not os.path.exists(blacklistf):
                created1 = True
                createFile(blacklistf, self.logger)
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                event = {"eventtype": "creation",
                         "filepath": blacklistf}
                self.statechglogger.recordchgevent(myid, event)
            # file was already present and we need contents already
            # inside file to remain in newly written file
            if not created1:
                contents = readFile(blacklistf, self.logger)
                for item in contents:
                    tempstring += item
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
            if not checkPerms(blacklistf, [0, 0, 420],
                              self.logger):
                self.iditerator += 1
                myid = iterate(self.iditerator,
                               self.rulenumber)
                if not setPerms(blacklistf, [0, 0, 420],
                                self.logger,
                                self.statechglogger, myid):
                    success = False
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
                created2 = True
        if os.path.exists(self.udevfile):
            if not checkPerms(self.udevfile, [0, 0, 0o644], self.logger):
                if created2:
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
                if re.search(
                        "ACTION==\"add\"\, SUBSYSTEMS==\"usb\"\, RUN+=\"/bin/sh -c \'for host in /sys/bus/usb/devices/usb\*\; do echo 0 > \$host/authorized_default; done\'\"",
                        line.strip()):
                    found = True
                tempstring += line
            if not found:
                tempstring += "ACTION==\"add\", SUBSYSTEMS==\"usb\", RUN+=\"/bin/sh -c \'for host in /sys/bus/usb/devices/usb*; do echo 0 > $host/authorized_default; done\'\""
                tmpfile = self.udevfile + ".tmp"
                if writeFile(tmpfile, tempstring,
                             self.logger):
                    if not created2:
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
        return success