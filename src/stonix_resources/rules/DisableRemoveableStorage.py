###############################################################################
#                                                                             #
# Copyright 2015-2017.  Los Alamos National Security, LLC. This material was  #
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
@change: 2016/03/01 ekkehard cgi default value set to False
@change: 2017/03/30 dkennel Added fisma = high to applicable dictionary
@change: 2017/07/07 ekkehard - make eligible for macOS High Sierra 10.13
@change 2017/08/28 rsn Fixing to use new help text methods
@change: 2017/11/13 ekkehard - make eligible for OS X El Capitan 10.11+
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
from time import sleep
import stat
import pwd
import grp
import sys


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
        self.guidance = ['NSA 2.2.2.2, CIS, NSA(2.2.2.2), cce-4006-3,4173-1']
        self.applicable = {'type': 'white',
                           'family': ['linux', 'solaris', 'freebsd'],
                           'os': {'Mac OS X': ['10.11', 'r', '10.13.10']},
                           'fisma': 'high'}

        # configuration item instantiation
        datatype = "bool"
        key = "DISABLESTORAGE"
        instructions = "To disable removeable storage devices on this " + \
            "system, set the value of DISABLESTORAGE to True"
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
                found = True
                self.blacklist = {}
                self.blacklist["blacklist usb_storage"] = False
                self.blacklist["install usbcore /bin/true"] = False
                self.blacklist["blacklist usb-storage"] = False
                self.blacklist["install usb-storage /bin/true"] = False
                # first check for files in modprobe.d, first choice
                self.blacklist["blacklist uas"] = False
                self.blacklist["blacklist firewire-ohci"] = False
                self.blacklist["blacklist firewire-sbp2"] = False
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
#         self.plistpath = "/Library/LaunchDaemons/gov.lanl.stonix.disablestorage.plist"
#         self.plistcontents = '''<?xml version="1.0" encoding="UTF-8"?>
# <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
# <plist version="1.0">
# <dict>
#      <key>Label</key>
#      <string>gov.lanl.stonix.disablestorage</string>
#      <key>ProgramArguments</key>
#      <array>
#          <string>sh</string>
#          <string>-c</string>
#          <string>''' + self.daemonpath + '''</string>
#      </array>
#      <key>StartOnMount</key>
#      <true/>
#      <key>RunAtLoad</key>
#      <true/>
#      <key>KeepAlive</key>
#      <true/>
# </dict>
# </plist>
# '''
#         self.plistcontents2 = '''<?xml version="1.0" encoding="UTF-8"?>
# <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
# "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
# <plist version="1.0">
# <dict>
#     <key>LimitLoadToSessionType</key>
#     <string>Aqua</string>
#     <key>Label</key>
#     <string>gov.lanl.stonix.disablestorage2</string>
#     <key>ProgramArguments</key>
#     <array>
#         <string>sh</string>
#         <string>-c</string>
#         <string>''' + self.daemonpath + '''</string>
#     </array>
#     <key>KeepAlive</key>
#     <true/>
#     <key>RunAtLoad</key>
#     <true/>
# </dict>
# </plist>'''
#         self.daemoncontents = '''#!/usr/bin/python
# \'\'\'
# Created on Jan 5, 2016
# @author: dwalker
# \'\'\'
# import re
# from subprocess import PIPE, Popen, call
# 
# 
# def main():
#     check = "/usr/sbin/kextstat "
#     proc2 = Popen('/usr/bin/sw_vers -productVersion', shell=True, stdout=PIPE)
#     release = proc2.stdout.readline()
#     release = release.strip()
#     osversion = release
#     unload = "/sbin/kextunload "
#     filepath = "/System/Library/Extensions/"
#     if re.search("^10.11", osversion):
#         usb = "IOUSBMassStorageDriver"
#     else:
#         usb = "IOUSBMassStorageClass"
#     cmd = check + "| grep " + usb
#     retcode = call(cmd, shell=True)
#     if retcode == 0:
#         cmd = unload + filepath + usb + ".kext/"
#         call(cmd, shell=True)
#     fw = "IOFireWireFamily"
#     cmd = check + "| grep " + fw
#     retcode = call(cmd, shell=True)
#     if retcode == 0:
#         cmd = unload + filepath + fw + ".kext/Contents/PlugIns/AppleFWOHCI.kext/"
#         call(cmd, shell=True)
#     tb = "AppleThunderboltUTDM"
#     cmd = check + "| grep " + tb
#     retcode = call(cmd, shell=True)
#     if retcode == 0:
#         cmd = unload + "/System/Library/Extensions/" + tb + ".kext/"
#         call(cmd, shell=True)
#     sd = "AppleSDXC"
#     cmd = check + "| grep " + sd
#     retcode = call(cmd, shell=True)
#     if retcode == 0:
#         cmd = unload + "/System/Library/Extensions/" + sd + ".kext/"
#         call(cmd, shell=True)
# 
# 
# if __name__ == '__main__':
#     main()
# '''     
#         self.plistregex = "<\?xml version\=\"1\.0\" encoding\=\"UTF\-8\"\?>" + \
#             "<!DOCTYPE plist PUBLIC \"\-//Apple//DTD PLIST 1\.0//EN\" \"http://www\.apple\.com/DTDs/PropertyList\-1\.0\.dtd\">" + \
#             "<plist version\=\"1\.0\"><dict><key>Label</key><string>gov\.lanl\.stonix\.disablestorage</string>" + \
#             "<key>ProgramArguments</key>" + \
#             "<array>" + \
#             "<string>sh</string>" + \
#             "<string>\-c</string>" + \
#             "<string>" + re.escape(self.daemonpath) + "</string>" + \
#             "</array>" + \
#             "<key>StartOnMount</key><true/><key>RunAtLoad</key><true/>" + \
#             "<key>KeepAlive</key><true/></dict></plist>"
#         self.daemonregex = "\#\!/usr/bin/python\n\'\'\'\nCreated on Jan 5\, 2016\n@author: dwalker\n\'\'\'\n" + \
#             "import re\n" + \
#             "from Subprocess import PIPE\, Popen\, call\n\n" + \
#             "def main\(\):\n" + \
#             "    check \= \"/usr/sbin/kextstat \"\n" + \
#             "    proc2 = Popen\(\'/usr/bin/sw\_vers \-productVersion\'\, shell\=True\, stdout\=PIPE\)\n" + \
#             "    release \= proc2\.stdout\.readline\(\)\n" + \
#             "    release \= release\.strip\(\)\n" + \
#             "    osversion \= release\n" + \
#             "    unload \= \"/sbin/kextunload \"\n" + \
#             "    filepath \= \"/System/Library/Extensions/\"\n" + \
#             "    if re\.search\(\"\^10\.11\"\, osversion\):\n" + \
#             "        usb \= \"IOUSBMassStorageDriver\"\n" + \
#             "    else:\n" + \
#             "        usb \= \"IOUSBMassStorageClass\"\n" + \
#             "    cmd \= check + \"\| grep \" + usb\n" + \
#             "    retcode \= call\(cmd\, shell\=True\)" + \
#             "    if retcode \=\=0:\n" + \
#             "        cmd \= unload \+ filepath \+ usb \+ \"\.kext/\"\n" + \
#             "        call\(cmd\, shell\=True\)\n" + \
#             "    fw \= \"IOFireWireFamily\"\n" + \
#             "    cmd \= check \+ \"\| grep \" \+ fw\n" + \
#             "    retcode \= call\(cmd\, shell\=True\)" + \
#             "    if retcode \=\=0:\n" + \
#             "        cmd \= unload \+ filepath \+ fw \+ \"\.kext/Contents/PlugIns/AppleFWOHCI\.kext/\"\n" + \
#             "        call\(cmd\, shell\=True\)\n" + \
#             "    tb \= \"AppleThunderboltUTDM\"\n" + \
#             "    cmd \= check \+ \"\| grep \" \+ fw\n" + \
#             "    retcode \= call\(cmd\, shell\=True\)" + \
#             "    if retcode \=\=0:\n" + \
#             "        cmd \= unload \+ filepath \+ tb \+ \"\.kext/\"\n" + \
#             "        retcode\(cmd\, shell\=True\)\n" + \
#             "    sd \= \"AppleSDXC\"\n" + \
#             "    cmd \= check \+ \"\| grep \" \+ sd\n" + \
#             "    retcode \= call\(cmd\, shell\=True\)" + \
#             "    if retcode \=\=0:\n" + \
#             "        cmd \= unload \+ filepath \+ sd \+ \"\.kext/\"\n" + \
#             "        call\(cmd\, shell\=True\)\n\n\n" + \
#             "if __name__ \=\= \'__main__\':\n    main()\n"
#         if os.path.exists(self.plistpath):
#             statdata = os.stat(self.plistpath)
#             mode = stat.S_IMODE(statdata.st_mode)
#             ownergrp = getUserGroupName(self.plistpath)
#             owner = ownergrp[0]
#             group = ownergrp[1]
#             if mode != 420:
#                 compliant = False
#                 self.detailedresults += "permissions on " + self.plistpath + \
#                     "aren't 644\n"
#                 debug = "permissions on " + self.plistpath + " aren't 644\n"
#                 self.logger.log(LogPriority.DEBUG, debug)
#             if owner != "root":
#                 compliant = False
#                 self.detailedresults += "Owner of " + self.plistpath + \
#                     " isn't root\n"
#                 debug = "Owner of " + self.plistpath + \
#                     " isn't root\n"
#                 self.logger.log(LogPriority.DEBUG, debug)
#             if group != "wheel":
#                 compliant = False
#                 self.detailedresults += "Group of " + self.plistpath + \
#                     " isn't wheel\n"
#                 debug = "Group of " + self.plistpath + \
#                     " isn't wheel\n"
#                 self.logger.log(LogPriority.DEBUG, debug)
#             contents = readFile(self.plistpath, self.logger)
#             contentstring = ""
#             for line in contents:
#                 contentstring += line.strip()
#             if not re.search(self.plistregex, contentstring):
#                 compliant = False
#                 self.detailedresults += "plist file doesn't contain the " + \
#                     "correct contents\n"
#         else:
#             compliant = False
#             self.detailedresults += "daemon plist file doesn't exist\n"
#         if os.path.exists(self.daemonpath):
#             statdata = os.stat(self.daemonpath)
#             mode = stat.S_IMODE(statdata.st_mode)
#             if mode != 509:
#                 compliant = False
#                 self.detailedresults += "permissions on " + self.daemonpath + \
#                     " aren't 775\n"
#                 debug = "permissions on " + self.daemonpath + " aren't 775\n"
#                 self.logger.log(LogPriority.DEBUG, debug)
#             contents = readFile(self.daemonpath, self.logger)
#             contentstring = ""
#             for line in contents:
#                 contentstring += line
#             if contentstring != self.daemoncontents:
#                 compliant = False
#                 self.detailedresults += "disablestorage.py file doesn't " + \
#                     "contain the correct contents\n"
#         else:
#             compliant = False
#             self.detailedresults += "disablestorage file doesn't exist\n"
#         check = "/usr/sbin/kextstat "
#         self.ch = CommandHelper(self.logger)
#         if re.search("^10.11", self.environ.getosver()):
#             usb = "IOUSBMassStorageDriver"
#         else:
#             usb = "IOUSBMassStorageClass"
#         cmd = check + "| grep " + usb
#         self.ch.executeCommand(cmd)
# 
#         # if return code is 0, the kernel module is loaded, thus we need
#         # to disable it
#         if self.ch.getReturnCode() == 0:
#             compliant = False
#             debug += "USB Kernel module is loaded\n"
#             self.detailedresults += "USB Kernel module is loaded\n"
#         fw = "IOFireWireFamily"
#         #fw = "IOFireWireSerialBusProtocolTransport"
#         cmd = check + "| grep " + fw
#         self.ch.executeCommand(cmd)
#         # if return code is 0, the kernel module is loaded, thus we need
#         # to disable it
#         if self.ch.getReturnCode() == 0:
#             '''Do not set compliant False here.  Due to issues with Mac
#             This is going to fail no matter what.  Other compliancy 
#             checks will still ensure the rule is compliant or not'''
#             debug += "Firewire kernel module is loaded\n"
#             self.detailedresults += "Firewire kernel module is loaded\n"
# 
#         tb = "AppleThunderboltUTDM"
#         cmd = check + "| grep " + tb
#         self.ch.executeCommand(cmd)
#         # if return code is 0, the kernel module is loaded, thus we need
#         # to disable it
#         if self.ch.getReturnCode() == 0:
#             compliant = False
#             debug += "Thunderbolt kernel module is loaded\n"
#             self.detailedresults += "Thunderbolt kernel module is loaded\n"
# 
#         sd = "AppleSDXC"
#         cmd = check + "| grep " + sd
#         self.ch.executeCommand(cmd)
#         # if return code is 0, the kernel module is loaded, thus we need
#         # to disable it
#         if self.ch.getReturnCode() == 0:
#             compliant = False
#             debug += "SD card kernel module is loaded\n"
#             self.detailedresults += "SD card kernel module is loaded\n"
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
            if self.storageci.getcurrvalue():
                if self.environ.getostype() == "Mac OS X":
                    success = self.fixMac()
                else:
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
#         if not os.path.exists(self.plistpath):
#             createFile(self.plistpath, self.logger)
#         self.iditerator += 1
#         myid = iterate(self.iditerator, self.rulenumber)
#         cmd = "/bin/launchctl unload " + self.plistpath
#         event = {"eventtype": "commandstring",
#                  "command": cmd}
#         self.statechglogger.recordchgevent(myid, event)
#         #created1 = True
#         self.iditerator += 1
#         myid = iterate(self.iditerator, self.rulenumber)
#         event = {"eventtype": "creation",
#                  "filepath": self.plistpath}
#         self.statechglogger.recordchgevent(myid, event)
#         if os.path.exists(self.plistpath):
#             uid, gid = "", ""
#             statdata = os.stat(self.plistpath)
#             mode = stat.S_IMODE(statdata.st_mode)
#             ownergrp = getUserGroupName(self.plistpath)
#             owner = ownergrp[0]
#             group = ownergrp[1]
#             if grp.getgrnam("wheel")[2] != "":
#                 gid = grp.getgrnam("wheel")[2]
#             if pwd.getpwnam("root")[2] != "":
#                 uid = pwd.getpwnam("root")[2]
# #             if not created1:
# #                 if mode != 420 or owner != "root" or group != "wheel":
# #                     origuid = statdata.st_uid
# #                     origgid = statdata.st_gid
# #                     if gid:
# #                         if uid:
# #                             self.iditerator += 1
# #                             myid = iterate(self.iditerator,
# #                                            self.rulenumber)
# #                             event = {"eventtype": "perm",
# #                                      "startstate": [origuid,
# #                                                     origgid, mode],
# #                                      "endstate": [uid, gid, 420],
# #                                      "filepath": self.plistpath}
#             contents = readFile(self.plistpath, self.logger)
#             contentstring = ""
#             for line in contents:
#                 contentstring += line.strip()
#             if not re.search(self.plistregex, contentstring):
#                 tmpfile = self.plistpath + ".tmp"
#                 if not writeFile(tmpfile, self.plistcontents, self.logger):
#                     success = False
# #                 elif not created1:
# #                     self.iditerator += 1
# #                     myid = iterate(self.iditerator, self.rulenumber)
# #                     event = {"eventtype": "conf",
# #                              "filepath": self.plistpath}
# #                     self.statechglogger.recordchgevent(myid, event)
# #                     self.statechglogger.recordfilechange(self.plistpath,
# #                                                          tmpfile, myid)
# #                     os.rename(tmpfile, self.plistpath)
# #                     if uid and gid:
# #                         os.chown(self.plistpath, uid, gid)
# #                     os.chmod(self.plistpath, 420)
#                 else:
#                     os.rename(tmpfile, self.plistpath)
#                     if uid and gid:
#                         os.chown(self.plistpath, uid, gid)
#                     os.chmod(self.plistpath, 420)
#         if not os.path.exists(self.daemonpath):
#             if not createFile(self.daemonpath, self.logger):
#                 success = False
#                 self.detailedresults += "Unable to create the disablestorage python file\n"
#             else:
#                 self.iditerator += 1
#                 myid = iterate(self.iditerator, self.rulenumber)
#                 event = {"eventtype": "creation",
#                          "filepath": self.daemonpath}
#         self.statechglogger.recordchgevent(myid, event)
#         if os.path.exists(self.daemonpath):
#             uid, gid = "", ""
#             statdata = os.stat(self.daemonpath)
#             mode = stat.S_IMODE(statdata.st_mode)
#             ownergrp = getUserGroupName(self.daemonpath)
#             owner = ownergrp[0]
#             group = ownergrp[1]
#             if grp.getgrnam("admin")[2] != "":
#                 gid = grp.getgrnam("admin")[2]
#             if pwd.getpwnam("root")[2] != "":
#                 uid = pwd.getpwnam("root")[2]
#             #if we didn't have to create the file then we want to record
#             #incorrect permissions as state event
#             if not created2:
#                 if mode != 509 or owner != "root" or group != "admin":
#                     origuid = statdata.st_uid
#                     origgid = statdata.st_gid
#                     if gid:
#                         if uid:
#                             self.iditerator += 1
#                             myid = iterate(self.iditerator,
#                                            self.rulenumber)
#                             event = {"eventtype": "perm",
#                                      "startstate": [origuid,
#                                                     origgid, mode],
#                                      "endstate": [uid, gid, 509],
#                                      "filepath": self.daemonpath}
#                             self.statechglogger.recordchgevent(myid, event)
#             contents = readFile(self.daemonpath, self.logger)
#             contentstring = ""
#             for line in contents:
#                 contentstring += line
#             if contentstring != self.daemoncontents:
#                 tmpfile = self.daemonpath + ".tmp"
#                 if writeFile(tmpfile, self.daemoncontents, self.logger):
#                     if not created2:
#                         self.iditerator += 1
#                         myid = iterate(self.iditerator, self.rulenumber)
#                         event = {"eventtype": "conf",
#                                  "filepath": self.daemonpath}
#                         self.statechglogger.recordchgevent(myid, event)
#                         self.statechglogger.recordfilechange(self.daemonpath,
#                                                              tmpfile, myid)
#                         os.rename(tmpfile, self.daemonpath)
#                         if uid and gid:
#                             os.chown(self.daemonpath, uid, gid)
#                         os.chmod(self.daemonpath, 509)
#                     else:
#                         os.rename(tmpfile, self.daemonpath)
#                         if uid and gid:
#                             os.chown(self.daemonpath, uid, gid)
#                         os.chmod(self.daemonpath, 509)
#                 else:
#                     success = False
#             elif not checkPerms(self.daemonpath, [0, 0, 509], self.logger):
#                 if not setPerms(self.daemonpath, [0, 0, 509], self.logger):
#                     success = False
#         if re.search("^10.11", self.environ.getosver()):
#             usb = "IOUSBMassStorageDriver"
#         else:
#             usb = "IOUSBMassStorageClass"
#         cmd = check + "| grep " + usb
#         self.ch.executeCommand(cmd)
#         # if return code is 0, the kernel module is loaded, thus we need
#         # to disable it
#         if self.ch.getReturnCode() == 0:
#             cmd = unload + filepath + usb + ".kext/"
#             if not self.ch.executeCommand(cmd):
#                 debug += "Unable to disable USB\n"
#                 success = False
#             else:
#                 self.iditerator += 1
#                 myid = iterate(self.iditerator, self.rulenumber)
#                 undo = load + filepath + usb + ".kext/"
#                 event = {"eventtype": "comm",
#                          "command": undo}
#                 self.statechglogger.recordchgevent(myid, event)
#         fw = "IOFireWireFamily"
#         #fw = "IOFireWireSerialBusProtocolTransport"
#         cmd = check + "| grep " + fw
#         self.ch.executeCommand(cmd)
# 
#         # if return code is 0, the kernel module is loaded, thus we need
#         # to disable it
#         if self.ch.getReturnCode() == 0:
#             cmd = unload + filepath + fw + ".kext/Contents/PlugIns/AppleFWOHCI.kext/"
#             if not self.ch.executeCommand(cmd):
#                 debug += "Unable to disable Firewire\n"
#                 success = False
#             else:
#                 self.iditerator += 1
#                 myid = iterate(self.iditerator, self.rulenumber)
#                 undo = load + filepath + fw + ".kext/"
#                 event = {"eventtype": "comm",
#                          "command": undo}
#                 self.statechglogger.recordchgevent(myid, event)
#         tb = "AppleThunderboltUTDM"
#         cmd = check + "| grep " + tb
#         self.ch.executeCommand(cmd)
# 
#         # if return code is 0, the kernel module is loaded, thus we need
#         # to disable it
#         if self.ch.getReturnCode() == 0:
#             cmd = unload + "/System/Library/Extensions/" + tb + ".kext/"
#             if not self.ch.executeCommand(cmd):
#                 debug += "Unable to disable Thunderbolt\n"
#                 success = False
#             else:
#                 self.iditerator += 1
#                 myid = iterate(self.iditerator, self.rulenumber)
#                 undo = load + filepath + tb + ".kext/"
#                 event = {"eventtype": "comm",
#                          "command": undo}
#                 self.statechglogger.recordchgevent(myid, event)
#         sd = "AppleSDXC"
#         cmd = check + "| grep " + sd
#         self.ch.executeCommand(cmd)
# 
#         # if return code is 0, the kernel module is loaded, thus we need
#         # to disable it
#         if self.ch.getReturnCode() == 0:
#             cmd = unload + "/System/Library/Extensions/" + sd + ".kext/"
#             if not self.ch.executeCommand(cmd):
#                 debug += "Unable to disable SD Card functionality\n"
#                 success = False
#             else:
#                 self.iditerator += 1
#                 myid = iterate(self.iditerator, self.rulenumber)
#                 undo = load + filepath + sd + ".kext/"
#                 event = {"eventtype": "comm",
#                          "command": undo}
#                 self.statechglogger.recordchgevent(myid, event)
#         sleep(30)
#         cmd = ["/bin/launchctl", "load", self.plistpath]
#         if not self.ch.executeCommand(cmd):
#             debug += "Unable to load the launchctl job to regularly " + \
#                 "disable removeable storage.  May need to be done manually\n"
#             success = False
#         cmd = ["/bin/launchctl", "load", self.plistpath]
#         if not self.ch.executeCommand(cmd):
#             debug += "Unable to load the launchctl job to regularly " + \
#                 "disable removeable storage.  May need to be done manually\n"
#             success = False
        if debug:
            self.logger.log(LogPriority.DEBUG, debug)
        return success
