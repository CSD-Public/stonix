###############################################################################
#                                                                             #
# Copyright 2015-2017.  Los Alamos National Security, LLC. This material was  #
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
Created on Apr 9, 2013

@author: dwalker
@change: 02/14/2014 ekkehard Implemented self.detailedresults flow
@change: 04/18/2014 dkennel replaced old style CI with new
@change: 06/02/2014 dkennel removed extraneous arg from setperms call on 864
@change: 2014/10/17 ekkehard OS X Yosemite 10.10 Update
@change: 2015/04/15 dkennel updated for new isApplicable
@change: 2015/10/07 eball Help text/PEP8 cleanup
@change: 2015/11/16 eball Moved all file creation from report to fix
@change: 2017/6/29  bgonz12 Added fix in ReportLinux for machines that have
                            deprecated "ifconfig"
@change: 2017/07/07 ekkehard - make eligible for macOS High Sierra 10.13
@change: 2017/08/28 rsn Fixing to use new help text methods
@change: 2017/10/23 rsn - change to new service helper interface
@change: 2017/11/13 ekkehard - make eligible for OS X El Capitan 10.11+
@change: 2018/04/10 dkennel - commented out module killing code and set
                        default to False per artf48817
'''
from __future__ import absolute_import
from ..stonixutilityfunctions import iterate, setPerms, checkPerms, writeFile
from ..stonixutilityfunctions import readFile, resetsecon, createFile
from ..rule import Rule
from ..logdispatcher import LogPriority
from ..KVEditorStonix import KVEditorStonix
from ..pkghelper import Pkghelper
from ..CommandHelper import CommandHelper
from ..ServiceHelper import ServiceHelper
import traceback
import os
import re
import glob


class DisableIPV6(Rule):

    def __init__(self, config, environ, logger, statechglogger):
        Rule.__init__(self, config, environ, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 123
        self.rulename = "DisableIPV6"
        self.formatDetailedResults("initialize")
        self.guidance = ["NSA 2.5.3.1"]
        self.applicable = {'type': 'white',
                           'family': ['linux', 'solaris', 'freebsd'],
                           'os': {'Mac OS X': ['10.11', 'r', '10.13.10']}}

        # configuration item instantiation
        datatype = 'bool'
        key = 'DISABLEIPV6'
        instructions = "To disable this rule set the value of DISABLEIPV6 " + \
            "to False."
        default = False
        self.ci = self.initCi(datatype, key, instructions, default)

        self.iditerator = 0
        self.created = False
        self.created2 = False
        self.editor1, self.editor2, self.editor3 = "", "", ""
        self.sh = ServiceHelper(self.environ, self.logger)
        self.sethelptext()

    def report(self):
        try:
            self.detailedresults = ""
            if self.environ.getosfamily() == "linux":
                self.compliant = self.reportLinux()
            elif self.environ.getosfamily() == "freebsd":
                self.compliant = self.reportFree()
            elif self.environ.getosfamily() == "solaris":
                self.compliant = self.reportSol()
            elif self.environ.getostype() == "Mac OS X":
                self.compliant = self.reportMac()
        except (KeyboardInterrupt, SystemExit):
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

    def fix(self):
        try:
            if not self.ci.getcurrvalue():
                return
            self.detailedresults = ""

            # clear out event history so only the latest fix is recorded
            self.iditerator = 0
            eventlist = self.statechglogger.findrulechanges(self.rulenumber)
            for event in eventlist:
                self.statechglogger.deleteentry(event)

            if self.environ.getosfamily() == "linux":
                self.rulesuccess = self.fixLinux()
            elif self.environ.getosfamily() == "freebsd":
                self.rulesuccess = self.fixFree()
            elif self.environ.getosfamily() == "darwin":
                self.rulesuccess = self.fixMac()
            elif self.environ.getosfamily() == "solaris":
                self.detailedresults = "Solaris systems require a manual fix"
                self.logger.log(LogPriority.INFO, self.detailedresults)
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

##############################################################################

    def reportSol(self):
        cmd = ["/usr/sbin/ifconfig", "-a"]
        if not self.cmdhelper.executeCommand(cmd):
            self.detailedresults += "Unable to run ifconfig command\n"
            self.logger.log(LogPriority.DEBUG, self.detailedresults)
            return False
        output = self.cmdhelper.getOutput()
        for line in output:
            if re.search("(.*)inet6(.*)", line):
                self.detailedresults += "IPV6 is still showing as enabled\n"
                self.logger.log(LogPriority.DEBUG, self.detailedresults)
                return False
        return True

###############################################################################

    def reportMac(self):
        self.ifaces = []
        compliant = True
        self.cmdhelper = CommandHelper(self.logger)
        cmd = ["/usr/sbin/networksetup", "-listallnetworkservices"]
        if not self.cmdhelper.executeCommand(cmd):
            self.detailedresults += "Unable to run " + \
                "networksetup -listallnetworkservices command\n"
            return False
        output = self.cmdhelper.getOutput()
        for item in output:
            item = item.strip()
            cmd = ["/usr/sbin/networksetup", "-getinfo", item]
            if not self.cmdhelper.executeCommand(cmd):
                self.detailedresults += "Unable to run " + \
                    "networksetup -getinfo command\n"
                return False
            output2 = self.cmdhelper.getOutput()
            for item2 in output2:
                if re.search("^IPv6:", item2):
                    check = item2.split(":")
                    if check[1].strip() != "Off":
                        self.detailedresults += "IPV6 is not turned off " + \
                            "for " + item + " interface\n"
                        self.ifaces.append(item)
                        compliant = False
        return compliant

##############################################################################

    def fixMac(self):
        if self.ifaces:
            for item in self.ifaces:
                cmd = ["/usr/sbin/networksetup", "setv6off", item]
                if not self.cmdhelper.executeCommand(cmd):
                    self.rulesuccess = False
                else:
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    event = {'eventtype': 'comm',
                             'startstate': 'notconfigured',
                             'endstate': 'configured',
                             'command': ['/usr/sbin/networksetup',
                                         'setv6automatic', item]}
                    self.statechglogger.recordchgevent(myid, event)
        return self.rulesuccess

##############################################################################

    def reportFree(self):
        compliant = True
        self.editor1, self.editor2 = "", ""

        directives1 = {"ipv6_network_interfaces": "none",
                       "ipv6_activate_all_interfaces": "NO",
                       "ip6addrctl_enable": "NO",
                       "ip6addrctl_policy": "NO"}
        directives2 = {"net.ipv6.conf.all.disable_ipv6": "1",
                       "net.ipv6.conf.default.disable_ipv6": "1",
                       "net.ipv6.conf.lo.disable_ipv6": "1"}

        path1 = "/etc/rc.conf"
        path2 = "/etc/sysctl.conf"
        tmpfile1 = "/etc/rc.conf.tmp"
        tmpfile2 = "/etc/sysctl.conf.tmp"

        # try and create /etc/rc.conf if doesn't exist
        if not os.path.exists(path1):
            if not createFile(path1, self.logger):
                compliant = False
                self.detailedresults += "Unable to create the file: " + \
                    path1 + ", so this file will not be configured, " + \
                    "resulting in failed compliance\n"

        if os.path.exists(path1):
            if not checkPerms(path1, [0, 0, 420], self.logger):
                compliant = False
            self.editor1 = KVEditorStonix(self.statechglogger, self.logger,
                                          "conf", path1, tmpfile1, directives1,
                                          "present", "closedeq")
            if not self.editor1.report():
                compliant = False

        # try and create /etc/sysctl.conf if doesn't exist
        if not os.path.exists(path2):
            if not createFile(path2, self.logger):
                compliant = False
                self.detailedresults += "Unable to create the file: " + \
                    path2 + " so this file will not be configured " + \
                    "resulting in failed compliance\n"

        if os.path.exists(path2):
            if not checkPerms(path2, [0, 0, 384], self.logger):
                compliant = False
            self.editor2 = KVEditorStonix(self.statechglogger, self.logger,
                                          "conf", path2, tmpfile2, directives2,
                                          "present", "closedeq")
            if not self.editor2.report():
                compliant = False
        else:
            compliant = False

        cmdhelper = CommandHelper(self.logger)
        cmd = ["/sbin/ifconfig", "-a"]
        if not cmdhelper.executeCommand(cmd):
            return False
        output = cmdhelper.getOutput()
        for line in output:
            line = line.strip()
            if re.search("^nd6", line):
                if not re.search("(.)*IFDISABLED(.)*", line):
                    compliant = False
        return compliant

##############################################################################

    def fixFree(self):
        # debug messages are used for developers, self.detailedresults
        # are used for the users information
        path1 = "/etc/rc.conf"
        path2 = "/etc/sysctl.conf"
        success = True
        debug = ""
        if os.path.exists(path1):
            if not checkPerms(path1, [0, 0, 420], self.logger):
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                if not setPerms(self.path, [0, 0, 420], self.logger,
                                self.statechglogger, myid):
                    success = False
            if self.editor1:
                if self.editor1.fixables:
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    self.editor1.setEventID(myid)
                    if not self.editor1.fix():
                        debug += "Kveditor unable to correct file: " + \
                            path1 + "\n"
                        self.detailedresults += "Unable to correct " + path1 + \
                            "\n"
                        success = False
                    elif not self.editor1.commit():
                        self.detailedresults += "Unable to correct " + path1 + \
                            "\n"
                        debug += "commit for kveditor1 was not successful\n"
                        success = False
            else:
                debug += "Editor2 was never created so path didn't exist \
and/or wasn't able to be created\n"
                success = False
        else:
            self.detailedresults += path1 + " doesn't exist!\n"
            debug += path1 + " doesn't exist, unble to fix file\n"
            success = False

        if os.path.exists(path2):
            # check permissions on /etc/sysctl.conf
            if not checkPerms(path2, [0, 0, 384], self.logger):
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)

                # set permissions if wrong
                if not setPerms(self.path, [0, 0, 384, self.logger],
                                self.statechglogger, myid):
                    success = False
            # check if editor is present
            if self.editor2:
                if self.editor2.fixables():
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    self.editor2.setEventID(myid)
                    if not self.editor2.fix():
                        debug += "Kveditor unable to correct file: " + \
                            path2 + "\n"
                        self.detailedresults += "Unable to correct " + path2 + \
                            "\n"
                        success = False
                    elif not self.editor2.commit():
                        self.detailedresults += "Unable to correct " + path2 + \
                            "\n"
                        debug += "commit for kveditor2 was not successful\n"
                        success = False
            else:
                debug += "Editor2 was never created so path didn't exist \
and/or wasn't able to be created\n"
                success = False
        else:
            self.detailedresults += path2 + " doesn't exist!\n"
            debug += path2 + " doesn't exist, unble to fix file\n"
            success = False

        # restart the network
        ch = CommandHelper(self.logger)
        cmd = ["/etc/rc.d/netif", "restart"]
        if not ch.executeCommand(cmd):
            self.detaileresults += "Unable to restart network\n"
            success = False
        return success

##############################################################################

    def reportLinux(self):
        netwrkfile = ""
        ifacefile = ""
        self.editor1, self.editor2, self.editor3 = "", "", ""
        sysctl = "/etc/sysctl.conf"
#         modprobecompliant = True
#         modprobefile = "/etc/modprobe.conf"
#         modprobedir = "/etc/modprobe.d/"
        interface = {"IPV6INIT": "no",
                     "NETWORKING_IPV6": "no"}
        self.rulesuccess = True
        compliant = True
        sysctls = {"net.ipv6.conf.all.disable_ipv6": "1",
                   "net.ipv6.conf.default.disable_ipv6": "1"}
        self.helper = Pkghelper(self.logger, self.environ)

        #stig portion
        if self.helper.manager == "apt-get":
            nfspkg = "nfs-common"
        else:
            nfspkg = "nfs-utils.x86_64"
        if self.helper.check(nfspkg):
            if os.path.exists("/etc/netconfig"):
                item1 = "udp6 tpi_clts v inet6 udp - -"
                item2 = "tcp6 tpi_cots_ord v inet6 tcp - -"
                contents = readFile("/etc/netconfig", self.logger)
                for line in contents:
                    line = re.sub("\s+", " ", line.strip())
                    if re.search(item1, line) or re.search(item2, line):
                        self.detailedresults += "/etc/netconfig file contains " + \
                            "lines we don't want present\n"
                        compliant = False

        if self.helper.manager == "yum":
            ifacefile = "/etc/sysconfig/network-scripts/"
            if not os.path.exists(ifacefile):
                ifacefile = ""
            netwrkfile = "/etc/sysconfig/network"
            if not os.path.exists(netwrkfile):
                netwrkfile = ""
        elif self.helper.manager == "zypper":
            ifacefile = "/etc/sysconfig/network/"
            if not os.path.exists(ifacefile):
                ifacefile = ""
#         if self.sh.auditService("ip6tables", _="_"):
#             compliant = False
#             debug = "ip6tables is still set to run\n"
#             self.logger.log(LogPriority.DEBUG, debug)
        # we will search for directives2 in any file in modprobe.d and
        # modprobe.conf
#         self.modprobes1 = {"options ipv6 disable": "1"}
#         self.modprobes2 = {"options ipv6 disable": "1"}
#         remove1 = []
#         remove2 = []
        # "ifconfig"has been deprecated on Debian9 so use "ip addr" instead
        if os.path.exists("/sbin/ifconfig"):
            cmd = ["/sbin/ifconfig"]
        else:
            cmd = ["/sbin/ip", "addr"]
        cmdhelper = CommandHelper(self.logger)
        if not cmdhelper.executeCommand(cmd):
            compliant = False
        else:
            output = cmdhelper.getOutput()
            for line in output:
                if re.search("^inet6", line.strip()):
                    self.detailedresults += "inet6 exists in the " + \
                        "ifconfig output\n"
                    compliant = False
                    break
#----------------------check for ipv6 address in hostname file----------------#
        if os.path.exists("/etc/hosts"):
            contents = readFile("/etc/hosts", self.logger)
            for line in contents:
                if re.search("^#", line) or re.match("^\s*$", line):
                    continue
                if re.search(":", line):
                    compliant = False
#-----------------------check /etc/sysctl.conf--------------------------------#
        if not os.path.exists(sysctl):
            self.detailedresults += "File " + sysctl + " does not exist\n"
            compliant = False
        else:
            if not checkPerms(sysctl, [0, 0, 420], self.logger):
                self.detailedresults += "Permissions for " + sysctl + \
                    "are incorrect\n"
                compliant = False
            tmpfile = sysctl + ".tmp"
            self.editor1 = KVEditorStonix(self.statechglogger, self.logger,
                                          "conf", sysctl, tmpfile, sysctls,
                                          "present", "openeq")
            if not self.editor1.report():
                self.detailedresults += "/etc/sysctl file doesn't contain \
the correct contents\n"
                compliant = False
# #---------------------check out /etc/modprobe.conf----------------------------#
#         # this file is optional so if it doesn't exist, no harm done, however
#         # if it does exist, it needs to be configured correctly
#         if os.path.exists(modprobefile):  # optional file
#             contents = []
#             if not checkPerms(modprobefile, [0, 0, 420], self.logger):
#                 compliant = False
#             contents = readFile(modprobefile, self.logger)
#             if contents:
#                 for key, val in self.modprobes1.iteritems():
#                     found = False
#                     blfound = ""
#                     for line in contents:
#                         if re.search("^" + key, line.strip()):
#                             if key == "options ipv6 disable":
#                                 if re.search("=", line):
#                                     temp = line.split("=")
#                                     if len(temp) == 2:
#                                         if temp[1] == val:
#                                             found = True
#                                         else:
#                                             self.detailedresults += \
# "/etc/modprobe.conf does not contain the correct value for " + key + "\n"
#                                             found = False
#                                             break
#                                     else:
#                                         self.detailedresults += modprobefile + \
# " is in bad format at line: " + line + "\n"
#                                         found = False
#                             elif key == "blacklist":
#                                 temp = line.strip().split()
#                                 if len(temp) == 2:
#                                     if temp[1] == val:
#                                         blfound = True
#                                         found = True
#                                         break
#                             else:
#                                 templine = line.split()
#                                 tempval = templine[-1]
#                                 if tempval == val:
#                                     found = True
#                                 else:
#                                     found = False
#                                     self.detailedresults += \
# "/etc/modprobe.conf does not contain the correct value for " + key + "\n"
#                                     break
#                     if blfound != "":
#                         if not blfound:
#                             self.detailedresults += "didn't find the \
# blacklist item: " + key + "\n"
#                     if not found:
#                         compliant = False
#                     else:
#                         remove1.append(key)
#                 for item in remove1:
#                     del(self.modprobes1[item])
# #-----------------------------------------------------------------------------#
#         if os.path.exists(modprobedir):
#             contents = []
#             dirs = glob.glob(modprobedir + '*')
#             for key, val in self.modprobes2.iteritems():
#                 blfound = ""
#                 found = False
#                 valwrong = False
#                 for loc in dirs:
#                     contents = readFile(loc, self.logger)
#                     if contents:
#                         for line in contents:
#                             if re.search("^" + key, line.strip()):
#                                 if key == "options ipv6 disable":
#                                     if re.search("=", line):
#                                         temp = line.split("=")
#                                         if len(temp) == 2:
#                                             if temp[1].strip() == val:
#                                                 found = True
#                                             else:
#                                                 self.detailedresults += \
# "/etc/modprobe.conf does not contain the correct value for " + key + "\n"
#                                                 valwrong = True
#                                                 found = False
#                                                 break
#                                         else:
#                                             self.detailedresults += loc + \
# " is in bad format on line: " + line + "\n"
#                                 elif key == "blacklist":
#                                     temp = line.strip().split()
#                                     if len(temp) == 2:
#                                         if temp[1] == val:
#                                             blfound = True
#                                             found = True
#                                             break
#                                 else:
#                                     templine = line.split()
#                                     tempval = templine[-1].strip()
#                                     if tempval == val:
#                                         found = True
#                                     else:
#                                         self.detailedresults += \
# "/etc/modprobe.conf does not contain the correct value for " + key + "\n"
#                                         valwrong = True
#                                         found = False
#                                         break
#                         if valwrong:
#                             compliant = False
#                             modprobecompliant = False
#                             break
#                 if blfound != "":
#                     if not blfound:
#                         self.detailedresults += "didn't find the \
# blacklist item: " + key + "\n"
#                 if not found:
#                     compliant = False
#                     modprobecompliant = False
#                 else:
#                     remove2.append(key)
#             for item in remove2:
#                 del(self.modprobes2[item])
#             filename = modprobedir + 'stonix-blacklist.conf'
#             if not modprobecompliant:
#                 if not os.path.exists(filename):
#                     self.detailedresults += filename + " does not exist\n"
#                     compliant = False
#         else:
#             compliant = False

        if ifacefile:
            dirs = glob.glob(ifacefile + '*')
            for loc in dirs:
                contents = []
                if re.search('^' + ifacefile + 'ifcfg', loc):
                    if not checkPerms(loc, [0, 0, 420], self.logger):
                        compliant = False
                    contents = readFile(loc, self.logger)
                    if contents:
                        for key in interface:
                            found = False
                            for line in contents:
                                if re.search("^#", line) or re.match("^\s*$",
                                                                     line):
                                    continue
                                if re.search("^" + key, line):
                                    if re.search("=", line):
                                        temp = line.split("=")
                                        if temp[1].strip() == interface[key]:
                                            found = True
                                            continue
                                        else:
                                            found = False
                                            break
                                    else:
                                        compliant = False
                                        self.detailedresults += loc + \
                                            " file in bad format\n"
                            if not found:
                                self.detailedresults += "contents of " + \
                                    loc + " file is wrong\n"
                                compliant = False
                                break
                            else:
                                continue
                    else:
                        compliant = False

        if netwrkfile:
            if os.path.exists(netwrkfile):
                if not checkPerms(netwrkfile, [0, 0, 420], self.logger):
                    compliant = False
                tmpfile = netwrkfile + ".tmp"
                self.editor2 = KVEditorStonix(self.statechglogger, self.logger,
                                              "conf", netwrkfile, tmpfile,
                                              interface, "present", "closedeq")
                if not self.editor2.report():
                    self.detailedresults += netwrkfile + " doesn't contain \
the correct contents\n"
                    compliant = False
            else:
                self.detailedresults += netwrkfile + " doesn't exist\n"
                compliant = False

        '''This subpart is only for apt-get based systems'''
        if self.helper.manager == "apt-get":
            data = {"AddressFamily": "inet"}
            kvtype = "conf"
            path = "/etc/ssh/sshd_config"
            tmpPath = path + ".tmp"
            intent = "present"
            configtype = "space"
            self.editor3 = KVEditorStonix(self.statechglogger, self.logger,
                                          kvtype, path, tmpPath, data, intent,
                                          configtype)
            if not self.editor3.report():
                self.detailedresults += "/etc/ssh/ssdh_config doesn't \
contain the correct contents\n"
                compliant = False
        if self.detailedresults:
            self.logger.log(LogPriority.DEBUG, self.detailedresults)
        return compliant

###############################################################################

    def fixLinux(self):
        '''
        @change: dkennel removed extraneous arg from setperms call on 864
        '''
        universal = "#The following lines were added by stonix\n"
        debug = ""
        success = True
        ifacefile = ""
        netwrkfile = ""
        tempstring1 = ""
        tempstring2 = ""
        sysctl = "/etc/sysctl.conf"
        sysctls = {"net.ipv6.conf.all.disable_ipv6": "1",
                   "net.ipv6.conf.default.disable_ipv6": "1"}
        modprobefile = "/etc/modprobe.conf"
        modprobedir = "/etc/modprobe.d/"
        interface = {"IPV6INIT": "no",
                     "NETWORKING_IPV6": "no"}
        #stig stuff
        if self.helper.manager == "apt-get":
            nfspkg = "nfs-common"
        else:
            nfspkg = "nfs-utils.x86_64"
        if self.helper.check(nfspkg):
            if os.path.exists("/etc/netconfig"):
                filestring = ""
                item1 = "udp6 tpi_clts v inet6 udp - -"
                item2 = "tcp6 tpi_cots_ord v inet6 tcp - -"
                contents = readFile("/etc/netconfig", self.logger)
                for line in contents:
                    templine = re.sub("\s+", " ", line.strip())
                    if re.search(item1, templine) or re.search(item2, templine):
                        continue
                    else:
                        filestring += line
                tmpfile = "/etc/netconfig.tmp"
                if not writeFile(tmpfile, filestring, self.logger):
                    success = False
                else:
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    event = {"eventtype": "conf",
                             "filepath": "/etc/netconfig"}
                    self.statechglogger.recordchgevent(myid, event)
                    self.statechglogger.recordfilechange("/etc/netconfig",
                                                         tmpfile, myid)
                    os.rename(tmpfile, "/etc/netconfig")
                    os.chown("/etc/netconfig", 0, 0)
                    os.chmod("/etc/netconfig", 420)
                    resetsecon("/etc/netconfig")
        if self.helper.manager == "yum":
            ifacefile = "/etc/sysconfig/network-scripts/"
            netwrkfile = "/etc/sysconfig/network"
        elif self.helper.manager == "zypper":
            ifacefile = "/etc/sysconfig/network/"
#---------------------remove any ipv6 addresses-------------------------------#
        if os.path.exists("/etc/hosts"):
            contents = readFile("/etc/hosts", self.logger)
            tempstring = ""
            tmpfile = "/etc/hosts.tmp"
            for line in contents:
                if re.search("^#", line) or re.match("^\s*$", line):
                    tempstring += line
                    continue
                elif re.search(":", line):
                    tempstring += "#" + line
                else:
                    tempstring += line
            if writeFile(tmpfile, tempstring, self.logger):
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                event = {"eventtype": "conf",
                         "filepath": "/etc/hosts"}
                self.statechglogger.recordchgevent(myid, event)
                self.statechglogger.recordfilechange("/etc/hosts", tmpfile,
                                                     myid)
                os.rename(tmpfile, "/etc/hosts")
                os.chown("/etc/hosts", 0, 0)
                os.chmod("/etc/hosts", 420)
                resetsecon("/etc/hosts")
            else:
                success = False
                debug = "Unable to write to file /etc/hosts\n"
                self.logger.log(LogPriority.DEBUG, debug)
#-------------------------disableipv6 from loading----------------------------#
#         if self.sh.auditService("ip6tables", _="_"):
#             debug = "auditservice returned: " + \
#                 str(self.sh.auditService("ip6tables", _="_")) + "\n\n\n"
#             self.logger.log(LogPriority.DEBUG, debug)
#             if not self.sh.disableService("ip6tables", _="_"):
#                 success = False
#                 debug = "Unable to disable ip6tables service\n"
#                 self.logger.log(LogPriority.DEBUG, debug)
#---------------------------fix Sysctl----------------------------------------#
        if not os.path.exists(sysctl):
            if createFile(sysctl, self.logger):
                self.created = True
                setPerms(sysctl, [0, 0, 420], self.logger)
                tmpfile = sysctl + ".tmp"
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                event = {"eventtype": "creation",
                         "filepath": sysctl}
                self.statechglogger.recordchgevent(myid, event)
            else:
                success = False
                debug = "Unable to create " + sysctl + "\n"
                self.logger.log(LogPriority.DEBUG, debug)
        if os.path.exists(sysctl):
            self.editor1 = KVEditorStonix(self.statechglogger, self.logger,
                                          "conf", sysctl, tmpfile, sysctls,
                                          "present", "openeq")
            if not self.editor1.report():
                if self.editor1.fixables:
                    self.iditerator += 1
                    # If we did not create the file, set an event ID for the
                    # KVEditor's undo event
                    if not self.created:
                        myid = iterate(self.iditerator, self.rulenumber)
                        self.editor1.setEventID(myid)
                    if not self.editor1.fix():
                        success = False
                        debug = "Unable to complete kveditor fix method" + \
                            "for /etc/sysctl.conf file\n"
                        self.logger.log(LogPriority.DEBUG, debug)
                    elif not self.editor1.commit():
                        success = False
                        debug = "Unable to complete kveditor commit " + \
                            "method for /etc/sysctl.conf file\n"
                        self.logger.log(LogPriority.DEBUG, debug)
                    if not checkPerms(sysctl, [0, 0, 420], self.logger):
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        if not setPerms(sysctl, [0, 0, 420], self.logger,
                                        self.statechglogger, myid):
                            success = False
                            debug = "Unable to set permissions on /etc/sysctl.conf\n"
                            self.logger.log(LogPriority.DEBUG, debug)
                    resetsecon(sysctl)
                    cmdhelper = CommandHelper(self.logger)
                    cmd = ["/sbin/sysctl", "-q", "-e", "-p"]
                    if not cmdhelper.executeCommand(cmd):
                        success = False
                        debug = "Unable to reset sysctl\n"
                        self.logger.log(LogPriority.DEBUG, debug)
#--------------------------fix /etc/modprobe.conf-----------------------------#
#         tempstring = ""
#         tmpfile = modprobefile + ".tmp"
#         found = False
#         if os.path.exists(modprobefile):
#             if not checkPerms(modprobefile, [0, 0, 420], self.logger):
#                 self.iditerator += 1
#                 myid = iterate(self.iditerator, self.rulenumber)
#                 if not setPerms(modprobefile, [0, 0, 420], self.logger,
#                                 self.statechglogger, myid):
#                     success = False
#                     debug = "Unable to set permissions on " + modprobefile + \
#                         "\n"
#                     self.logger.log(LogPriority.DEBUG, debug)
#             contents = readFile(modprobefile, self.logger)
#             if contents:
#                 for key, val in self.modprobes1.iteritems():
#                     found = False
#                     if contents:
#                         i = 0
#                         for line in contents:
#                             if re.search("^" + key, line.strip()):
#                                 if key == "options ipv6 disable":
#                                     if re.search("=", line):
#                                         temp = line.split("=")
#                                         if temp[1] == val:
#                                             found = True
#                                             i += 1
#                                         else:
#                                             contents.pop(i)
#                                             filechanged = True
#                                             break
#                                     else:
#                                         i += 1
#                                 else:
#                                     if re.search("^" + key, line.strip()):
#                                         templine = line.split()
#                                         tempval = templine[-1]
#                                         if tempval == val:
#                                             found = True
#                                             i += 1
#                                         else:
#                                             contents.pop(i)
#                                             filechanged = True
#                                             break
#                                     else:
#                                         i += 1
#                         if filechanged:
#                             for line in contents:
#                                 tempstring += line
#                             if writeFile(tmpfile, tempstring, self.logger):
#                                 self.iditerator += 1
#                                 myid = iterate(self.iditerator, self.rulenumber)
#                                 event = {"eventtype": "conf",
#                                          "filepath": modprobefile}
#                                 self.statechglogger.recordchgevent(myid, event)
#                                 self.statechglogger.recordfilechange(modprobefile, tmpfile, myid)
#                                 os.rename(tmpfile, modprobefile)
#                                 os.chown(modprobefile, 0, 0)
#                                 os.chmod(modprobefile, 420)
#                                 resetsecon(modprobefile)
#                             else:
#                                 success = False
#                                 debug = "Unable to write to file " + \
#                                     modprobefile + "\n"
#                                 self.logger.log(LogPriority.DEBUG, debug)
#                     if found:
#                         del(self.modprobes1[key])  # may need to get rid of these two lines
#         else:
#             info = "modprobe.conf file doesn't exist but this file is \
# optional so your system's compliance is not effected by it's absence\n"
#             self.logger.log(LogPriority.INFO, info)
#-----------------fix modprobe.d----------------------------------------------#
##
#    Commented out 2018/04/10 by D. Kennel for artf48817
##
#         filename = modprobedir + 'stonix-blacklist.conf'
#         tmpfile = filename + ".tmp"
#         if os.path.exists(modprobedir):
#             tempstring = ""
#             contents = []
#             dirs = glob.glob(modprobedir + '*')
#             for loc in dirs:
#                 contents = readFile(loc, self.logger)
#                 filechanged = False
#                 for key, val in self.modprobes2.iteritems():
#                     if key == "blacklist":
#                         continue
#                     if contents:
#                         i = 0
#                         for line in contents:
#                             if re.search("^" + key, line.strip()):
#                                 if key == "options ipv6 disable":
#                                     if re.search("=", line):
#                                         temp = line.split("=")
#                                         if temp[1] != val:
#                                             contents.pop(i)
#                                             filechanged = True
#                                             i += 1
#                                     else:
#                                         i += 1
#                                 else:
#                                     templine = line.split()
#                                     tempval = templine[-1]
#                                     if tempval != val:
#                                         val = contents.pop(i)
#                                         filechanged = True
#                                         i += 1
#                             else:
#                                 i += 1
#                 if filechanged:
#                     for line in contents:
#                         tempstring += line
#                     tmpfile = loc + ".tmp"
#                     if writeFile(tmpfile, tempstring, self.logger):
#                         self.iditerator += 1
#                         myid = iterate(self.iditerator, self.rulenumber)
#                         event = {"eventtype": "conf",
#                                  "filepath": loc}
#                         self.statechglogger.recordchgevent(myid, event)
#                         self.statechglogger.recordfilechange(loc, tmpfile,
#                                                              myid)
#                         os.rename(tmpfile, loc)
#                         os.chown(loc, 0, 0)
#                         os.chmod(loc, 420)
#                         resetsecon(loc)
#                     else:
#                         success = False
#                         debug = "Unable to write to file " + loc + "\n"
#                         self.logger.log(LogPriority.DEBUG, debug)
#             if self.modprobes2:
#                 for key, val in self.modprobes2.iteritems():
#                     if key == "options ipv6 disable":
#                         tempstring1 += key + "=" + val + "\n"
#                     else:
#                         tempstring1 += key + " " + val + "\n"
#             if not os.path.exists(filename):
#                 if createFile(filename, self.logger):
#                     self.created2 = True
#                     self.iditerator += 1
#                     myid = iterate(self.iditerator, self.rulenumber)
#                     event = {"eventtype": "creation",
#                              "filepath": filename}
#                     self.statechglogger.recordchgevent(myid, event)
#                     if tempstring1:
#                         if writeFile(tmpfile, tempstring1, self.logger):
#                             os.rename(tmpfile, filename)
#                             os.chown(filename, 0, 0)
#                             os.chmod(filename, 420)
#                             resetsecon(filename)
#                         else:
#                             success = False
#                             debug = "Unable to write to file " + filename + "\n"
#                             self.logger.log(LogPriority.DEBUG, debug)
#                 else:
#                     success = False
#                     debug = "Could not create " + filename + "\n"
#                     self.logger.log(LogPriority.DEBUG, debug)
#             else:
#                 contents = readFile(filename, self.logger)
# 
#                 for line in contents:
#                     if line == universal:
#                         continue
#                     else:
#                         tempstring2 += line
#                 tempstring2 += universal + tempstring1
#                 if writeFile(tmpfile, tempstring2, self.logger):
#                     self.iditerator += 1
#                     myid = iterate(self.iditerator, self.rulenumber)
#                     event = {"eventtype": "conf",
#                              "filepath": filename}
#                     self.statechglogger.recordchgevent(myid, event)
#                     self.statechglogger.recordfilechange(filename, tmpfile,
#                                                          myid)
#                     os.rename(tmpfile, filename)
#                     os.chown(filename, 0, 0)
#                     os.chmod(filename, 420)
#                     resetsecon(filename)
#                 else:
#                     success = False
#                     debug = "Unable to write to file " + filename + "\n"
#                     self.logger.log(LogPriority.DEBUG, debug)
#         else:
#             debug = "modprobe.d doesn't exist\n"
#             success = False
#             self.logger.log(LogPriority.DEBUG, debug)
#--------------------------------fix ifcfg files------------------------------#
        if ifacefile:
            if os.path.exists(ifacefile):
                dirs = glob.glob(ifacefile + "*")
                if dirs:
                    for loc in dirs:
                        interface = {"IPV6INIT": "no",
                                     "NETWORKING_IPV6": "no"}
                        interface2 = {"IPV6INIT": "no",
                                     "NETWORKING_IPV6": "no"}
                        found = False
                        tempstring = ""
                        if re.search('^' + ifacefile + 'ifcfg', loc):
                            filename = loc
                            tmpfile = filename + ".tmp"
                            contents = readFile(filename, self.logger)
                            if not checkPerms(filename, [0, 0, 420],
                                              self.logger):
                                self.iditerator += 1
                                myid = iterate(self.iditerator, self.rulenumber)
                                if not setPerms(filename, [0, 0, 420],
                                                self.logger,
                                                self.statechglogger, myid):
                                    debug = "Unable to set permissions on " + \
                                        filename + "\n"
                                    self.logger.log(LogPriority.DEBUG, debug)
                                    success = False
                            for key in interface:
                                found = False
                                for line in contents:
                                    if re.search("^#", line) or \
                                       re.match("^\s*$", line):
                                        continue
                                    if re.search("^" + key, line):
                                        if re.search("=", line):
                                            temp = line.split("=")
                                            if temp[1].strip() == interface[key]:
                                                if found:
                                                    continue
                                                found = True
                                            else:
                                                contents.remove(line)
                                if found:
                                    del interface2[key]
                            for line in contents:
                                tempstring += line
                            tempstring += universal
                            for key in interface2:
                                tempstring += key + "=" + interface2[key] + \
                                    "\n"
                            if not writeFile(tmpfile, tempstring, self.logger):
                                success = False
                                debug = "Unable to write to file " + loc + "\n"
                                self.logger.log(LogPriority.DEBUG, debug)
                            self.iditerator += 1
                            myid = iterate(self.iditerator, self.rulenumber)
                            event = {'eventtype': 'conf',
                                     'filepath': filename}
                            self.statechglogger.recordchgevent(myid, event)
                            self.statechglogger.recordfilechange(filename,
                                                                 tmpfile, myid)
                            os.rename(tmpfile, filename)
                            os.chown(filename, 0, 0)
                            os.chmod(filename, 420)
                            resetsecon(filename)
            elif not os.path.exists(ifacefile) and ifacefile != "":
                # will not attempt to create the interface files
                debug = "interface directory which holds interface \
                files, doesn't exist, stonix will not attempt to make this \
                directory or the files contained therein"
                success = False
                self.logger.log(LogPriority.DEBUG, debug)
#-----------------------------------------------------------------------------#
        if netwrkfile:
            if not os.path.exists(netwrkfile):
                if not createFile(netwrkfile, self.logger):
                    debug = "Unable to create " + netwrkfile + "file\n"
                    self.logger.log(LogPriority.DEBUG, debug)
                    success = False
                else:
                    if not checkPerms(netwrkfile, [0, 0, 420], self.logger):
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        if not setPerms(netwrkfile, [0, 0, 420], self.logger,
                                        self.statechglogger, myid):
                            debug = "Unable to set permissions on " + \
                                    netwrkfile + "\n"
                            self.logger.log(LogPriority.DEBUG, debug)
                            success = False
                    tmpfile = netwrkfile + ".tmp"
                    self.editor2 = KVEditorStonix(self.statechglogger,
                                                  self.logger, "conf",
                                                  netwrkfile, tmpfile,
                                                  interface, "present",
                                                  "closedeq")
                    if not self.editor2.report():
                        self.detailedresults += netwrkfile + " doesn't contain \
the correct contents\n"
            if self.editor2:
                if self.editor2.fixables:
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    self.editor2.setEventID(myid)
                    if not self.editor2.fix():
                        success = False
                        debug = "Unable to complete kveditor fix method" + \
                            "for " + netwrkfile + "\n"
                        self.logger.log(LogPriority.DEBUG, debug)
                    elif not self.editor2.commit():
                        success = False
                        debug = "Unable to complete kveditor commit " + \
                            "method for " + netwrkfile + "\n"
                        self.logger.log(LogPriority.DEBUG, debug)
                    os.chown(netwrkfile, 0, 0)
                    os.chmod(netwrkfile, 420)
                    resetsecon(netwrkfile)
#-----------------------------------------------------------------------------#
        if self.helper.manager == "apt-get":
            if not os.path.exists("/etc/ssh/sshd_config"):
                msg = "/etc/ssh/ssd_config doesn\'t exist.  This could mean ssh \
    is not installed or the file has been inadvertantly deleted.  Due to the \
    complexity of this file stonix will not attempt to create this file"
                self.logger.log(LogPriority.DEBUG, msg)
                success = False
            else:
                if not checkPerms("/etc/ssh/sshd_config", [0, 0, 420],
                                  self.logger):
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    if not setPerms("/etc/ssh/sshd_config", [0, 0, 420],
                                    self.logger, self.statechglogger, myid):
                        success = False
                        debug = "Unable to set permissions on " + \
                            "/etc/ssh/sshd_config\n"
                        self.logger.log(LogPriority.DEBUG, debug)
                if self.editor3:
                    if self.editor3.fixables:
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        self.editor3.setEventID(myid)
                        if not self.editor3.fix():
                            success = False
                            debug = "Unable to complete kveditor fix method" + \
                                "for /etc/ssh/sshd_config file\n"
                            self.logger.log(LogPriority.DEBUG, debug)
                        elif not self.editor3.commit():
                            success = False
                            debug = "Unable to complete kveditor commit " + \
                                "method for /etc/ssh/sshd_config file\n"
                            self.logger.log(LogPriority.DEBUG, debug)
                        os.chown("/etc/ssh/sshd_config", 0, 0)
                        os.chmod("/etc/ssh/sshd_config", 420)
                        resetsecon("/etc/ssh/sshd_config")
        return success
