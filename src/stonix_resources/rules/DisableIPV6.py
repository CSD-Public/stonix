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
@change: 2018/06/08 ekkehard - make eligible for macOS Mojave 10.14
@change: 2019/06/05 dwalker - refactored linux portion of rule to be
    consistent with other rules that handle sysctl and to properly
    handle sysctl by writing to /etc/sysctl.conf and also using command
@change: 2019/08/07 ekkehard - enable for macOS Catalina 10.15 only
@change: 2019/08/07 Brandon R. Gonzales - Improve logging in linux report;
        Remove/cleanup unused lines of code
'''

from stonixutilityfunctions import iterate, setPerms, checkPerms, writeFile
from stonixutilityfunctions import readFile, resetsecon, createFile
from rule import Rule
from logdispatcher import LogPriority
from KVEditorStonix import KVEditorStonix
from pkghelper import Pkghelper
from CommandHelper import CommandHelper
from ServiceHelper import ServiceHelper

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
                           'os': {'Mac OS X': ['10.15', 'r', '10.15.10']}}

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
        # self.editor1: sysctl file editor
        # self.editor2: network file editor
        # self.editor3: sshd file editor
        self.editor1, self.editor2, self.editor3 = "", "", ""
        self.sh = ServiceHelper(self.environ, self.logger)
        self.sethelptext()

    def report(self):
        try:
            self.detailedresults = ""
            if self.environ.getosfamily() == "linux":
                self.ph = Pkghelper(self.logger, self.environ)
                self.compliant = self.reportLinux()
            elif self.environ.getosfamily() == "freebsd":
                self.compliant = self.reportFree()
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
                             'command': ['/usr/sbin/networksetup',
                                         'setv6automatic', item]}
                    self.statechglogger.recordchgevent(myid, event)
        return self.rulesuccess

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

    def reportLinux(self):
        self.ch = CommandHelper(self.logger)
        compliant = True
        netwrkfile = ""
        ifacefile = ""
        self.modprobefiles = []
        #self.modprobeOK = False
        self.modprobeOK = True
        sysctl = "/etc/sysctl.conf"
        self.interface = {"IPV6INIT": "no",
                     "NETWORKING_IPV6": "no"}
        self.sysctls = {"net.ipv6.conf.all.disable_ipv6": "1",
                        "net.ipv6.conf.default.disable_ipv6": "1"}
        self.modprobes = {"options": ["ipv6 disable=1"],
                          "install": ["ipv6 /bin/true"]}

        # stig portion, check netconfig file for correct contents
        if self.ph.manager == "apt-get":
            nfspkg = "nfs-common"
        else:
            nfspkg = "nfs-utils.x86_64"
        if self.ph.check(nfspkg):
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

        # "ifconfig" has been deprecated on Debian9 and some otherd distros
        # so use "ip addr" instead
        # Here we check if the system is giving out ipv6 ip addresses
        if os.path.exists("/sbin/ifconfig"):
            cmd = ["/sbin/ifconfig"]
        else:
            cmd = ["/sbin/ip", "addr"]

        if not self.ch.executeCommand(cmd):
            compliant = False
        else:
            output = self.ch.getOutput()
            for line in output:
                if re.search("^inet6", line.strip()):
                    self.detailedresults += "inet6 exists in the " + \
                        "ifconfig output\n"
                    compliant = False
                    break

        # check for ipv6 address in hostname file
        if os.path.exists("/etc/hosts"):
            contents = readFile("/etc/hosts", self.logger)
            for line in contents:
                if re.search("^#", line) or re.match("^\s*$", line):
                    continue
                if re.search(":", line):
                    compliant = False

        # check compliancy of /etc/sysctl.conf file
        if not os.path.exists(sysctl):
            self.detailedresults += "File " + sysctl + " does not exist\n"
            compliant = False
        else:
            tmpfile = sysctl + ".tmp"
            self.editor1 = KVEditorStonix(self.statechglogger, self.logger,
                                          "conf", sysctl, tmpfile, self.sysctls,
                                          "present", "openeq")
            if not self.editor1.report():
                self.detailedresults += "/etc/sysctl file doesn't contain \
                    the correct contents\n"
                compliant = False
            if not checkPerms(sysctl, [0, 0, 0o644], self.logger):
                self.detailedresults += "Permissions for " + sysctl + \
                    "are incorrect\n"
                compliant = False

        # in addition to checking /etc/sysctl.conf contents we need to
        # also check sysctl compliancy using the sysctl command
        for key in self.sysctls:
            self.ch.executeCommand("/sbin/sysctl " + key)
            retcode = self.ch.getReturnCode()
            output = self.ch.getOutputString()
            errmsg = output + self.ch.getErrorString()
            if retcode != 0:
                if re.search("unknown key", errmsg):
                    continue
                else:
                    self.detailedresults += "Failed to get value " + key + " using sysctl command\n"
                    errmsg = self.ch.getErrorString()
                    self.logger.log(LogPriority.DEBUG, errmsg)
                    compliant = False
            else:
                actualoutput = output.strip()
                expectedoutput = key + " = " + self.sysctls[key]
                if actualoutput != expectedoutput:
                    compliant = False
                    self.detailedresults += "\nsysctl output has " + \
                                            "incorrect value: expected " + \
                                            expectedoutput + ", found " + \
                                            actualoutput + "\n"
        # check files inside modprobe.d directory for correct contents
        if os.path.exists("/etc/modprobe.d/"):
            modprobefiles = glob.glob("/etc/modprobe.d/*")
            for modfile in modprobefiles:
                tmpfile = ""
                modprobekveditor = KVEditorStonix(self.statechglogger, self.logger,
                                                  "conf", modfile, tmpfile, self.modprobes,
                                                  "present", "space")
                if modprobekveditor.report():
                    self.modprobeOK = True
                    break
            if not self.modprobeOK:
                self.detailedresults += "Didn't find desired contents inside files " + \
                    "within /etc/modprobe.d/"
                compliant = False
        else:
            # system isn't using loadable kernel modules, not an issue
            self.modprobeOK = True

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

        # go through interface directory and check each interface file
        # for correct contents
        if ifacefile:
            dirs = glob.glob(ifacefile + '*')
            for loc in dirs:
                contents = []
                if re.search('^' + ifacefile + 'ifcfg', loc):
                    if not checkPerms(loc, [0, 0, 0o644], self.logger):
                        compliant = False
                    contents = readFile(loc, self.logger)
                    if contents:
                        for key in self.interface:
                            found = False
                            for line in contents:
                                if re.search("^#", line) or re.match("^\s*$", line):
                                    continue
                                if re.search("^" + key, line):
                                    if re.search("=", line):
                                        temp = line.split("=")
                                        if temp[1].strip() == self.interface[key]:
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

        # check network file for correct contents
        if netwrkfile:
            if os.path.exists(netwrkfile):
                if not checkPerms(netwrkfile, [0, 0, 0o644], self.logger):
                    compliant = False
                tmpfile = netwrkfile + ".tmp"
                self.editor2 = KVEditorStonix(self.statechglogger, self.logger,
                                              "conf", netwrkfile, tmpfile,
                                              self.interface, "present", "closedeq")
                if not self.editor2.report():
                    self.detailedresults += netwrkfile + " doesn't contain \
the correct contents\n"
                    compliant = False
            else:
                self.detailedresults += netwrkfile + " doesn't exist\n"
                compliant = False

        # This subpart is only for apt-get based systems
        # sshd needs the inet directive for ipv6 disablement
        if self.ph.manager == "apt-get":
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
        return compliant

    def fixLinux(self):
        '''
        @change: dkennel removed extraneous arg from setperms call on 864
        '''
        universal = "#The following lines were added by stonix\n"
        debug = ""
        success = True
        ifacefile = ""
        netwrkfile = ""
        sysctl = "/etc/sysctl.conf"
        blacklistfile = "/etc/modprobe.d/stonix-blacklist.conf"

        # STIG portion, correct netconfig file
        if self.ph.manager == "apt-get":
            nfspkg = "nfs-common"
        else:
            nfspkg = "nfs-utils.x86_64"
        # if package not installed, no need to configure it
        if self.ph.check(nfspkg):
            if os.path.exists("/etc/netconfig"):
                filestring = ""
                # we want to make sure the following two lines don't
                # appear in the netconfig file
                item1 = "udp6 tpi_clts v inet6 udp - -"
                item2 = "tcp6 tpi_cots_ord v inet6 tcp - -"
                contents = readFile("/etc/netconfig", self.logger)
                for line in contents:
                    templine = re.sub("\s+", " ", line.strip())
                    # if we find the lines, skip them thus leaving them out of
                    # of the rewrite
                    if re.search(item1, templine) or re.search(item2, templine):
                        continue
                    else:
                        filestring += line
                tmpfile = "/etc/netconfig.tmp"
                if not writeFile(tmpfile, filestring, self.logger):
                    success = False
                else:
                    # record event, rename file, set perms
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

        # remove any ipv6 addresses from /etc/hosts file
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

        # fix sysctl / tuning kernel parameters
        # manually write key value pairs to /etc/sysctl.conf
        created = False
        if not os.path.exists(sysctl):
            if createFile(sysctl, self.logger):
                created = True
                setPerms(sysctl, [0, 0, 0o644], self.logger)
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
            if not checkPerms(sysctl, [0, 0, 0o644], self.logger):
                if not created:
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    if not setPerms(sysctl, [0, 0, 0o644], self.logger,
                                    self.statechglogger, myid):
                        success = False

            tmpfile = sysctl + ".tmp"
            self.editor1 = KVEditorStonix(self.statechglogger, self.logger,
                                          "conf", sysctl, tmpfile, self.sysctls,
                                          "present", "openeq")
            if not self.editor1.report():
                if self.editor1.fixables:
                    # If we did not create the file, set an event ID for the
                    # KVEditor's undo event
                    if not created:
                        self.iditerator += 1
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
                    if not checkPerms(sysctl, [0, 0, 0o644], self.logger):
                        if not setPerms(self.path, [0, 0, 0o644], self.logger):
                            self.detailedresults += "Could not set permissions on " + \
                                                    self.path + "\n"
                            success = False
                    resetsecon(sysctl)

        # here we also check the output of the sysctl command for each key
        # to cover all bases
        for key in self.sysctls:
            if self.ch.executeCommand("/sbin/sysctl " + key):
                output = self.ch.getOutputString().strip()
                errmsg = output + self.ch.getErrorString()
                if re.search("unknown key", errmsg):
                    continue
                if not re.search(self.sysctls[key] + "$", output):
                    undovalue = output[-1]
                    self.ch.executeCommand("/sbin/sysctl -q -e -w " + key + "=" + self.sysctls[key])
                    retcode = self.ch.getReturnCode()
                    if retcode != 0:
                        success = False
                        self.detailedresults += "Failed to set " + key + " = " + self.sysctls[key] + "\n"
                        errmsg = self.ch.getErrorString()
                        self.logger.log(LogPriority.DEBUG, errmsg)
                    else:
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        command = "/sbin/sysctl -q -e -w " + key + "=" + undovalue
                        event = {"eventtype": "commandstring",
                                 "command": command}
                        self.statechglogger.recordchgevent(myid, event)
            else:
                self.detailedresults += "Unable to get value for " + key + "\n"
                success = False
        # at the end do a print and ignore any key errors to ensure
        # the new values are read into the kernel
        self.ch.executeCommand("/sbin/sysctl -q -e -p")
        retcode2 = self.ch.getReturnCode()
        if retcode2 != 0:
            success = False
            self.detailedresults += "Failed to load new sysctl configuration from config file\n"
            errmsg2 = self.ch.getErrorString()
            self.logger.log(LogPriority.DEBUG, errmsg2)

        # We never found the correct contents in any of the modprobe.d files
        # so we're going to created the stonix-blacklist file
        # this file is used in other rules
        if not self.modprobeOK:
            created = False
            tmpfile = blacklistfile + ".tmp"
            modprobekveditor = KVEditorStonix(self.statechglogger, self.logger,
                                              "conf", blacklistfile, tmpfile, self.modprobes,
                                              "notpresent", "space")
            if not os.path.exists(blacklistfile):
                # create the file and record the event as file creation
                if createFile(blacklistfile, self.logger):
                    created = True
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    event = {"eventtype": "creation",
                             "filepath": blacklistfile}
                    self.statechglogger.recordchgevent(myid, event)
            if os.path.exists(blacklistfile):
                if not modprobekveditor.report():
                    if not modprobekveditor.fix():
                        success = False
                        self.detailedresults += "Unable to correct contents in " + \
                                                blacklistfile + "\n"
                    else:
                        # if the file was created, then we already recorded an event
                        # for that, so this step would get skipped
                        if not created:
                            self.iditerator += 1
                            myid = iterate(self.iditerator, self.rulenumber)
                            modprobekveditor.setEventID(myid)
                        if not modprobekveditor.commit():
                            success = False
                            self.detailedresults += "Unable to correct contents in " + \
                                                blacklistfile + "\n"

        # fix ifcfg (interface) files
        if self.ph.manager == "yum":
            ifacefile = "/etc/sysconfig/network-scripts/"
            netwrkfile = "/etc/sysconfig/network"
        elif self.ph.manager == "zypper":
            ifacefile = "/etc/sysconfig/network/"
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

        # fix network file if it exists
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
                    self.editor2 = KVEditorStonix(self.statechglogger, self.logger,
                                                  "conf", netwrkfile, tmpfile,
                                                  self.interface, "present", "closedeq")
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

        # fix sshd_config file for apt-get systems if ssh is installed
        if self.ph.manager == "apt-get":
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
