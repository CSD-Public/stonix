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
Created on Jan 14, 2014

@author: dwalker
@change: 04/21/2014 dkennel Updated CI invocation
@change: 2015/04/17 dkennel updated for new isApplicable
@change: 2015/10/08 eball Help text cleanup
@change: 2016/04/26 ekkehard Results Formatting
@change: 2016/06/23 dwalker adding mac os x configuration
@change: 2016/07/07 ekkehard added net.inet6.ip6.maxifdefrouters = 1
@change: 2017/07/17 ekkehard - make eligible for macOS High Sierra 10.13
@change: 2017/11/13 ekkehard - make eligible for OS X El Capitan 10.11+
@change: 2018/06/08 ekkehard - make eligible for macOS Mojave 10.14
'''
from __future__ import absolute_import
from ..stonixutilityfunctions import iterate, setPerms, checkPerms, writeFile
from ..stonixutilityfunctions import readFile, resetsecon, createFile
from ..rule import Rule
from ..logdispatcher import LogPriority
from ..KVEditorStonix import KVEditorStonix
from ..CommandHelper import CommandHelper
from ..pkghelper import Pkghelper
import traceback
import os
import glob
import re


class SecureIPV6(Rule):

    def __init__(self, config, enviro, logger, statechglogger):
        Rule.__init__(self, config, enviro, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 124
        self.rulename = "SecureIPV6"
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.sethelptext()
        datatype = "bool"
        key = "SECUREIPV6"
        instructions = '''To disable this rule set the value of SECUREIPV6 to \
False.'''
        default = True
        self.ci = self.initCi(datatype, key, instructions, default)
        self.guidance = ["NSA 2.5.3.2", "CCE 4269-7", "CCE 4291-1",
                         "CCE 4313-3", "CCE 4198-8", "CCE 3842-2",
                         "CCE 4221-8", "CCE 4137-6", "CCE 4159-0",
                         "CCE 3895-0", "CCE 4287-9", "CCE 4058-4",
                         "CCE 4128-5"]
        self.applicable = {'type': 'white',
                           'family': ['linux'],
                           'os': {'Mac OS X': ['10.11', 'r', '10.14.10']}}
        self.iditerator = 0
        self.created = False

    def report(self):
        try:
            self.detailedresults = ""
            if self.environ.getosfamily() == "linux":
                self.compliant = self.reportLinux()
            if self.environ.getosfamily() == "freebsd":
                self.compliant = self.reportFree()
            if self.environ.getosfamily() == "darwin":
                self.compliant = self.reportMac()
            elif self.environ.getosfamily() == "solaris":
                self.compliant = self.reportSol()
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
    def reportMac(self):
        '''
        check the values of the directives, specified in self.directives
        check that self.path (/private/etc/sysctl.conf) exists
        check that the permissions and ownership on file sysctl.conf
        are 0o600 and 0,0

        @return: compliant
        @rtype: bool
        @author: dwalker
        @change: Breen Malmberg - 1/10/2017 - added doc string; try/except;
                fixed perms for file sysctl.conf (should be 0o600; was 420)
        '''

        compliant = True

        self.editor = ""
        self.path = "/private/etc/sysctl.conf"
        self.tmpPath = self.path + ".tmp"
        sysctl = "/usr/sbin/sysctl"
        self.directives = {"net.inet6.ip6.forwarding": "0",
                           "net.inet6.ip6.maxifprefixes": "1",
                           "net.inet6.ip6.maxifdefrouters": "1",
                           "net.inet6.ip6.maxfrags": "0",
                           "net.inet6.ip6.maxfragpackets": "0",
                           "net.inet6.ip6.neighborgcthresh": "1024",
                           "net.inet6.ip6.use_deprecated": "0",
                           "net.inet6.ip6.hdrnestlimit": "0",
                           "net.inet6.ip6.only_allow_rfc4193_prefixes": "1",
                           "net.inet6.ip6.dad_count": "0",
                           "net.inet6.icmp6.nodeinfo": "0",
                           "net.inet6.icmp6.rediraccept": "1",
                           "net.inet6.ip6.maxdynroutes": "0"}
        self.fixables = {}

        try:

            self.cmdhelper = CommandHelper(self.logger)

            for directive in self.directives:
                cmd = [sysctl, "-n", directive]
                if self.cmdhelper.executeCommand(cmd):
                    output = self.cmdhelper.getOutputString().strip()
                    if output != self.directives[directive]:
                        self.detailedresults += "The value for " + directive + \
                            " is not " + self.directives[directive] + ", it's " + \
                            output + "\n"
                        compliant = False
                        self.fixables[directive] = self.directives[directive]
                else:
                    error = self.cmdhelper.getErrorString()
                    self.detailedresults += "There was an error running the " + \
                        "the command " + cmd + "\n"
                    self.logger.log(LogPriority.DEBUG, error)
                    self.fixables[directive] = self.directives[directive]
                    compliant = False
            if not os.path.exists(self.path):
                compliant = False
            else:
                self.editor = KVEditorStonix(self.statechglogger, self.logger,
                                                 "conf", self.path, self.tmpPath,
                                                 self.directives, "present",
                                                 "closedeq")
                if not self.editor.report():
                    compliant = False
                    self.detailedresults += "Didn't find the correct contents " + \
                        "inside " + self.path + "\n"
                if not checkPerms(self.path, [0, 0, 0o600], self.logger):
                    compliant = False

        except Exception:
            raise

        return compliant

###############################################################################
    def reportLinux(self):
        netwrkfile = ""
        ifacefile = ""
        sysctl = "/etc/sysctl.conf"
        self.editor1, self.editor2 = "", ""
        compliant = True
        interface = {"IPV6_AUTOCONF": "no"}
        interface2 = {"IPV6_PRIVACY": "rfc3041"}
#                       "IPV6_DEFAULTGW": self.gateway,
#                       "IPV6ADDR":self.ipaddr}
        sysctls = {"net.ipv6.conf.default.router_solicitations": "0",
                   "net.ipv6.conf.default.accept_ra_rtr_pref": "0",
                   "net.ipv6.conf.default.accept_ra_pinfo": "0",
                   "net.ipv6.conf.default.accept_ra_defrtr": "0",
                   "net.ipv6.conf.default.autoconf": "0",
                   "net.ipv6.conf.default.dad_transmits": "0",
                   "net.ipv6.conf.default.max_addresses": "1",
                   "net.ipv6.conf.default.accept_ra": "0",
                   "net.ipv6.conf.default.accept_redirect": "0"}
        self.ph = Pkghelper(self.logger, self.environ)
        if self.ph.manager == "yum":
            ifacefile = "/etc/sysconfig/network-scripts/"
            if not os.path.exists(ifacefile):
                ifacefile = ""
            netwrkfile = "/etc/sysconfig/network"
            if not os.path.exists(netwrkfile):
                netwrkfile = ""
        elif self.ph.manager == "zypper":
            ifacefile = "/etc/sysconfig/network"
            if not os.path.exists(ifacefile):
                ifacefile = ""

        tmpfile = sysctl + ".tmp"
        # check if sysctl file is present
        if not os.path.exists(sysctl):
            # if not, create it
            if createFile(sysctl, self.logger):
                self.created = True
                setPerms(sysctl, [0, 0, 420], self.logger)
                tmpfile = sysctl + ".tmp"
                # create an editor to check file
                self.editor1 = KVEditorStonix(self.statechglogger, self.logger,
                                              "conf", sysctl, tmpfile, sysctls,
                                              "present", "openeq")
                if not self.editor1.report():
                    self.detailedresults += "/etc/sysctl file doesn't " + \
                        "contain the correct contents\n"
                    compliant = False
            else:
                compliant = False
        else:
            if not checkPerms(sysctl, [0, 0, 420], self.logger):
                compliant = False
            tmpfile = sysctl + ".tmp"
            self.editor1 = KVEditorStonix(self.statechglogger, self.logger,
                                          "conf", sysctl, tmpfile, sysctls,
                                          "present", "openeq")
            if not self.editor1.report():
                self.detailedresults += "/etc/sysctl file doesn't contain \
the correct contents\n"
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

        if ifacefile:
            dirs = glob.glob(ifacefile + "*")
            for loc in dirs:
                contents = []
                if re.search("^" + ifacefile + "ifcfg", loc):
                    if not checkPerms(loc, [0, 0, 420], self.logger):
                        compliant = False
                    contents = readFile(loc, self.logger)
                    if contents:
                        for key in interface2:
                            found = False
                            iterator = 0
                            for line in contents:
                                if re.search("^#", line) or re.match("^\s*$",
                                                                     line):
                                    continue
                                if re.search("^" + key, line):
                                    if re.search("=", line):
                                        temp = line.split("=")
                                        if temp[1].strip() == interface2[key]:
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
        return compliant
###############################################################################

    def reportFree(self):
        pass
# freebsd 9.0 or later
# "net.inet6.ip6.redirect":"0",
# ipv6_activate_all_interfaces="NO"
# ipv6_defaultrouter="2607:f2f8:100:999::1"
# ifconfig_em0_ipv6="inet6 2607:f2f8:100:999::2 prefixlen 64"
# ip6addrctl_policy="ipv4_prefer"
###############################################################################

    def fix(self):
        try:
            if not self.ci.getcurrvalue():
                return
            self.detailedresults = ""

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
###############################################################################
    def fixMac(self):
        '''
        use the sysctl command to write directives
        create the sysctl.conf file if needed
        set permissions and ownership of sysctl.conf file
        to 0o600 and 0,0

        @return: success
        @rtype: bool
        @author: dwalker
        @change: Breen Malmberg - 1/10/2017 - added doc string; try/except;
                fixed perms for file sysctl.conf (should be 0o600; was 420)
        '''

        success = True
        created = False

        try:

            if self.fixables:
                sysctl = "/usr/sbin/sysctl"
                for directive in self.fixables:
                    cmd = [sysctl, "-w", directive + "=" + self.fixables[directive]]
                    if not self.cmdhelper.executeCommand(cmd):
                        error = self.cmdhelper.getErrorString()
                        self.detailedresults += "There was an error running " + \
                        "the command " + cmd + "\n"
                        self.logger.log(LogPriority.DEBUG, error)
                        success = False
            if not os.path.exists(self.path):
                if createFile(self.path, self.logger):
                    created = True
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    event = {"eventtype": "creation", "filepath": self.path}
                    self.statechglogger.recordchgevent(myid, event)
                else:
                    return False
            if not self.editor:
                self.editor = KVEditorStonix(self.statechglogger, self.logger,
                                                 "conf", self.path, self.tmpPath,
                                                 self.directives, "present",
                                                 "closedeq")
                if not self.editor.report():
                    if self.editor.fix():
                        if not self.editor.commit():
                            success = False
                            self.detailedresults += "KVEditor commit to " + \
                                self.path + " was not successful\n"
                    else:
                        success = False
                        self.detailedresults += "KVEditor fix of " + self.path + \
                            " was not successful\n"
            else:
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                self.editor.setEventID(myid)
                if self.editor.fix():
                    if not self.editor.commit():
                        success = False
                        self.detailedresults += "KVEditor commit to " + \
                            self.path + " was not successful\n"
                else:
                    success = False
                    self.detailedresults += "KVEditor fix of " + self.path + \
                        " was not successful\n"
            if not checkPerms(self.path, [0, 0, 0o600], self.logger):
                if not created:
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    if not setPerms(self.path, [0, 0, 0o600], self.logger,
                                self.statechglogger, myid):
                        self.detailedresults += "Could not set permissions" + \
                            " on " + self.path + "\n"
                        success = False
                else:
                    if not setPerms(self.path, [0, 0, 0o600], self.logger):
                        self.detailedresults += "Could not set permissions" + \
                            " on " + self.path + "\n"
                        success = False

        except Exception:
            raise

        return success

###############################################################################
    def fixLinux(self):
        universal = "#The following lines were added by stonix\n"
        debug = ""
        success = True
        ifacefile = ""
        netwrkfile = ""
        tempstring1 = ""
        tempstring2 = ""
        sysctl = "/etc/sysctl.conf"
        interface = {"IPV6_AUTOCONF": "no"}
        interface2 = {"IPV6_PRIVACY": "rfc3041"}
#                     "IPV6_DEFAULTGW": self.gateway,
#                     "IPV6ADDR":self.ipaddr}
        if self.ph.manager == "yum":
            ifacefile = "/etc/sysconfig/network-scripts/"
            netwrkfile = "/etc/sysconfig/network"
        elif self.ph.manager == "zypper":
            ifacefile = "/etc/sysconfig/network/"
        if self.created:
            self.iditerator += 1
            myid = iterate(self.iditerator, self.rulenumber)
            event = {"eventtype": "creation",
                     "filepath": self.editor1.getPath()}
            self.statechglogger.recordchgevent(myid, event)
        if os.path.exists(sysctl):
            if not checkPerms(sysctl, [0, 0, 420], self.logger):
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                if not setPerms(sysctl, [0, 0, 420], self.logger,
                                self.statechglogger, myid):
                    success = False
            if self.editor1:
                if self.editor1.fixables:
                    self.iditerator += 1
                    if not self.created:
                        myid = iterate(self.iditerator, self.rulenumber)
                        self.editor1.setEventID(myid)
                    if not self.editor1.fix():
                        success = False
                    elif not self.editor1.commit():
                        success = False
                    os.chown(sysctl, 0, 0)
                    os.chmod(sysctl, 420)
                    resetsecon(sysctl)
                    cmdhelper = CommandHelper(self.logger)
                    cmd = ["/sbin/sysctl", "-q", "-e", "-p"]
                    if not cmdhelper.executeCommand(cmd):
                        success = False
        if netwrkfile:
            if not os.path.exists(netwrkfile):
                if not createFile(netwrkfile, self.logger):
                    success = False
                else:
                    if not checkPerms(netwrkfile, [0, 0, 420], self.logger):
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        if not setPerms(netwrkfile, [0, 0, 420], self.logger,
                                        self.statechglogger, myid):
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
                    elif not self.editor2.commit():
                        success = False
                    os.chown(netwrkfile, 0, 0)
                    os.chmod(netwrkfile, 420)
                    resetsecon(netwrkfile)
        if ifacefile:
            if os.path.exists(ifacefile):
                dirs = glob.glob(ifacefile + "*")
                if dirs:
                    for loc in dirs:
                        interface2 = {"IPV6_PRIVACY": "rfc3041"}
#                                       "IPV6_DEFAULTGW": self.gateway,
#                                       "IPV6ADDR":self.ipaddr}
                        interface3 = {"IPV6_PRIVACY": "rfc3041"}
#                                       "IPV6_DEFAULTGW": self.gateway,
#                                       "IPV6ADDR":self.ipaddr}
                        found = False
                        tempstring = ""
                        if re.search('^' + ifacefile + 'ifcfg', loc):
                            filename = loc
                            tmpfile = filename + ".tmp"
                            contents = readFile(filename, self.logger)
                            if not checkPerms(filename, [0, 0, 420],
                                              self.logger):
                                self.iditerator += 1
                                myid = iterate(self.iditerator,
                                               self.rulenumber)
                                if not setPerms(filename, [0, 0, 420],
                                                self.logger,
                                                self.statechglogger, myid):
                                    return False
                            for key in interface2:
                                found = False
                                for line in contents:
                                    if re.search("^#", line) or \
                                            re.match("^\s*$", line):
                                        continue
                                    if re.search("^" + key, line):
                                        if re.search("=", line):
                                            temp = line.split("=")
                                            if temp[1].strip() == \
                                                    interface2[key]:
                                                if found:
                                                    continue
                                                found = True
                                            else:
                                                contents.remove(line)
                                if found:
                                    del interface3[key]
                            for line in contents:
                                tempstring += line
                            tempstring += universal
                            for key in interface3:
                                tempstring += key + "=" + interface3[key] + \
                                    "\n"
                            if not writeFile(tmpfile, tempstring, self.logger):
                                return False
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
                debug += "interface directory which holds interface \
                files, doesn't exist, stonix will not attempt to make this \
                directory or the files contained therein"
                success = False
        return success
