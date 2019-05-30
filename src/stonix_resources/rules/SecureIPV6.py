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
@change: 2019/03/12 ekkehard - make eligible for macOS Sierra 10.12+
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
                           'os': {'Mac OS X': ['10.12', 'r', '10.14.10']}}
        self.iditerator = 0
        # self.editor1: sysctl file editor
        # self.editor2: network file editor
        self.editor1, self.editor2 = "", ""
        self.ch = CommandHelper(self.logger)

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
        '''check the values of the directives, specified in self.directives
        check that self.path (/private/etc/sysctl.conf) exists
        check that the permissions and ownership on file sysctl.conf
        are 0o600 and 0,0


        :returns: compliant

        :rtype: bool
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
        compliant = True
        self.interface1 = {"IPV6_AUTOCONF": "no"}
        self.interface2 = {"IPV6_PRIVACY": "rfc3041"}
        self.sysctls = {"net.ipv6.conf.default.router_solicitations": "0",
                   "net.ipv6.conf.default.accept_ra_rtr_pref": "0",
                   "net.ipv6.conf.default.accept_ra_pinfo": "0",
                   "net.ipv6.conf.default.accept_ra_defrtr": "0",
                   "net.ipv6.conf.default.autoconf": "0",
                   "net.ipv6.conf.default.dad_transmits": "0",
                   "net.ipv6.conf.default.max_addresses": "1",
                   "net.ipv6.conf.default.accept_ra": "0",
                   "net.ipv6.conf.default.accept_redirects": "0"}
        self.ph = Pkghelper(self.logger, self.environ)

        # check compliancy of /etc/sysctl.conf file
        if not os.path.exists(sysctl):
            compliant = False
            self.detailedresults += sysctl + " file doesn't exist\n"
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
            if retcode != 0:
                self.detailedresults += "Failed to get value of core dumps configuration with sysctl command\n"
                errmsg = self.ch.getErrorString()
                self.logger.log(LogPriority.DEBUG, errmsg)
                compliant = False
            else:
                output = self.ch.getOutputString()
                if output.strip() != key + " = " + self.sysctls[key]:
                    compliant = False
                    self.detailedresults += "sysctl output has incorrect value: " + \
                                            output + "\n"

        # set the appropriate files based on the system
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

        # Check contents of network file
        if netwrkfile:
            if os.path.exists(netwrkfile):
                if not checkPerms(netwrkfile, [0, 0, 0o644], self.logger):
                    compliant = False
                tmpfile = netwrkfile + ".tmp"
                self.editor2 = KVEditorStonix(self.statechglogger, self.logger,
                                              "conf", netwrkfile, tmpfile,
                                              self.interface1, "present", "closedeq")
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
                    if not checkPerms(loc, [0, 0, 0o644], self.logger):
                        compliant = False
                    contents = readFile(loc, self.logger)
                    if contents:
                        for key in self.interface2:
                            found = False
                            iterator = 0
                            for line in contents:
                                if re.search("^#", line) or re.match("^\s*$",
                                                                     line):
                                    continue
                                if re.search("^" + key, line):
                                    if re.search("=", line):
                                        temp = line.split("=")
                                        if temp[1].strip() == self.interface2[key]:
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
        '''use the sysctl command to write directives
        create the sysctl.conf file if needed
        set permissions and ownership of sysctl.conf file
        to 0o600 and 0,0


        :returns: success

        :rtype: bool
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
        created = False

        # fix sysctl / tuning kernel parameters
        # manually write key value pairs to /etc/sysctl.conf
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
                self.detailedresults += "Could not create file " + self.path + \
                                        "\n"
                success = False
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
                    # KVEditor's undo event to record the file write
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
                    # permissions on file are incorrect
                    if not checkPerms(sysctl, [0, 0, 0o644], self.logger):
                        # if we didn't create the file and already record an event
                        # for that, then we're going to record the perm change
                        if not created:
                            self.iditerator += 1
                            myid = iterate(self.iditerator, self.rulenumber)
                            if not setPerms(sysctl, [0, 0, 0o644], self.logger,
                                            self.statechglogger, myid):
                                success = False
                                self.detailedresults += "Unable to set permissions on /etc/sysctl.conf\n"
                        else:
                            # otherwise just change the permissions without recording
                            # the perm change
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
                if not re.search(self.sysctls[key] + "$", output):
                    undovalue = output[-1]
                    self.ch.executeCommand("/sbin/sysctl -w " + key + "=" + self.sysctls[key])
                    retcode = self.ch.getReturnCode()
                    if retcode != 0:
                        success = False
                        self.detailedresults += "Failed to set " + key + " = " + self.sysctls[key] + "\n"
                        errmsg = self.ch.getErrorString()
                        self.logger.log(LogPriority.DEBUG, errmsg)
                    else:
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        command = "/sbin/sysctl -w " + key + "=" + undovalue
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

        # correct the network file if it exists
        if netwrkfile:
            created = False
            if not os.path.exists(netwrkfile):
                if not createFile(netwrkfile, self.logger):
                    success = False
                    debug = "Unable to create " + netwrkfile + " file\n"
                    self.logger.log(LogPriority.DEBUG, debug)
                else:
                    created = True
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    event = {"eventtype": "creation",
                             "filepath": netwrkfile}
                    self.statechglogger.recordchgevent(myid, event)
                    tmpfile = netwrkfile + ".tmp"
                    self.editor2 = KVEditorStonix(self.statechglogger, self.logger,
                                                  "conf", netwrkfile, tmpfile,
                                                  self.interface1, "present", "closedeq")
                    self.editor2.report()
            if os.path.exists(netwrkfile):
                if not checkPerms(netwrkfile, [0, 0, 0o644], self.logger):
                    if not created:
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        if not setPerms(netwrkfile, [0, 0, 0o644], self.logger,
                                        self.statechglogger, myid):
                            success = False
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
                        os.chmod(netwrkfile, 0o644)
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
                            if not checkPerms(filename, [0, 0, 0o644],
                                              self.logger):
                                self.iditerator += 1
                                myid = iterate(self.iditerator,
                                               self.rulenumber)
                                if not setPerms(filename, [0, 0, 0o644],
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
                            os.chmod(filename, 0o644)
                            resetsecon(filename)
            elif not os.path.exists(ifacefile) and ifacefile != "":
                # will not attempt to create the interface files
                self.detailedresults += "Interface directory which holds interface \
                files, doesn't exist. Stonix will not attempt to make this \
                directory or the files contained therein."
                success = False
        return success
