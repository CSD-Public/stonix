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
Created on Aug 28, 2012

@author: dwalker
@change: 02/16/2014 ekkehard Implemented self.detailedresults flow
@change: 02/16/2014 ekkehard Implemented isapplicable
@change: 02/16/2014 ekkehard blacklisted darwin seems to mess up OS X
@change: 04/18/2014 dkennel Replaced old-style CI invocation
@change: 2014/07/29 dkennel Removed undefined variables from code. Remnants of old "method"
@change: 2014/10/17 ekkehard OS X Yosemite 10.10 Update
variable.
@change: 2015/04/15 dkennel updated for new isApplicable
@change: 2015/10/07 eball Help text cleanup
@change: 2015/11/09 ekkehard - make eligible of OS X El Capitan
@change: 2016/05/23 eball Improvements to feedback and workflow
@change: 2016/07/08 ekkehard complete renaming to SecureIPV4
@change: 2017/07/17 ekkehard - make eligible for macOS High Sierra 10.13
@change: 2017/11/13 ekkehard - make eligible for OS X El Capitan 10.11+
@change: 2018/06/08 ekkehard - make eligible for macOS Mojave 10.14
@change: 2019/03/12 ekkehard - make eligible for macOS Sierra 10.12+
@change: 2019/4/11/ dwalker - removed solaris code and other unnecessary
    code, updated linux fix to be more efficient and record change events
    properly.
@change: 2019/06/05 dwalker - refactored linux portion of rule to be
    consistent with other rules that handle sysctl and to properly
    handle sysctl by writing to /etc/sysctl.conf and also using command
'''
from __future__ import absolute_import
from ..stonixutilityfunctions import resetsecon, iterate, readFile, writeFile
from ..stonixutilityfunctions import checkPerms, setPerms, createFile
from ..stonixutilityfunctions import getOctalPerms
from ..rule import Rule
from ..logdispatcher import LogPriority
from ..CommandHelper import CommandHelper
from subprocess import Popen, PIPE, call
from ..KVEditorStonix import KVEditorStonix
import os
import traceback
import re


class SecureIPV4(Rule):

    def __init__(self, config, environ, logger, statechglogger):
        '''Constructor'''
        Rule.__init__(self, config, environ, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 15
        self.cmdhelper = CommandHelper(self.logger)
        self.rulename = "SecureIPV4"
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.sethelptext()
        if self.environ.getostype() == "Mac OS X":
            self.networkTuning2 = self.__InitializeNetworkTuning2()
        else:
            self.networkTuning1 = self.__InitializeNetworkTuning1()
            self.networkTuning2 = self.__InitializeNetworkTuning2()
        self.guidance = ["NSA 2.5.1.1", "NSA 2.5.1.2"]
        self.applicable = {'type': 'white',
                           'family': ['linux', 'solaris', 'freebsd'],
                           'os': {'Mac OS X': ['10.12', 'r', '10.14.10']}}
        self.iditerator = 0
        self.ch = CommandHelper(self.logger)

    def __InitializeNetworkTuning1(self):
        '''Private method to initialize the configurationitem object for the
        NetworkTuning1 bool.
        @return: configurationitem object instance'''

        datatype = 'bool'
        key = "NETWORKTUNING1"
        instructions = "Network Parameter Tuning. You should not need " + \
            "to override this under normal circumstances."
        default = True
        ci = self.initCi(datatype, key, instructions, default)
        return ci

    def __InitializeNetworkTuning2(self):
        '''Private method to initialize the configurationitem object for the
        NetworkTuning2 bool.
        @return: configurationitem object instance'''

        key = "NETWORKTUNING2"
        instructions = "Additional network parameters. Set this to False " + \
            "if you are running a router or a bridge. Also, in rare " + \
            "cases, you may need to set this to False for VMware (if you " + \
            "are using normal VMware routing, True should be fine)."
        default = True
        datatype = "bool"
        ci = self.initCi(datatype, key, instructions, default)
        return ci

    def report(self):
        '''Main parent report method that calls the sub report methods


        :returns: bool

        '''
        try:
            self.detailedresults = ""
            if self.environ.getosfamily() == "linux":
                self.path = "/etc/sysctl.conf"
                self.tmpPath = "/etc/sysctl.conf.tmp"
                self.original = readFile(self.path, self.logger)
                rep1success = self.reportLinux1()
                rep2success = self.reportLinux2()
            elif self.environ.getosfamily() == "freebsd":
                self.path = "/etc/sysctl.conf"
                self.tmpPath = "/etc/sysctl.conf.tmp"
                self.original = readFile(self.path, self.logger)
                rep1success = self.reportFreebsd1()
                rep2success = self.reportFreebsd2()
            elif self.environ.getostype() == "Mac OS X":
                self.path = "/private/etc/sysctl.conf"
                self.tmpPath = "/private/etc/sysctl.conf.tmp"
                rep1success = True
                rep2success = self.reportMac()
            if rep1success and rep2success:
                self.compliant = True
            else:
                self.compliant = False
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
        return self.rulesuccess

    def reportLinux1(self):
        '''Linux specific report method that ensures the items in fileContents
        exist in /etc/sysctl.conf.  Sets self.compliant to True if all items
        exist in the file.  Returns True if successful in updating the file


        :returns: bool

        '''
        compliant = True
        if not os.path.exists(self.path):
            self.detailedresults += self.path + " does not exist\n"
            compliant = False
        else:
            lfc = {"net.ipv4.conf.all.secure_redirects": "0",
                   "net.ipv4.conf.all.accept_redirects": "0",
                   "net.ipv4.conf.all.rp_filter": "1",
                   "net.ipv4.conf.all.log_martians": "1",
                   "net.ipv4.conf.all.accept_source_route": "0",
                   "net.ipv4.conf.default.accept_redirects": "0",
                   "net.ipv4.conf.default.secure_redirects": "0",
                   "net.ipv4.conf.default.rp_filter": "1",
                   "net.ipv4.conf.default.accept_source_route": "0",
                   "net.ipv4.tcp_syncookies": "1",
                   "net.ipv4.icmp_echo_ignore_broadcasts": "1",
                   "net.ipv4.tcp_max_syn_backlog": "4096"}
            editor = KVEditorStonix(self.statechglogger, self.logger,
                                    "conf", self.path, self.tmpPath, lfc,
                                    "present", "openeq")
            if not editor.report():
                self.detailedresults += self.path + " is not configured " + \
                    "correctly for configuration item 1\n"
                compliant = False
            if not checkPerms(self.path, [0, 0, 0o644], self.logger):
                self.detailedresults += "Permissions are incorrect on " + \
                    self.path + "\n"
                compliant = False
        for key in lfc:
            self.ch.executeCommand("/sbin/sysctl " + key)
            retcode = self.ch.getReturnCode()

            if retcode != 0:
                self.detailedresults += "Failed to get value of core dumps configuration with sysctl command\n"
                errmsg = self.ch.getErrorString()
                self.logger.log(LogPriority.DEBUG, errmsg)
                compliant = False
            else:
                output = self.ch.getOutputString()
                if output.strip() != key + " = " + lfc[key]:
                    compliant = False
                    self.detailedresults += "sysctl output has incorrect value: " + \
                        output + "\n"
        return compliant

    def reportLinux2(self):
        '''Linux specific report method2 that ensures the items in fileContents
        exist in /etc/sysctl.conf.  Sets self.compliant to True if all items
        exist in the file.  Returns True if successful in updating the file


        :returns: bool

        '''
        compliant = True
        if not os.path.exists(self.path):
            compliant = False
        else:
            lfc = {"net.ipv4.conf.default.send_redirects": "0",
                   "net.ipv4.conf.all.send_redirects": "0",
                   "net.ipv4.ip_forward": "0"}
            editor = KVEditorStonix(self.statechglogger, self.logger,
                                    "conf", self.path, self.tmpPath,
                                    lfc, "present", "openeq")
            if not editor.report():
                self.detailedresults += self.path + " is not configured " + \
                    "correctly for configuration item 2\n"
                compliant = False

        for key in lfc:
            self.ch.executeCommand("/sbin/sysctl " + key)
            retcode = self.ch.getReturnCode()

            if retcode != 0:
                self.detailedresults += "Failed to get value of core dumps configuration with sysctl command\n"
                errmsg = self.ch.getErrorString()
                self.logger.log(LogPriority.DEBUG, errmsg)
                compliant = False
            else:
                output = self.ch.getOutputString()
                if output.strip() != key + " = " + lfc[key]:
                    compliant = False
                    self.detailedresults += "sysctl output has incorrect value: " + \
                        output + "\n"
        return compliant

    def reportMac(self):
        '''Mac specific report method1 that ensures the items in fileContents
        exist in /etc/sysctl.conf.  Sets self.compliant to True if all items
        exist in the file.


        :returns: compliant

        :rtype: bool
@author: dwalker
@change: Breen Malmberg - 1/10/2017 - minor doc string adjustments; fixed
        permissions on file /etc/sysctl.conf (needs to be 0o600; was 0o644);
        try/except

        '''

        compliant = True

        try:

            if not os.path.exists(self.path):
                self.detailedresults += self.path + " does not exist\n"
                compliant = False
            else:
                mfc = {"net.inet.ip.forwarding": "0",
                       "net.inet.ip.redirect": "0"}
                kvtype = "conf"
                intent = "present"
                self.editor = KVEditorStonix(self.statechglogger, self.logger,
                                             kvtype, self.path, self.tmpPath, mfc,
                                             intent, "closedeq")
                if not self.editor.report():
                    self.detailedresults += self.path + " is not " + \
                        "configured correctly\n"
                    compliant = False
                else:
                    self.detailedresults += self.path + " is " + \
                        "configured correctly\n"
                if not checkPerms(self.path, [0, 0, 0o600], self.logger):
                    self.detailedresults += "Permissions are incorrect on " + \
                        self.path + ": Expected 644, found " + \
                        str(getOctalPerms(self.path)) + "\n"
                    compliant = False

        except Exception:
            raise

        return compliant

    def reportFreebsd1(self):
        '''Freebsd specific report method1 that ensures the items in the file
        exist in /etc/sysctl.conf.  Sets self.compliant to True if all items
        exist in the file.  Returns True if successful in updating the file


        :returns: bool

        '''
        compliant = True
        if not os.path.exists(self.path):
            self.detailedresults += self.path + " does not exist\n"
            compliant = False
        else:
            ffc = {"net.inet.icmp.bmcastecho": "0",
                   "net.inet.ip.redirect": "0",
                   "net.inet.icmp.maskrepl": "0",
                   "net.inet.ip.sourceroute": "0",
                   "net.inet.ip.accept_sourceroute": "0",
                   "net.inet.tcp.syncookies": "1"}
            kvtype = "conf"
            intent = "present"
            self.editor = KVEditorStonix(self.statechglogger, self.logger,
                                         kvtype, self.path, self.tmpPath, ffc,
                                         intent, "openeq")
            if not self.editor.report():
                compliant = False
            if not checkPerms(self.path, [0, 0, 0o644], self.logger):
                self.detailedresults += "Permissions are incorrect on " + \
                    self.path + ": Expected 644, found " + \
                    str(getOctalPerms(self.path)) + "\n"
                compliant = False
        return compliant

    def reportFreebsd2(self):
        '''Freebsd specific report method1 that ensures the items in
        fileContents exist in /etc/sysctl.conf. Sets self.compliant to True
        if all items exist in the file. Returns True if successful in updating
        the file


        :returns: bool

        '''
        compliant = True
        if not os.path.exists(self.path):
            self.detailedresults += self.path + " does not exist\n"
            compliant = False
        else:
            ffc = {"net.inet.ip.forwarding": "0",
                   "net.inet.ip.fastforwarding": "0"}
            if not self.networkTuning1.getcurrvalue():
                kvtype = "conf"
                intent = "present"
                self.editor = KVEditorStonix(self.statechglogger, self.logger,
                                             kvtype, self.path, self.tmpPath,
                                             ffc, intent, "closedeq")
            else:
                self.editor.setData(ffc)
            if not self.editor.report():
                compliant = False
            if not checkPerms(self.path, [0, 0, 0o644], self.logger):
                self.detailedresults += "Permissions are incorrect on " + \
                    self.path + ": Expected 644, found " + \
                    str(getOctalPerms(self.path)) + "\n"
                compliant = False
        return compliant

    def fix(self):
        '''Main parent fix method that calls the sub fix methods


        :returns: bool

        '''
        try:
            if not self.networkTuning1 and not self.networkTuning2:
                return
            self.detailedresults = ""
            success = True
            self.iditerator = 0
            eventlist = self.statechglogger.findrulechanges(self.rulenumber)
            for event in eventlist:
                self.statechglogger.deleteentry(event)

            if self.environ.getosfamily() == "linux":
                self.rulesuccess = self.fixLinux()
            elif self.environ.getosfamily() == "freebsd":
                self.rulesuccess = self.fixFreebsd()
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

    def fixLinux(self):
        success = True
        created = False
        debug = ""
        sysctl = "/etc/sysctl.conf"
        tmpfile = sysctl + ".tmp"
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
                self.formatDetailedResults("fix", False,
                                           self.detailedresults)
        if not checkPerms(sysctl, [0, 0, 0o644], self.logger):
            if not created:
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                if not setPerms(sysctl, [0, 0, 0o644], self.logger,
                                self.statechglogger, myid):
                    success = False
        lfc = {}
        if self.networkTuning1.getcurrvalue():
            lfc.update({"net.ipv4.conf.all.secure_redirects": "0",
                        "net.ipv4.conf.all.accept_redirects": "0",
                        "net.ipv4.conf.all.rp_filter": "1",
                        "net.ipv4.conf.all.log_martians": "1",
                        "net.ipv4.conf.all.accept_source_route": "0",
                        "net.ipv4.conf.default.accept_redirects": "0",
                        "net.ipv4.conf.default.secure_redirects": "0",
                        "net.ipv4.conf.default.rp_filter": "1",
                        "net.ipv4.conf.default.accept_source_route": "0",
                        "net.ipv4.tcp_syncookies": "1",
                        "net.ipv4.icmp_echo_ignore_broadcasts": "1",
                        "net.ipv4.tcp_max_syn_backlog": "4096"})
        if self.networkTuning2.getcurrvalue():
            lfc.update({"net.ipv4.conf.default.send_redirects": "0",
                        "net.ipv4.conf.all.send_redirects": "0",
                        "net.ipv4.ip_forward": "0"})
        self.editor = KVEditorStonix(self.statechglogger, self.logger,
                                         "conf", sysctl, tmpfile,
                                         lfc, "present", "openeq")
        if not self.editor.report():
            if self.editor.fixables:
                # If we did not create the file, set an event ID for the
                # KVEditor's undo event to record the file write
                if not created:
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    self.editor.setEventID(myid)
                if not self.editor.fix():
                    success = False
                    debug = "KVEditor fix of " + self.path + \
                                            " was not successful\n"
                    self.logger.log(LogPriority.DEBUG, debug)
                elif not self.editor.commit():
                    success = False
                    debug = "KVEditor commit to " + \
                        self.path + " was not successful\n"
                    self.logger.log(LogPriority.DEBUG, debug)
                # permissions on file are incorrect
                if not checkPerms(self.path, [0, 0, 0o644], self.logger):
                    if not setPerms(self.path, [0, 0, 0o644], self.logger):
                        self.detailedresults += "Could not set permissions on " + \
                                                self.path + "\n"
                        success = False
                resetsecon(self.path)

        # here we also check the output of the sysctl command for each key
        # to cover all bases
        for key in lfc:
            if self.ch.executeCommand("/sbin/sysctl " + key):
                output = self.ch.getOutputString().strip()
                if not re.search(lfc[key] + "$", output):
                    undovalue = output[-1]
                    self.ch.executeCommand("/sbin/sysctl -w " + key + "=" + lfc[key])
                    retcode = self.ch.getReturnCode()
                    if retcode != 0:
                        success = False
                        self.detailedresults += "Failed to set " + key + " = " + lfc[key] + "\n"
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
        return success

    def fixMac(self):
        '''run fix actions for mac systems


        :returns: success

        :rtype: bool
@author: dwalker
@change: Breen Malmberg - 1/10/2017 - added doc string; try/except;
        fixed perms for file sysctl.conf (should be 0o600; was 0o644)

        '''

        success = True

        try:

            if not os.path.exists(self.path):
                if createFile(self.path, self.logger):
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    event = {"eventtype": "creation", "filepath": self.path}
                    self.statechglogger.recordchgevent(myid, event)
                else:
                    return False
            if self.networkTuning2.getcurrvalue():
                if not self.editor:
                    mfc = {"net.inet.ip.forwarding": "0",
                           "net.inet.ip.redirect": "0"}
                    kvtype = "conf"
                    intent = "present"
                    self.editor = KVEditorStonix(self.statechglogger, self.logger,
                                                 kvtype, self.path, self.tmpPath,
                                                 mfc, intent, "closedeq")
                if not self.editor.report():
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
                    resetsecon(self.path)
                if not checkPerms(self.path, [0, 0, 0o600], self.logger):
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    if not setPerms(self.path, [0, 0, 0o600], self.logger,
                                    self.statechglogger, myid):
                        self.detailedresults += "Could not set permissions on " + \
                            self.path + "\n"
                        success = False

        except Exception:
            raise

        return success

    def fixFreebsd(self):
        if not checkPerms(self.path, [0, 0, 0o644], self.logger):
            self.iditerator += 1
            myid = iterate(self.iditerator, self.rulenumber)
            if not setPerms(self.path, [0, 0, 0o644], self.logger,
                            self.statechglogger, myid):
                return False
        if self.networkTuning1.getcurrvalue() or \
                self.networkTuning2.getcurrvalue():
            if self.editor.fixables:
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                self.editor.setEventID(myid)
                if not self.editor.fix():
                    return False
                elif not self.editor.commit():
                    return False
                os.chown(self.path, 0, 0)
                os.chmod(self.path, 0o644)
                resetsecon(self.path)
                cmd = ["/usr/sbin/service", "sysctl", "restart"]
                self.ch.executeCommand(cmd)
                if self.ch.getReturnCode() != 0:
                    self.detailedresults = "Unable to restart sysctl\n"
                    self.logger.log(LogPriority.DEBUG, self.detailedresults)
                    return False
                else:
                    return True
            else:
                return True
