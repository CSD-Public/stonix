###############################################################################
#                                                                             #
# Copyright 2015-2019.  Los Alamos National Security, LLC. This material was  #
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
Created on May 27, 2016

@author: dkennel
@change: 2017/08/28 ekkehard - Added self.sethelptext()
@change: 2017/10/23 rsn - change to new service helper interface
@change: 2018/08/29 Brandon R. Gonzales - increased the sleep time in fixes to
    give iptables more time to restart
'''
from __future__ import absolute_import

import os
import traceback
import re
import time

from ..ServiceHelper import ServiceHelper
from ..CommandHelper import CommandHelper
from ..rule import Rule
from ..logdispatcher import LogPriority
from ..stonixutilityfunctions import iterate, writeFile, readFile, createFile, checkPerms, setPerms, resetsecon


class ConfigureLinuxFirewall(Rule):
    '''
    The configureLinuxFirewall class attempts to audit and configure firewalls
    for Linux OS based systems. Note: there is tremendous variations in the
    approach taken by the various distributions on how to manage firewalls,
    this code should work effectively for debian, ubuntu, RHEL and close
    derivatives. Note: unlike many other rules this behaves as a binary state
    manager, the undo will set the system back to an as new state with no
    firewalls.
    '''

    def __init__(self, config, environ, logger, statechglogger):
        '''
        Constructor
        '''
        Rule.__init__(self, config, environ, logger, statechglogger)
        self.config = config
        self.environ = environ
        self.logger = logger
        self.statechglogger = statechglogger
        self.rulenumber = 92
        self.rulename = 'ConfigureLinuxFirewall'
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.sethelptext()
        self.rootrequired = True
        self.applicable = {'type': 'white',
                           'family': ['linux']}
        self.servicehelper = ServiceHelper(self.environ, self.logger)
        self.serviceTarget = ""
        self.cmdhelper = CommandHelper(self.logger)
        self.guidance = ['NIST 800-53 AC-4', 'DISA RHEL 7 STIG 2.5.7.1',
                         'DISA RHEL 7 STIG 2.5.7.1.1',
                         'DISA RHEL 7 STIG 2.5.8.1.1',
                         'DISA RHEL 7 STIG 2.5.8.1.2',
                         'DISA RHEL 7 STIG 2.5.8.1.3',
                         'DISA RHEL 7 STIG 2.5.8.2.1',
                         'DISA RHEL 7 STIG 2.5.8.2.2',
                         'DISA RHEL 7 STIG 2.5.8.2.3',
                         'DISA RHEL 7 STIG 2.5.8.2.4']
        datatype = 'bool'
        key = 'CONFIGURELINUXFIREWALL'
        instructions = '''To disable this rule set the value of \
CONFIGURELINUXFIREWALL to False.'''
        default = True
        self.clfci = self.initCi(datatype, key, instructions, default)
        self.scriptType = ""
        self.iptables, self.ip6tables, self.iprestore, self.ip6restore = "", "", "", ""
        self.checkIptables()
        self.iditerator = 0

    def report(self):
        """
        Report on whether the firewall meets baseline expectations.

        @return: bool
        @author: D.Kennel
        """
        try:
            compliant = True
            iptablesrunning = False
            ip6tablesrunning = False
            catchall = False
            catchall6 = False
            self.detailedresults = ""
            self.iptScriptPath = ""
            scriptExists = ""
            if self.checkFirewalld():
                if self.servicehelper.auditService('firewalld.service', serviceTarget=self.serviceTarget):
                    compliant = True
                else:
                    compliant = False
                    self.detailedresults = 'This system appears to have ' + \
                        'firewalld but it is not running as required'
            elif self.checkUFW():
                cmdufw = '/usr/sbin/ufw status'
                if not self.cmdhelper.executeCommand(cmdufw):
                    self.detailedresults += "Unable to run " + \
                        "ufw status command\n"
                    compliant = False
                else:
                    outputufw = self.cmdhelper.getOutputString()
                    if re.search('Status: inactive', outputufw):
                        compliant = False
                        self.detailedresults += 'This system appears to have ' + \
                            'ufw but it is not running as required'
                    elif re.search('Status: active', outputufw):
                        cmdufw = "/usr/sbin/ufw status verbose"
                        if not self.cmdhelper.executeCommand(cmdufw):
                            compliant = False
                            self.detailedresults += "Cannot retrieve firewall rules\n"
                        else:
                            outputufw = self.cmdhelper.getOutputString()
                            if not re.search("Default\:\ deny\ \(incoming\)", outputufw):
                                compliant = False
                                self.detailedresults += "The default value for " + \
                                    "incoming unspecified packets is not deny\n"
            elif self.checkIsOther():
                # for debian and opensuse systems
                if "iptables" not in self.servicehelper.listServices():
                    cmd = [self.iptables, "-L"]
                    if not self.cmdhelper.executeCommand(cmd):
                        self.detailedresults += "Unable to run " + \
                            "iptables -L command\n"
                        compliant = False
                    else:
                        output = self.cmdhelper.getOutput()
                        for line in output:
                            if re.search('Chain INPUT \(policy REJECT\)|REJECT' +
                                         '\s+all\s+--\s+anywhere\s+anywhere', line):
                                catchall = True
                                break
                        self.logger.log(LogPriority.DEBUG,
                                        ['ConfigureLinuxFirewall.report',
                                         "Debian type system. ipv4 catchall rule: "
                                         + str(catchall)])
                if "ip6tables" not in self.servicehelper.listServices():
                    cmd6 = [self.ip6tables, "-L"]
                    if not self.cmdhelper.executeCommand(cmd6):
                        self.detailedresults += "Unable to run " + \
                            "ip6tables -L command\n"
                        compliant = False
                    else:
                        output6 = self.cmdhelper.getOutput()
                        for line in output6:
                            if re.search('Chain INPUT \(policy REJECT\)|REJECT' +
                                         '\s+all\s+anywhere\s+anywhere', line):
                                catchall6 = True
                                break
                        self.logger.log(LogPriority.DEBUG,
                                        ['ConfigureLinuxFirewall.report',
                                         "Debian type system. ipv6 catchall rule: "
                                         + str(catchall6)])

                if os.path.exists("/etc/network/if-pre-up.d"):
                    self.iptScriptPath = "/etc/network/if-pre-up.d/iptables"
                    self.scriptType = "debian"
                elif os.path.exists("/etc/sysconfig/scripts"):
                    self.iptScriptPath = "/etc/sysconfig/scripts/SuSEfirewall2-custom"
                    self.scriptType = "suse"
                else:
                    self.logger.log(LogPriority.DEBUG,
                                    ['ConfigureLinuxFirewall.report',
                                     "No acceptable path for a startup " +
                                     "script found"])
                if self.iptScriptPath:
                    if os.path.exists(self.iptScriptPath):
                        scriptExists = True
                    else:
                        scriptExists = False

                if not catchall:
                    compliant = False
                    self.detailedresults += 'This system appears to use ' + \
                        'iptables but the expected deny all is missing ' + \
                        'from the rules.\n'
                    self.logger.log(LogPriority.DEBUG,
                                    ['ConfigureLinuxFirewall.report',
                                     "Debian type system. Missing v4 deny all."])
                if not catchall6:
                    compliant = False
                    self.detailedresults += 'This system appears to use ' + \
                        'ip6tables but the expected deny all is missing ' + \
                        'from the rules.\n'
                    self.logger.log(LogPriority.DEBUG,
                                    ['ConfigureLinuxFirewall.report',
                                     "Debian type system. Missing v6 deny all."])
                if not scriptExists:
                    compliant = False
                    self.detailedresults += 'This system appears to use ' + \
                        'iptables but the startup script is not present\n'
                    self.logger.log(LogPriority.DEBUG,
                                    ['ConfigureLinuxFirewall.report',
                                     "Debian type system. Missing startup " +
                                     "script"])
            else:
                if self.servicehelper.auditService('iptables.service', serviceTarget=self.serviceTarget) or \
                   self.servicehelper.auditService('iptables', serviceTarget=self.serviceTarget):
                    iptablesrunning = True
                self.logger.log(LogPriority.DEBUG,
                                ['ConfigureLinuxFirewall.report',
                                 "RHEL 6 type system. iptables service: " +
                                 str(iptablesrunning)])
                if self.servicehelper.auditService('ip6tables.service', serviceTarget=self.serviceTarget) or \
                   self.servicehelper.auditService('ip6tables', serviceTarget=self.serviceTarget):
                    ip6tablesrunning = True
                self.logger.log(LogPriority.DEBUG,
                                ['ConfigureLinuxFirewall.report',
                                 "RHEL 6 type system. ip6tables service: " +
                                 str(ip6tablesrunning)])
                if self.iptables:
                    cmd = [self.iptables, "-L"]
                    if not self.cmdhelper.executeCommand(cmd):
                        self.detailedresults += "Unable to run " + \
                            "iptables -L command\n"
                        compliant = False
                    else:
                        output = self.cmdhelper.getOutput()
                        for line in output:
                            if re.search('Chain INPUT \(policy REJECT\)|REJECT' +
                                         '\s+all\s+--\s+anywhere\s+anywhere', line):
                                catchall = True
                                break
                        self.logger.log(LogPriority.DEBUG,
                                        ['ConfigureLinuxFirewall.report',
                                         "RHEL 6 type system. ipv4 catchall rule: "
                                         + str(catchall)])
                if self.ip6tables:
                    cmd6 = [self.ip6tables, "-L"]
                    if not self.cmdhelper.executeCommand(cmd6):
                        self.detailedresults += "Unable to run " + \
                            "ip6tables -L command\n"
                        compliant = False
                    else:
                        output6 = self.cmdhelper.getAllString()
                        if re.search('Chain INPUT \(policy REJECT\)|REJECT' +
                                     '\s+all\s+anywhere\s+anywhere', output6):
                            catchall6 = True
                        elif re.search("can't initialize ip6tables", output6):
                            catchall6 = True
                            self.logger.log(LogPriority.DEBUG,
                                            ['ConfigureLinuxFirewall.report',
                                             "IPv6 is disabled. " +
                                             "Reporting as compliant."])
                        self.logger.log(LogPriority.DEBUG,
                                        ['ConfigureLinuxFirewall.report',
                                         "RHEL 6 type system. ipv6 catchall rule: "
                                         + str(catchall6)])
                if not iptablesrunning:
                    compliant = False
                    self.detailedresults += 'This system appears to use ' + \
                        'iptables but it is not running as required.\n'
                    self.logger.log(LogPriority.DEBUG,
                                    ['ConfigureLinuxFirewall.report',
                                     "RHEL 6 type system. IPtables not running."])
                if not ip6tablesrunning:
                    compliant = False
                    self.detailedresults += 'This system appears to use ' + \
                        'ip6tables but it is not running as required.\n'
                    self.logger.log(LogPriority.DEBUG,
                                    ['ConfigureLinuxFirewall.report',
                                     "RHEL 6 type system. IP6tables not running."])
                if not catchall:
                    compliant = False
                    self.detailedresults += 'This system appears to use ' + \
                        'iptables but the expected deny all is missing ' + \
                        'from the rules.\n'
                    self.logger.log(LogPriority.DEBUG,
                                    ['ConfigureLinuxFirewall.report',
                                     "RHEL 6 type system. Missing v4 deny all."])
                if not catchall6:
                    compliant = False
                    self.detailedresults += 'This system appears to use ' + \
                        'ip6tables but the expected deny all is missing ' + \
                        'from the rules.\n'
                    self.logger.log(LogPriority.DEBUG,
                                    ['ConfigureLinuxFirewall.report',
                                     "RHEL 6 type system. Missing v6 deny all."])
            self.compliant = compliant
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
        """
        Enable the firewall services and establish basic rules if needed.

        @author: D. Kennel
        """
        try:
            if not self.clfci.getcurrvalue():
                return
            self.iditerator = 0
            self.detailedresults = ""
            success = True
            if self.checkFirewalld():
                if self.servicehelper.enableService('firewalld.service', serviceTarget=self.serviceTarget):
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    cmd = "/usr/bin/systemctl disable firewalld.service"
                    event = {"eventtype": "commandstring",
                             "command": cmd}
                    self.statechglogger.recordchgevent(myid, event)
                    self.detailedresults += "Firewall configured.\n "
                else:
                    success = False
                    self.detailedresults += "Unable to enable firewall\n"
                    debug = "Unable to enable firewall\n"
                    self.logger.log(LogPriority.DEBUG, debug)
            elif self.checkUFW():
                self.logger.log(LogPriority.DEBUG, "System uses ufw. Running ufw commands...")
                cmdufw = '/usr/sbin/ufw status'
                if not self.cmdhelper.executeCommand(cmdufw):
                    self.detailedresults += "Unable to run " + \
                        "ufw status command\n"
                    success = False
                else:
                    outputufw = self.cmdhelper.getOutputString()
                    if re.search('Status: inactive', outputufw):
                        ufwcmd = '/usr/sbin/ufw --force enable'
                        if not self.cmdhelper.executeCommand(ufwcmd):
                            self.detailedresults += "Unable to run " + \
                                "ufw enable command\n"
                            success = False
                        else:
                            self.iditerator += 1
                            myid = iterate(self.iditerator, self.rulenumber)
                            undocmd = "/usr/sbin/ufw --force disable"
                            event = {"eventtype": "commandstring",
                                     "command": undocmd}
                            self.statechglogger.recordchgevent(myid, event)
                            cmdufw = "/usr/sbin/ufw status verbose"
                            if not self.cmdhelper.executeCommand(cmdufw):
                                self.detailedresults += "Unable to retrieve firewall rules\n"
                                success = False
                            else:
                                outputfw = self.cmdhelper.getOutputString()
                                if not re.search("Default\:\ deny\ \(incoming\)", outputfw):
                                    ufwcmd = "/usr/sbin/ufw default deny incoming"
                                    if not self.cmdhelper.executeCommand(ufwcmd):
                                        self.detailedresults += "Unable to set default " + \
                                            "rule for incoming unspecified packets\n"
                                        success = False
                                    else:
                                        self.iditerator += 1
                                        myid = iterate(self.iditerator, self.rulenumber)
                                        undocmd = "/usr/sbin/ufw default allow incoming"
                                        event = {"eventtype": "commandstring",
                                                 "command": undocmd}
                                        self.statechglogger.recordchgevent(myid, event)
                    elif re.search('Status: active', outputufw):
                        cmdufw = "/usr/sbin/ufw status verbose"
                        if not self.cmdhelper.executeCommand(cmdufw):
                            self.detailedresults += "Cannot retrieve firewall rules\n"
                            success = False
                        else:
                            outputufw = self.cmdhelper.getOutputString()
                            if not re.search("Default\:\ deny\ \(incoming\)", outputufw):
                                ufwcmd = "/usr/sbin/ufw default deny incoming"
                                if not self.cmdhelper.executeCommand(ufwcmd):
                                    self.detailedresults += "Unable to set default " + \
                                        "rule for incoming unspecified packets\n"
                                    success = False
                                else:
                                    self.iditerator += 1
                                    myid = iterate(self.iditerator, self.rulenumber)
                                    undocmd = "/usr/sbin/ufw default allow incoming"
                                    event = {"eventtype": "commandstring",
                                             "command": undocmd}
                                    self.statechglogger.recordchgevent(myid, event)
            elif self.checkIsOther():
                #this script will ensure that iptables gets configured
                #each time the network restarts
                iptables = self.getScriptValues("iptables")
                ip6tables = self.getScriptValues("ipt6tables")
                if self.scriptType == "debian":
                    iptScript = '#!/bin/bash\n' + self.iprestore + \
                                ' <<< "' + iptables + '"\n' + self.ip6restore + \
                                ' <<< "' + ip6tables + '"'
                else:
                    iptScript = self.getScriptValues("iptscript")
                if not os.path.exists(self.iptScriptPath):
                    created = False
                    if not createFile(self.iptScriptPath, self.logger):
                        created = True
                        success = False
                        self.detailedresults += "Unable to create file " + self.iptScriptPath + "\n"
                    else:
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        event = {"eventtype": "creation",
                                 "filepath": self.iptScriptPath}
                        self.statechglogger.recordchgevent(myid, event)
                if os.path.exists(self.iptScriptPath):
                    if not checkPerms(self.iptScriptPath, [0, 0, 0o755], self.logger):
                        if not created:
                            self.iditerator += 1
                            myid = iterate(self.iditerator, self.rulenumber)
                            if not setPerms(self.iptScriptPath, [0, 0, 0o755], self.logger, self.statechglogger, myid):
                                success = False
                                self.detailedresults += "Unable to set permissions on " + self.iptScriptPath + "\n"
                    contents = readFile(self.iptScriptPath, self.logger)
                    if contents != iptScript:
                        tempfile = self.iptScriptPath + ".tmp"
                        if not writeFile(tempfile, self.iptScriptPath, self.logger):
                            success = False
                            self.detailedresults += "Unable to write contents to " + self.iptScriptPath + "\n"
                        else:
                            if not created:
                                self.iditerator += 1
                                myid = iterate(self.iditerator, self.rulenumber)
                                event = {"eventtype": "conf",
                                         "filepath": self.iptScriptPath}
                                self.statechglogger.recordchgevent(myid, event)
                                self.statechglogger.recordfilechange(self.iptScriptPath, tempfile, myid)
                                os.rename(tempfile, self.iptScriptPath)
                                os.chown(self.iptScriptPath, 0, 0)
                                os.chmod(self.iptScriptPath, 0o755)
                                resetsecon(self.iptScriptPath)
                #but we also want to ensure it takes effect now
                cmd = self.iprestore + ' <<< "' + iptables + '"'
                if not self.cmdhelper.executeCommand(cmd):
                    success = False
                    self.detailedresults += "Unable to configure ipv4 firewall\n"
                cmd = self.ip6restore + ' <<< "' + ip6tables + '"'
                if not self.cmdhelper.executeCommand(cmd):
                    success = False
                    self.detailedresults += "Unable to configure ipv6 firewall\n"
            else:
                self.logger.log(LogPriority.DEBUG, "System uses system-config-firewall. Writing system-config-firewall file configuration...")
                systemconfigfirewall = self.getScriptValues("systemconfigfirewall")
                sysconfigiptables = self.getScriptValues("sysconfigiptables")
                sysconfigip6tables = self.getScriptValues("sysconfigip6tables")

                fwpath = '/etc/sysconfig/system-config-firewall'
                iptpath = '/etc/sysconfig/iptables'
                ip6tpath = '/etc/sysconfig/ip6tables'
                #portion to handle the system-config-firewall file
                if not os.path.exists(fwpath):
                    created = False
                    if not createFile(fwpath, self.logger):
                        created = True
                        success = False
                        self.detailedresults += "Unable to create file " + fwpath + "\n"
                    else:
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        event = {"eventtype": "creation",
                                 "filepath": fwpath}
                        self.statechglogger.recordchgevent(myid, event)
                if os.path.exists(fwpath):
                    if not checkPerms(fwpath, [0, 0, 0o600], self.logger):
                        if not created:
                            self.iditerator += 1
                            myid = iterate(self.iditerator, self.rulenumber)
                            if not setPerms(fwpath, [0, 0, 0o600], self.logger, self.statechglogger, myid):
                                success = False
                                self.detailedresults += "Unable to set permissions on " + fwpath + "\n"
                    contents = readFile(fwpath, self.logger)
                    if contents != systemconfigfirewall:
                        tempfile = fwpath + ".tmp"
                        if not writeFile(tempfile, systemconfigfirewall, self.logger):
                            success = False
                            self.detailedresults += "Unable to write contents to " + fwpath + "\n"
                        else:
                            if not created:
                                self.iditerator += 1
                                myid = iterate(self.iditerator, self.rulenumber)
                                event = {"eventtype": "conf",
                                         "filepath": fwpath}
                                self.statechglogger.recordchgevent(myid, event)
                                self.statechglogger.recordfilechange(fwpath, tempfile, myid)
                                os.rename(tempfile, fwpath)
                                os.chown(fwpath, 0, 0)
                                os.chmod(fwpath, 0o600)
                                resetsecon(fwpath)
                #portion to handle the iptables rules file
                if not os.path.exists(iptpath):
                    created = False
                    if not createFile(iptpath, self.logger):
                        created = True
                        success = False
                        self.detailedresults += "Unable to create file " + iptpath + "\n"
                    else:
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        event = {"eventtype": "creation",
                                 "filepath": iptpath}
                        self.statechglogger.recordchgevent(myid, event)
                if os.path.exists(iptpath):
                    if not checkPerms(iptpath, [0, 0, 0o644], self.logger):
                        if not created:
                            self.iditerator += 1
                            myid = iterate(self.iditerator, self.rulenumber)
                            if not setPerms(iptpath, [0, 0, 0o644], self.logger, self.statechglogger, myid):
                                success = False
                                self.detailedresults += "Unable to set permissions on " + iptpath + "\n"
                    contents = readFile(iptpath, self.logger)
                    if contents != sysconfigiptables:
                        tempfile = iptpath + ".tmp"
                        if not writeFile(tempfile, sysconfigiptables, self.logger):
                            success = False
                            self.detailedresults += "Unable to write contents to " + iptpath + "\n"
                        else:
                            if not created:
                                self.iditerator += 1
                                myid = iterate(self.iditerator, self.rulenumber)
                                event = {"eventtype": "conf",
                                         "filepath": iptpath}
                                self.statechglogger.recordchgevent(myid, event)
                                self.statechglogger.recordfilechange(iptpath, tempfile, myid)
                                os.rename(tempfile, iptpath)
                                os.chown(iptpath, 0, 0)
                                os.chmod(iptpath, 0o644)
                                resetsecon(iptpath)
                #portion to handle ip6tables rules file
                if not os.path.exists(ip6tpath):
                    created = False
                    if not createFile(ip6tpath, self.logger):
                        created = True
                        success = False
                        self.detailedresults += "Unable to create file " + ip6tpath + "\n"
                    else:
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        event = {"eventtype": "creation",
                                 "filepath": ip6tpath}
                        self.statechglogger.recordchgevent(myid, event)
                if os.path.exists(ip6tpath):
                    if not checkPerms(ip6tpath, [0, 0, 0o644], self.logger):
                        if not created:
                            self.iditerator += 1
                            myid = iterate(self.iditerator, self.rulenumber)
                            if not setPerms(ip6tpath, [0, 0, 0o644], self.logger, self.statechglogger, myid):
                                success = False
                                self.detailedresults += "Unable to set permissions on " + ip6tpath + "\n"
                    contents = readFile(ip6tpath, self.logger)
                    if contents != sysconfigip6tables:
                        tempfile = ip6tpath + ".tmp"
                        if not writeFile(tempfile, sysconfigip6tables, self.logger):
                            success = False
                            self.detailedresults += "Unable to write contents to " + ip6tpath + "\n"
                        else:
                            if not created:
                                self.iditerator += 1
                                myid = iterate(self.iditerator, self.rulenumber)
                                event = {"eventtype": "conf",
                                         "filepath": ip6tpath}
                                self.statechglogger.recordchgevent(myid, event)
                                self.statechglogger.recordfilechange(ip6tpath, tempfile, myid)
                                os.rename(tempfile, ip6tpath)
                                os.chown(ip6tpath, 0, 0)
                                os.chmod(ip6tpath, 0o644)
                                resetsecon(ip6tpath)
                self.servicehelper.enableService('iptables', serviceTarget=self.serviceTarget)
                self.servicehelper.enableService('ip6tables', serviceTarget=self.serviceTarget)
                # we restart iptables here because it doesn't respond
                # to reload
                cmd = "/sbin/service iptables restart"
                if not self.cmdhelper.executeCommand(cmd):
                    success = False
                    self.detailedresults += "Unable to restart iptables service\n"
                cmd = "/sbin/service ip6tables restart"
                if not self.cmdhelper.executeCommand(cmd):
                    success = False
                    self.detailedresults += "Unable to restart ip6tables service\n"
                # Sleep for a bit to let the restarts occur
                time.sleep(10)
            self.rulesuccess = success
        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.rulesuccess

    def checkFirewalld(self):
        #For Rhel7, centos 7, and fedora mostly
        if os.path.exists('/bin/firewall-cmd'):
            return True

    def checkUFW(self):
        #for Ubuntu systems mostly
        if os.path.exists('/usr/sbin/ufw'):
            return True

    def checkIsOther(self):
        #for debian and opensuse mostly
        if "iptables" not in self.servicehelper.listServices():
            return True

    def checkIptables(self):
        # mostly pertains to RHEL6, Centos6

        if os.path.exists("/usr/sbin/iptables"):
            self.iptables = "/usr/sbin/iptables"
        elif os.path.exists("/sbin/iptables"):
            self.iptables = "/sbin/iptables"

        if os.path.exists("/usr/sbin/ip6tables"):
            self.ip6tables = "/usr/sbin/ip6tables"
        elif os.path.exists("/sbin/ip6tables"):
            self.ip6tables = "/sbin/ip6tables"

        if os.path.exists("/usr/sbin/iptables-restore"):
            self.iprestore = "/usr/sbin/iptables-restore"
        elif os.path.exists("/sbin/iptables-restore"):
            self.iprestore = "/sbin/iptables-restore"

        if os.path.exists("/usr/sbin/ip6tables-restore"):
            self.ip6restore = "/usr/sbin/ip6tables-restore"
        elif os.path.exists("/sbin/ip6tables-restore"):
            self.ip6restore = "/sbin/ip6tables-restore"

    def getScriptValues(self, scriptname):
        if scriptname == "iptscript":
            iptScript = '''fw_custom_after_chain_creation() {
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A INPUT -p icmp -j ACCEPT
-A INPUT -i lo -j ACCEPT
-A INPUT -m state --state NEW -m tcp -p tcp --dport 22 -j ACCEPT
-A INPUT -j REJECT --reject-with icmp-host-prohibited
-A FORWARD -j REJECT --reject-with icmp-host-prohibited
-A INPUT -p ipv6-icmp -j ACCEPT
-A INPUT -m state --state NEW -m udp -p udp --dport 546 -d fe80::/64 -j ACCEPT
-A INPUT -j REJECT --reject-with icmp6-adm-prohibited
-A FORWARD -j REJECT --reject-with icmp6-adm-prohibited
    true
}

fw_custom_before_port_handling() {
    true
}

fw_custom_before_masq() {
    true
}

fw_custom_before_denyall() {
    true
}

fw_custom_after_finished() {
    true
}
'''
            return iptScript
        elif scriptname == "iptables":
            iptables = '''*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A INPUT -p icmp -j ACCEPT
-A INPUT -i lo -j ACCEPT
-A INPUT -m state --state NEW -m tcp -p tcp --dport 22 -j ACCEPT
-A INPUT -j REJECT --reject-with icmp-host-prohibited
-A FORWARD -j REJECT --reject-with icmp-host-prohibited
COMMIT
'''
            return iptables
        elif scriptname == "ip6tables":
            ip6tables = '''*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A INPUT -p ipv6-icmp -j ACCEPT
-A INPUT -i lo -j ACCEPT
-A INPUT -m state --state NEW -m udp -p udp --dport 546 -d fe80::/64 -j ACCEPT
-A INPUT -m state --state NEW -m tcp -p tcp --dport 22 -j ACCEPT
-A INPUT -j REJECT --reject-with icmp6-adm-prohibited
-A FORWARD -j REJECT --reject-with icmp6-adm-prohibited
COMMIT
'''
            return ip6tables
        elif scriptname == "systemconfigurefirewall":
            systemconfigfirewall = '''# Configuration file for system-config-firewall

--enabled
--service=ssh
'''
            return systemconfigfirewall
        elif scriptname == "sysconfigiptables":
            sysconfigiptables = '''# Firewall configuration written by system-config-firewall
# Manual customization of this file is not recommended.
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A INPUT -p icmp -j ACCEPT
-A INPUT -i lo -j ACCEPT
-A INPUT -m state --state NEW -m tcp -p tcp --dport 22 -j ACCEPT
-A INPUT -j REJECT --reject-with icmp-host-prohibited
-A FORWARD -j REJECT --reject-with icmp-host-prohibited
COMMIT
'''
            return sysconfigiptables
        elif scriptname == "sysconfigip6tables":
            sysconfigip6tables = '''# Firewall configuration written by system-config-firewall
# Manual customization of this file is not recommended.
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A INPUT -p ipv6-icmp -j ACCEPT
-A INPUT -i lo -j ACCEPT
-A INPUT -m state --state NEW -m udp -p udp --dport 546 -d fe80::/64 -j ACCEPT
-A INPUT -m state --state NEW -m tcp -p tcp --dport 22 -j ACCEPT
-A INPUT -j REJECT --reject-with icmp6-adm-prohibited
-A FORWARD -j REJECT --reject-with icmp6-adm-prohibited
COMMIT
'''
            return sysconfigip6tables