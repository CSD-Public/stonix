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
        self.iptScriptPath = ""
        self.iptables, self.ip6tables, self.iprestore, self.ip6restore = "", "", "", ""
        self.checkIptables()
        self.iditerator = 0

    def report(self):
        """
        Report on whether the firewall meets baseline expectations.

        @return: bool
        @author: D.Kennel
        @change: dwalker - updating rule to check for every possible firewall
            implementation and configure it rather than mutually exclusively
            checking based on system.
        """
        try:
            compliant = True
            iptablesrunning = False
            ip6tablesrunning = False
            catchall = False
            catchall6 = False
            self.detailedresults = ""
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
            else:
                if self.servicehelper.auditService('iptables'):
                    iptablesrunning = True
                if self.servicehelper.auditService('ip6tables'):
                    ip6tablesrunning = True

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
                        if not catchall:
                            compliant = False
                            self.detailedresults += "Incorrect IPV4 firewall INPUT rule\n"
                            self.logger.log(LogPriority.DEBUG, self.detailedresults)

                if self.ip6tables:
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
                        if not catchall6:
                            self.detailedresults += "Incorrect IPV6 firewall INPUT rule\n"
                            self.logger.log(LogPriority.DEBUG, self.detailedresults)

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
                else:
                    scriptExists = True

                if not catchall:
                    compliant = False
                    self.detailedresults += 'This system appears to use ' + \
                        'iptables but does not contain the expected rules\n'
                    self.logger.log(LogPriority.DEBUG,
                                    ['ConfigureLinuxFirewall.report',
                                     "Missing v4 deny all."])
                if not catchall6:
                    compliant = False
                    self.detailedresults += 'This system appears to use ' + \
                        'ip6tables but does not contain the expected rules\n'
                    self.logger.log(LogPriority.DEBUG,
                                    ['ConfigureLinuxFirewall.report',
                                     "Missing v6 deny all."])
                if not scriptExists:
                    compliant = False
                    self.detailedresults += 'This system appears to use ' + \
                        'iptables but the startup script is not present\n'
                    self.logger.log(LogPriority.DEBUG,
                                    ['ConfigureLinuxFirewall.report',
                                     "Missing startup script"])
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
            # delete past state change records from previous fix
            eventlist = self.statechglogger.findrulechanges(self.rulenumber)
            for event in eventlist:
                self.statechglogger.deleteentry(event)
            #firewall-cmd portion
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

            #ufw command portion
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
            else:
                #following portion is mainly for debian and opensuse systems only
                if self.iptScriptPath:
                    if os.path.exists("/etc/network/if-pre-up.d"):
                        self.iptScriptPath = "/etc/network/if-pre-up.d/iptables"
                        self.scriptType = "debian"
                    elif os.path.exists("/etc/sysconfig/scripts"):
                        self.iptScriptPath = "/etc/sysconfig/scripts/SuSEfirewall2-custom"
                        self.scriptType = "suse"
                    #this script will ensure that iptables gets configured
                    #each time the network restarts
                    iptables = self.getScriptValues("iptables")
                    ip6tables = self.getScriptValues("ipt6tables")
                    iptScript = ""
                    if self.scriptType == "debian":
                        if self.iprestore and self.ip6restore:
                            iptScript = '#!/bin/bash\n' + self.iprestore + \
                                        ' <<< "' + iptables + '"\n' + self.ip6restore + \
                                        ' <<< "' + ip6tables + '"'
                    else:
                        iptScript = self.getScriptValues("iptscript")
                    if iptScript:
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
                    else:
                        success = False
                        self.detailedresults += "There is no iptables startup script\n"
                        self.logger.log(LogPriority.DEBUG, self.detailedresults)
                    if self.iprestore:
                        #but we also want to ensure it takes effect now
                        cmd = self.iprestore + ' <<< "' + iptables + '"'
                        if not self.cmdhelper.executeCommand(cmd):
                            success = False
                            self.detailedresults += "Unable to configure ipv4 firewall\n"
                    if self.ip6restore:
                        cmd = self.ip6restore + ' <<< "' + ip6tables + '"'
                        if not self.cmdhelper.executeCommand(cmd):
                            success = False
                            self.detailedresults += "Unable to configure ipv6 firewall\n"

                #this portion mostly applies to RHEL6 and Centos6
                if os.path.exists('/usr/bin/system-config-firewall') or \
                        os.path.exists('/usr/bin/system-config-firewall-tui'):
                    systemconfigfirewall = self.getScriptValues("systemconfigfirewall")
                    sysconfigiptables = self.getScriptValues("sysconfigiptables")
                    sysconfigip6tables = self.getScriptValues("sysconfigip6tables")

                    fwpath = '/etc/sysconfig/system-config-firewall'
                    iptpath = '/etc/sysconfig/iptables'
                    ip6tpath = '/etc/sysconfig/ip6tables'
                    #portion to handle the system-config-firewall file
                    created = False
                    if not os.path.exists(fwpath):
                        print "fwpath doesn't exist\n"
                        if not createFile(fwpath, self.logger):
                            success = False
                            self.detailedresults += "Unable to create file " + fwpath + "\n"
                        else:
                            created = True
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
                            print "contents don't equal systemconfigurefirewall contents\n"
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
                    created = False
                    #portion to handle the iptables rules file
                    if not os.path.exists(iptpath):
                        if not createFile(iptpath, self.logger):
                            success = False
                            self.detailedresults += "Unable to create file " + iptpath + "\n"
                        else:
                            created = True
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
                    created = False
                    #portion to handle ip6tables rules file
                    if not os.path.exists(ip6tpath):
                        if not createFile(ip6tpath, self.logger):
                            success = False
                            self.detailedresults += "Unable to create file " + ip6tpath + "\n"
                        else:
                            created = True
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
                    # check if iptables is enabled to run at start
                    if not self.servicehelper.auditService('iptables'):
                        # enable service to run at start if not
                        if not self.servicehelper.enableService('iptables'):
                            self.detailedresults += "Unable to enable iptables service\n"
                            debug = "Unable to enable iptables service\n"
                            self.logger.log(LogPriority.DEBUG, debug)
                            success = False
                        else:
                            # record event if successful
                            self.iditerator += 1
                            myid = iterate(self.iditerator, self.rulenumber)
                            cmd = self.servicehelper.getDisableCommand('iptables')
                            event = {"eventtype": "commandstring",
                                     "command": cmd}
                            self.statechglogger.recordchgevent(myid, event)

                    self.servicehelper.stopService('iptables')
                    # start iptables if not
                    if not self.servicehelper.startService('iptables'):
                        self.detailedresults += "Unable to start iptables service\n"
                        debug = "Unable to start iptables service\n"
                        self.logger.log(LogPriority.DEBUG, debug)
                        success = False

                    # check if ip6tables is enabled to run at start
                    if not self.servicehelper.auditService('ip6tables'):
                        # enable service to run at start if not
                        if not self.servicehelper.enableService('ip6tables'):
                            self.detailedresults += "Unable to enable ip6tables service\n"
                            debug = "Unable to enable ip6tables service\n"
                            self.logger.log(LogPriority.DEBUG, debug)
                            success = False
                        else:
                            # record event if successful
                            self.iditerator += 1
                            myid = iterate(self.iditerator, self.rulenumber)
                            cmd = self.servicehelper.getDisableCommand('ip6tables')
                            event = {"eventtype": "commandstring",
                                     "command": cmd}
                            self.statechglogger.recordchgevent(myid, event)

                    self.servicehelper.stopService('ip6tables')
                    # start ip6tables if not
                    if not self.servicehelper.startService('ip6tables'):
                        self.detailedresults += "Unable to start ip6tables service\n"
                        debug = "Unable to start ip6tables service\n"
                        self.logger.log(LogPriority.DEBUG, debug)
                        success = False

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
        elif scriptname == "systemconfigfirewall":
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