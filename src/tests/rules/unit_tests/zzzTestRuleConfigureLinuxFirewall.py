#!/usr/bin/env python
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
This is a Unit Test for Rule ConfigureLinuxFirewall

@author: D. Kennel

'''
from __future__ import absolute_import
import unittest
import sys
import os
import re

sys.path.append("../../../..")
from src.tests.lib.RuleTestTemplate import RuleTest
from src.stonix_resources.CommandHelper import CommandHelper
from src.tests.lib.logdispatcher_mock import LogPriority
from src.stonix_resources.ServiceHelper import ServiceHelper
from src.stonix_resources.rules.ConfigureLinuxFirewall import ConfigureLinuxFirewall


class zzzTestRuleConfigureLinuxFirewall(RuleTest):

    def setUp(self):
        RuleTest.setUp(self)
        self.rule = ConfigureLinuxFirewall(self.config,
                                           self.environ,
                                           self.logdispatch,
                                           self.statechglogger)
        self.rulename = self.rule.rulename
        self.rulenumber = self.rule.rulenumber
        self.logger = self.logdispatch
        self.ch = CommandHelper(self.logger)
        self.servicehelper = ServiceHelper(self.environ, self.logger)
        self.checkUndo = True
        self.isfirewalld = False
        self.isufw = False
        if os.path.exists('/bin/firewall-cmd'):
            self.isfirewalld = True
        if os.path.exists('/usr/sbin/ufw'):
            self.isufw = True

        # mostly pertains to RHEL6, Centos6
        self.iptables = "/usr/sbin/iptables"
        if not os.path.exists(self.iptables):
            self.iptables = '/sbin/iptables'
        self.ip6tables = "/usr/sbin/ip6tables"
        if not os.path.exists(self.ip6tables):
            self.ip6tables = '/sbin/ip6tables'
        self.scriptType = ""

    def tearDown(self):
        pass

    def runTest(self):
        self.simpleRuleTest()

    def setConditionsForRule(self):
        '''
        Configure system for the unit test
        @param self: essential if you override this definition
        @return: boolean - If successful True; If failure False
        @author: ekkehard j. koch
        '''
        success = True
        self.detailedresults = ""
        self.iptScriptPath = ""
        scriptExists = ""
        debug = ""
        if self.isfirewalld:
            if self.servicehelper.auditService('firewalld.service'):
                if not self.servicehelper.disableService('firewalld.service'):
                    success = False
        if self.isufw:
            cmdufw = '/usr/sbin/ufw status'
            if not self.cmdhelper.executeCommand(cmdufw):
                debug = "Unable to run ufw status command in unit test\n"
                self.logger.log(LogPriority.DEBUG, debug)
                success = False
            else:
                outputufw = self.cmdhelper.getOutputString()
                if re.search('Status: active', outputufw):
                    ufwcmd = '/usr/sbin/ufw --force disable'
                    if not self.ch.executeCommand(ufwcmd):
                        debug = "Unable to disable firewall for unit test\n"
                        self.logger.log(LogPriority.DEBUG, debug)
                        success = False
        elif os.path.exists('/usr/bin/system-config-firewall') or \
            os.path.exists('/usr/bin/system-config-firewall-tui'):
            print "system-config-firewall commands exist\n"
            fwpath = '/etc/sysconfig/system-config-firewall'
            iptpath = '/etc/sysconfig/iptables'
            ip6tpath = '/etc/sysconfig/ip6tables'
            if os.path.exists(fwpath):
                os.remove(fwpath)
            if os.path.exists(iptpath):
                os.remove(iptpath)
            if os.path.exists(ip6tpath):
                os.remove(ip6tpath)
            if not self.servicehelper.disableService('iptables'):
                print "unable to disable iptables\n"
                success = False
                debug = "Could not disable iptables in unit test\n"
                self.logger.log(LogPriority.DEBUG, debug)
            if not self.servicehelper.disableService('ip6tables'):
                print "unable to disable ip6tables\n"
                success = False
                debug = "Could not disable ip6tables in unit test\n"
                self.logger.log(LogPriority.DEBUG, debug)
            cmd = "/sbin/service iptables stop"
            if not self.ch.executeCommand(cmd):
                success = False
                debug = "Unable to stop iptables in unit test\n"
                print "unable to stop iptables in unit test\n"
                self.logger.log(LogPriority.DEBUG, debug)
            cmd = "/sbin/service ip6tables stop"
            if not self.ch.executeCommand(cmd):
                success = False
                debug = "Unable to stop ip6tables in unit test\n"
                print "unable to stop iop6tables in unit test\n"
                self.logger.log(LogPriority.DEBUG, debug)
        elif os.path.exists(self.iprestore) and \
                os.path.exists(self.ip6restore):
            if os.path.exists(self.iptScriptPath):
                if not os.remove(self.iptScriptPath):
                    debug = "Unable to remove " + self.iptScriptPath + " for setConditionsForRule\n"
                    self.logger.log(LogPriority.DEBUG, debug)
                    success = False
        return success

    def checkReportForRule(self, pCompliance, pRuleSuccess):
        '''
        check on whether report was correct
        @param self: essential if you override this definition
        @param pCompliance: the self.iscompliant value of rule
        @param pRuleSuccess: did report run successfully
        @return: boolean - If successful True; If failure False
        @author: ekkehard j. koch
        '''
        self.logdispatch.log(LogPriority.DEBUG, "pCompliance = " + \
                             str(pCompliance) + ".")
        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " + \
                             str(pRuleSuccess) + ".")
        success = True
        return success

    def checkFixForRule(self, pRuleSuccess):
        '''
        check on whether fix was correct
        @param self: essential if you override this definition
        @param pRuleSuccess: did report run successfully
        @return: boolean - If successful True; If failure False
        @author: ekkehard j. koch
        '''
        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " + \
                             str(pRuleSuccess) + ".")
        success = True
        return success

    def checkUndoForRule(self, pRuleSuccess):
        '''
        check on whether undo was correct
        @param self: essential if you override this definition
        @param pRuleSuccess: did report run successfully
        @return: boolean - If successful True; If failure False
        @author: ekkehard j. koch
        '''
        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " + \
                             str(pRuleSuccess) + ".")
        success = True
        return success

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
if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
