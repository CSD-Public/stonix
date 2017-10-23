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
Created on Apr 5, 2016

@author: dwalker
@change: 2016/07/06 eball Added undo events to fix
@change: 2017/10/23 rsn removed unused service helper
'''
from __future__ import absolute_import
from ..pkghelper import Pkghelper
from ..logdispatcher import LogPriority
from ..stonixutilityfunctions import iterate
from ..rule import Rule
import traceback


class RemoveSoftware(Rule):
    '''
    This class removes any unnecessary software installed on the system
    '''

    def __init__(self, config, environ, logger, statechglogger):
        '''
        Constructor
        '''
        Rule.__init__(self, config, environ, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 91
        self.rulename = "RemoveSoftware"
        self.mandatory = True
        self.sethelptext()
        self.rootrequired = True
        self.guidance = ["NSA 2.3.5.6"]
        self.applicable = {'type': 'white',
                           'family': ['linux', 'freebsd']}
        self.iditerator = 0
        self.ph = Pkghelper(self.logger, self.environ)
        # Configuration item instantiation
        datatype = "bool"
        key = "REMOVESOFTWARE"
        instructions = "To disable this rule set the value of " + \
            "REMOVESOFTWARE TO False."
        default = False
        self.ci = self.initCi(datatype, key, instructions, default)

        datatype = "list"
        key = "PACKAGES"
        instructions = "Enter the package(s) that you wish to remove.  By " + \
            "default we already list packages that we recommend for removal."
        default = ["squid",
                   "telnet-server",
                   "rsh-server",
                   "rsh",
                   "rsh-client",
                   "talk",
                   "talk-server",
                   "talkd",
                   "libpam-ccreds",
                   "pam_ccreds",
                   "tftp-server",
                   "tftp",
                   "tftpd",
                   "udhcpd",
                   "dhcpd",
                   "dhcp",
                   "dhcp-server",
                   "yast2-dhcp-server",
                   "vsftpd",
                   "httpd"
                   "dovecot",
                   "dovecot-imapd",
                   "dovecot-pop3d",
                   "snmpd",
                   "net-snmpd",
                   "net-snmp",
                   "ipsec-tools",
                   "irda-utils",
                   "slapd",
                   "openldap-servers"
                   "openldap2",
                   "bind9",
                   "bind9.i386",
                   "bind",
                   "dnsutils",
                   "bind-utils"]
        self.pkgci = self.initCi(datatype, key, instructions, default)

    def report(self):
        self.detailedresults = ""
        try:
            compliant = True
            if self.pkgci.getcurrvalue():
                for pkg in self.pkgci.getcurrvalue():
                    if self.ph.check(pkg):
                        self.detailedresults += pkg + " is installed\n"
                        compliant = False
            self.compliant = compliant
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
            success = True
            self.detailedresults = ""
            if not self.ci.getcurrvalue():
                return
            elif not self.pkgci.getcurrvalue():
                return
            # Clear out event history so only the latest fix is recorded
            eventlist = self.statechglogger.findrulechanges(self.rulenumber)
            for event in eventlist:
                self.statechglogger.deleteentry(event)
            for pkg in self.pkgci.getcurrvalue():
                if self.ph.check(pkg):
                    try:
                        if self.ph.remove(pkg):
                            self.iditerator += 1
                            myid = iterate(self.iditerator, self.rulenumber)
                            event = {"eventtype": "pkghelper",
                                     "pkgname": pkg,
                                     "startstate": "installed",
                                     "endstate": "removed"}
                            self.statechglogger.recordchgevent(myid, event)
                        else:
                            success = False
                    except Exception:
                        continue
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
