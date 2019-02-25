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
Created on Apr 5, 2016

@author: Derek Walker
@change: 2016/07/06 eball Added undo events to fix
@change: 2017/10/23 rsn removed unused service helper
@change: 2018/07/31 Breen Malmberg - added doc strings for report and fix
        methods; added redhat insights software to default list of software
        to remove
'''

from __future__ import absolute_import

import traceback

from ..pkghelper import Pkghelper
from ..logdispatcher import LogPriority
from ..stonixutilityfunctions import iterate
from ..rule import Rule


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
        self.formatDetailedResults("initialize")
        self.sethelptext()
        self.rootrequired = True
        self.guidance = ["NSA 2.3.5.6"]
        self.applicable = {'type': 'white',
                           'family': ['linux', 'freebsd']}
        self.iditerator = 0

        # Configuration item instantiation
        datatype1 = "bool"
        key1 = "REMOVESOFTWARE"
        instructions1 = "To disable this rule set the value of REMOVESOFTWARE TO False."
        default1 = False
        self.ci = self.initCi(datatype1, key1, instructions1, default1)

        datatype2 = "list"
        key2 = "PACKAGES"
        instructions2 = "Enter the package(s) that you wish to remove.  By " + \
            "default we already list packages that we recommend for removal."
        default2 = ["squid",
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
                   "httpd",
                   "dovecot",
                   "dovecot-imapd",
                   "dovecot-pop3d",
                   "snmpd",
                   "net-snmpd",
                   "net-snmp",
                   "ipsec-tools",
                   "irda-utils",
                   "slapd",
                   "openldap-servers",
                   "openldap2",
                   "bind9",
                   "bind9.i386",
                   "bind",
                   "dnsutils",
                   "bind-utils",
                   "redhat-access-insights",
                   "insights-client"]

        self.pkgci = self.initCi(datatype2, key2, instructions2, default2)

    def report(self):
        '''
        report on any unnecessary software that is currently
        installed
        return True if none installed
        return False if any installed

        @return: self.compliant
        @rtype: bool
        @author: Derek Walker
        '''

        self.detailedresults = ""
        self.compliant = True
        self.ph = Pkghelper(self.logger, self.environ)

        try:

            if self.pkgci.getcurrvalue():
                for pkg in self.pkgci.getcurrvalue():
                    if self.ph.check(pkg):
                        self.detailedresults += pkg + " is installed\n"
                        self.compliant = False

        except Exception:
            self.compliant = False
            self.detailedresults += traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)

        return self.compliant

    def fix(self):
        '''
        remove all unnecessary software

        @return: self.rulesuccess
        @rtype: bool
        @author: Derek Walker
        '''

        self.rulesuccess = True
        self.detailedresults = ""
        self.iditerator = 0

        try:

            if not self.ci.getcurrvalue():
                self.formatDetailedResults("fix", self.rulesuccess, self.detailedresults)
                return self.rulesuccess
            elif not self.pkgci.getcurrvalue():
                self.formatDetailedResults("fix", self.rulesuccess, self.detailedresults)
                return self.rulesuccess

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
                            self.rulesuccess = False
                    except Exception:
                        continue

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)

        return self.rulesuccess
