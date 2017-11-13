'''
###############################################################################
#                                                                             #
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

Created on Oct 18, 2013

TCPWrappers is a library which provides simple access control and standardized
logging for supported applications which accept connections over a network.
Historically, TCP Wrapper was used to support inetd services. Now that inetd is
deprecated (see Section 3.2.1), TCP Wrapper supports only services which were
built to make use of the libwrap library.

@author: bemalmbe
@change: 02/13/2014 ekkehard Implemented self.detailedresults flow
@change: 02/13/2014 ekkehard Implemented isapplicable
@change: 04/18/2014 ekkehard ci updates and ci fix method implementation
@change: 2015/04/17 dkennel updated for new isApplicable
@change: 2015/09/29 eball Fixed potential first-run failure
@change: 2015/10/08 eball Help text cleanup
@change: 2016/06/14 eball Rewrote most code
'''

from __future__ import absolute_import

import os
import re
import traceback

from ..rule import Rule
from ..logdispatcher import LogPriority
from ..stonixutilityfunctions import getOctalPerms, createFile, iterate
from ..localize import ALLOWNETS, HOSTSALLOWDEFAULT, HOSTSDENYDEFAULT


class TCPWrappers(Rule):
    '''
    TCPWrappers is a library which provides simple access control and
    standardized logging for supported applications which accept connections
    over a network. Historically, TCPWrappers was used to support inetd
    services. Now that inetd is deprecated (see Section 3.2.1), TCPWrappers
    supports only services which were built to make use of the libwrap library.

    @author:bemalmbe
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
        self.rulenumber = 13
        self.rulename = 'TCPWrappers'
        self.formatDetailedResults("initialize")
        self.compliant = False
        self.mandatory = True
        self.helptext = '''This rule will configure the /etc/hosts.allow and \
/etc/hosts.deny files for secure operation.

TCPWrappers is a library which provides simple \
access control and standardized logging for supported applications which \
accept connections over a network. Historically, TCPWrappers was used to \
support inetd services. Now that inetd is deprecated, TCPWrappers supports \
only services which were built to make use of the libwrap library.
This rule will ensure a secure configuration for the hosts.allow and \
hosts.deny files.'''
        self.rootrequired = True
        self.guidance = ['CIS', 'NSA(2.5.4)', '4434-7']
        self.applicable = {'type': 'white',
                           'family': ['linux']}

        # init CIs
        self.ci = self.initCi("bool",
                              "TCPWrappers",
                              "To prevent TCP Wrappers from being " +
                              "configured on this system, set the " +
                              "value of TCPWrappers to False.",
                              True)

        datatype = "list"
        key = "ALLOWNETS"
        instructions = "Please enter the subnet(s) you wish to allow to " + \
            "connect via SSH and X-11 forwarding. To allow none, leave blank."
        default = ALLOWNETS

        self.allownetCI = self.initCi(datatype, key, instructions, default)

    def report(self):
        '''
        Check for correct configuration of hosts.allow and hosts.deny

        @return: bool
        @author: bemalmbe
        '''

        # defaults
        self.compliant = True
        allowcfgline = False
        allownetscfg = True
        denycfgline = False
        allow = "/etc/hosts.allow"
        deny = "/etc/hosts.deny"

        try:

            self.detailedresults = ""

            if os.path.exists(allow):
                # check for correct permissions on the hosts.allow file
                perms = getOctalPerms(allow)
                if perms != 644:
                    self.compliant = False
                    self.detailedresults += "Permissions for " + allow + \
                        " are incorrect. Expected 644, got " + str(perms) + \
                        "\n"
                if os.stat(allow).st_uid != 0:
                    self.compliant = False
                    self.detailedresults += "Incorrect owner for " + allow + \
                        "\n"
                if os.stat(allow).st_gid != 0:
                    self.compliant = False
                    self.detailedresults += "Incorrect group for " + allow + \
                        "\n"

                # check for default deny all line in hosts.allow
                f = open(allow, 'r')
                contentlines = f.readlines()
                f.close()

                for line in contentlines:
                    if re.search("^(all|ALL)[\s]*:[\s]*(all|ALL)[\s]*:" +
                                 "[\s]*(DENY|deny)", line, re.M):
                        allowcfgline = True
                        break
                if not allowcfgline:
                    self.detailedresults += "Could not find 'all : " + \
                        "all : deny' line in " + allow + "\n"

                # check for allow sshd cfg lines
                allownets = self.allownetCI.getcurrvalue()
                for allownet in allownets:
                    if allownet:
                        foundsshd = False
                        foundx11 = False
                        for line in contentlines:
                            if re.search("^#", line):
                                continue
                            elif re.search("^sshd: " + allownet + " : ALLOW",
                                           line):
                                foundsshd = True
                            elif re.search("^sshdfwd-X11: " + allownet +
                                           " : ALLOW", line, re.M):
                                foundx11 = True
                        if not foundsshd:
                            self.detailedresults += "Could not find " + \
                                "\"sshd: " + allownet + " : ALLOW\" line in " + \
                                allow + "\n"
                        if not foundx11:
                            self.detailedresults += "Could not find " \
                                "\"sshdfwd-X11: " + allownet + \
                                " : ALLOW\" line in " + allow + "\n"

                        allownetscfg &= foundsshd & foundx11

                for line in contentlines:
                    if re.search("^#", line):
                        continue
                    elif re.search("ALLOW|allow", line):
                        orAllownets = "|".join(allownets)
                        # If allownets consists only of an empty string,
                        # a regex of |127.0.0.1 will match anything. We
                        # therefore need to make sure that if the joined
                        # allownets are an empty string, we get rid of the |.
                        if orAllownets:
                            regex = orAllownets + "|127.0.0.1"
                        else:
                            regex = "127.0.0.1"
                        if not re.search(regex, line):
                            self.compliant = False
                            self.detailedresults += "Uncommented ALLOW lines " + \
                                "for subnets not in ALLOWNETS (and not " + \
                                "127.0.0.1) found in " + allow
                            break

                self.compliant &= allowcfgline & allownetscfg

            else:
                self.compliant = False
                self.detailedresults += "Could not find /etc/hosts.allow\n"

            if os.path.exists(deny):
                # check for correct permissions on the hosts.deny file
                perms = getOctalPerms(deny)
                if perms != 644:
                    self.compliant = False
                    self.detailedresults += "Permissions for hosts.deny " + \
                        "file are incorrect\n"
                if os.stat(deny).st_uid != 0:
                    self.compliant = False
                    self.detailedresults += "Incorrect owner for hosts.deny\n"
                if os.stat(deny).st_gid != 0:
                    self.compliant = False
                    self.detailedresults += "Incorrect group for hosts.deny\n"

                # check for deny banners line in hosts.deny
                f = open(deny, 'r')
                contentlines = f.readlines()
                f.close()

                for line in contentlines:
                    if re.search("^(ALL|all)[\s]*:[\s]*(ALL|all)[\s]*:[\s]*" +
                                 "banners[\s]*/etc/banners[\s]*:[\s]*(deny|DENY)",
                                 line, re.M):
                        denycfgline = True
                        break
                if not denycfgline:
                    self.detailedresults += "Could not find \"ALL:ALL:" + \
                        "banners /etc/banners:deny\" line in hosts.deny\n"
                self.compliant &= denycfgline
            else:
                self.compliant = False
                self.detailedresults += "Could not find /etc/hosts.deny\n"

        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception as err:
            self.rulesuccess = False
            self.detailedresults = self.detailedresults + "\n" + str(err) + \
                " - " + str(traceback.format_exc())
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

    def fix(self):
        '''
        Apply changes to hosts.allow and hosts.deny to correctly configure them

        @author: bemalmbe
        '''

        # defaults
        self.iditer = 0
        self.detailedresults = ""
        allow = "/etc/hosts.allow"
        allowtmp = allow + ".stonixtmp"
        deny = "/etc/hosts.deny"
        denytmp = deny + ".stonixtmp"

        try:
            if self.ci.getcurrvalue():
                allownets = self.allownetCI.getcurrvalue()
                allowCreated = False
                # If file hosts.allow does not exist, create it with the
                # correct config and permissions/ownership
                if not os.path.exists(allow):
                    if createFile(allow, self.logger):
                        self.iditer += 1
                        myid = iterate(self.iditer, self.rulenumber)
                        event = {"eventtype": "creation", "filepath": allow}
                        self.statechglogger.recordchgevent(myid, event)
                        allowCreated = True
                    else:
                        self.rulesuccess = False
                        self.detailedresults += "Failed to create file: " + \
                            allow + "\n"
                content = HOSTSALLOWDEFAULT
                if len(allownets) == 1:
                    content = re.sub('{allownet}', allownets[0], content)
                    if allownets[0] == "":
                        content = re.sub('sshd:', '#sshd:', content)
                        content = re.sub('sshdfwd-X11:', '#sshdfwd-X11:',
                                         content)
                else:
                    contentlines = content.splitlines(True)
                    for ind, line in enumerate(contentlines):
                        search = re.search(r"^(.*)\{allownet\}(.*)$", line,
                                           re.S)
                        if search:
                            del contentlines[ind]
                            for allownet in allownets:
                                allowline = search.group(1) + allownet + \
                                    search.group(2)
                                contentlines.insert(ind, allowline)
                    content = "".join(contentlines)

                f = open(allowtmp, 'w')
                f.write(content)
                f.close()

                if not allowCreated:
                    self.iditer += 1
                    myid = iterate(self.iditer, self.rulenumber)
                    event = {"eventtype": "conf", "filepath": allow}
                    self.statechglogger.recordchgevent(myid, event)
                    self.statechglogger.recordfilechange(allow, allowtmp, myid)

                os.rename(allowtmp, allow)
                os.chmod(allow, 0644)
                os.chown(allow, 0, 0)

                # If file hosts.deny does not exist, create it with the correct
                # config
                content = HOSTSDENYDEFAULT
                denyCreated = False
                if not os.path.exists(deny):
                    if createFile(deny, self.logger):
                        self.iditer += 1
                        myid = iterate(self.iditer, self.rulenumber)
                        event = {"eventtype": "creation", "filepath": deny}
                        self.statechglogger.recordchgevent(myid, event)
                        denyCreated = True
                    else:
                        self.rulesuccess = False
                        self.detailedresults += "Failed to create file: " + \
                            deny + "\n"

                f = open(denytmp, 'w')
                f.write(content)
                f.close()

                if not denyCreated:
                    self.iditer += 1
                    myid = iterate(self.iditer, self.rulenumber)
                    event = {"eventtype": "conf", "filepath": deny}
                    self.statechglogger.recordchgevent(myid, event)
                    self.statechglogger.recordfilechange(deny, denytmp, myid)

                os.rename(denytmp, deny)
                os.chmod(deny, 0644)
                os.chown(deny, 0, 0)
            else:
                self.detailedresults = str(self.ci.getkey()) + \
                    " was disabled. No action was taken."

        except (OSError, IOError):
            self.detailedresults = self.detailedresults + \
                str(traceback.format_exc())
            self.logger.log(LogPriority.DEBUG, self.detailedresults)
        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception as err:
            self.rulesuccess = False
            self.detailedresults = self.detailedresults + "\n" + str(err) + \
                " - " + str(traceback.format_exc())
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.rulesuccess
