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
'''

from __future__ import absolute_import

import os
import re
import traceback

from ..rule import Rule
from ..logdispatcher import LogPriority
from ..stonixutilityfunctions import getOctalPerms
from ..localize import ALLOWNET, HOSTSALLOWDEFAULT, HOSTSDENYDEFAULT, LEGACYALLOWNET


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
        self.helptext = '''TCPWrappers is a library which provides simple \
access control and standardized logging for supported applications which \
accept connections over a network. Historically, TCPWrappers was used to \
support inetd services. Now that inetd is deprecated, TCPWrappers supports \
only services which were built to make use of the libwrap library.
This rule will ensure a secure configuration for the hosts.allow and \
hosts.deny files.'''
        self.rootrequired = True
        self.guidance = ['CIS', 'NSA(2.5.4)', '4434-7']
        self.isApplicableWhiteList = []
        self.isApplicableBlackList = ["darwin"]
        self.applicable = {'type': 'black', 'family': ['darwin']}

        # init CIs
        self.ci = self.initCi("bool",
                              "TCPWrappers",
                              "To prevent TCP Wrappers from being " +
                              "configured on this system, set the " +
                              "value of TCPWrappers to False.",
                              True)

        datatype = "string"
        key = "Allow Subnet"
        instructions = "Enter the subnet you wish to allow services access to on the network. To allow none, leave blank."
        default = ALLOWNET

        if os.path.exists('/etc/redhat-release'):
            osver = self.environ.getosver()
            if re.search('6\.[0-9]', osver):
                print "\n\nLEGACYALLOWNET SET\n\n"
                default = LEGACYALLOWNET

        self.allownetCI = self.initCi(datatype, key, instructions, default)

    def report(self):
        '''
        Check for correct configuration of hosts.allow and hosts.deny

        @return: bool
        @author: bemalmbe
        '''

        # defaults
        configured = True
        foundallowline = False
        founddenyline = False
        self.allowcfgline = True
        self.denycfgline = True
        self.allowperms = True
        self.denyperms = True
        allowsshd = False
        allowsshdfwdx = False

        try:

            self.detailedresults = ""

            if os.path.exists('/etc/hosts.allow'):

                # check for correct permissions on the hosts.allow file
                perms = getOctalPerms('/etc/hosts.allow')
                if perms != 644:
                    self.allowperms = False
                    self.detailedresults += "Permissions for hosts.allow " + \
                        "file are incorrect\n"
                if os.stat('/etc/hosts.allow').st_uid != 0:
                    self.allowperms = False
                    self.detailedresults += "Incorrect owner for hosts.allow\n"
                if os.stat('/etc/hosts.allow').st_gid != 0:
                    self.allowperms = False
                    self.detailedresults += "Incorrect group for hosts.allow\n"

                # check for default deny all line in hosts.allow
                f = open('/etc/hosts.allow', 'r')
                contentlines = f.readlines()
                f.close()

                for line in contentlines:
                    if re.search("^(all|ALL)[\s]*:[\s]*(all|ALL)[\s]*:[\s]*(DENY|deny)",
                                 line):
                        foundallowline = True

                if not foundallowline:
                    self.allowcfgline = False
                    self.detailedresults += "Could not find 'all : all : " + \
                        "deny' line in hosts.allow\n"

                # check for allow sshd cfg lines
                if str(self.allownetCI.getcurrvalue()).strip() != "":

                    for line in contentlines:
                        if re.search("^sshd: " +
                                     str(self.allownetCI.getcurrvalue()) +
                                     " : ALLOW", line):
                            allowsshd = True

                    for line in contentlines:
                        if re.search("^sshdfwd-X11: " +
                                     str(self.allownetCI.getcurrvalue()) +
                                     " : ALLOW", line):
                            allowsshdfwdx = True

                    if not allowsshd:
                        self.allowcfgline = False
                        self.detailedresults += "Could not find 'sshd:' " + \
                            "line for allowhost in hosts.allow\n"

                    if not allowsshdfwdx:
                        self.allowcfgline = False
                        self.detailedresults += "Could not find 'sshdfwd-X11:'" + \
                            " line for allowhost in hosts.allow\n"

            else:

                configured = False
                self.detailedresults += "Could not find /etc/hosts.allow\n"

            if os.path.exists('/etc/hosts.deny'):

                # check for correct permissions on the hosts.deny file
                perms = getOctalPerms('/etc/hosts.deny')
                if perms != 644:
                    self.denyperms = False
                    self.detailedresults += "Permissions for hosts.deny " + \
                        "file are incorrect\n"
                if os.stat('/etc/hosts.deny').st_uid != 0:
                    self.denyperms = False
                    self.detailedresults += "Incorrect owner for hosts.deny\n"
                if os.stat('/etc/hosts.deny').st_gid != 0:
                    self.denyperms = False
                    self.detailedresults += "Incorrect group for hosts.deny\n"

                # check for deny banners line in hosts.deny
                f = open('/etc/hosts.deny', 'r')
                contentlines = f.readlines()
                f.close()

                for line in contentlines:
                    if re.search("^(ALL|all)[\s]*:[\s]*(ALL|all)[\s]*:[\s]*banners[\s]*/etc/banners[\s]*:[\s]*(deny|DENY)",
                                 line):
                        founddenyline = True

                if not founddenyline:
                    self.denycfgline = False
                    self.detailedresults += "Could not find 'all : all : " + \
                        "deny' line in hosts.allow\n"

            else:

                configured = False
                self.detailedresults += "Could not find /etc/hosts.deny\n"

            if self.allowperms and self.allowcfgline and self.denyperms and \
               self.denycfgline and configured:
                self.compliant = True
            else:
                self.compliant = False
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

        try:

            if self.ci.getcurrvalue():

                # If file hosts.allow does not exist, create it with the
                # correct config and permissions/ownership
                if not os.path.exists('/etc/hosts.allow'):

                    f = open('/etc/hosts.allow', 'w')
                    content = HOSTSALLOWDEFAULT
                    content = re.sub('{allownet}',
                                     str(self.allownetCI.getcurrvalue()),
                                     content)
                    if str(self.allownetCI.getcurrvalue()).strip() == "":
                        content = re.sub('sshd:', '#sshd:', content)
                        content = re.sub('sshdfwd-X11:', '#sshdfwd-X11:',
                                         content)

                    f.write(content)
                    f.close()

                    os.chmod('/etc/hosts.allow', 0644)
                    os.chown('/etc/hosts.allow', 0, 0)

                else:

                    # If /etc/hosts.allow file does exist, make sure it has the
                    # correct configuration and permissions/ownership
                    if not self.allowcfgline:

                        content = HOSTSALLOWDEFAULT
                        content = re.sub('{allownet}',
                                         str(self.allownetCI.getcurrvalue()),
                                         content)
                        if str(self.allownetCI.getcurrvalue()).strip() == "":
                            content = re.sub('sshd:', '#sshd:', content)
                            content = re.sub('sshdfwd-X11:', '#sshdfwd-X11:',
                                             content)

                        tf = open('/etc/hosts.allow.stonixtmp', 'w')
                        tf.write(content)
                        tf.close()

                        event = {'eventtype': 'conf',
                                 'filename': '/etc/hosts.allow'}

                        self.iditer += 1
                        myid = '001300' + str(self.iditer)

                        self.statechglogger.recordchgevent(myid, event)
                        self.statechglogger.recordfilechange('/etc/hosts.allow',
                                                             '/etc/hosts.allow.stonixtmp',
                                                             myid)

                        os.rename('/etc/hosts.allow.stonixtmp',
                                  '/etc/hosts.allow')

                        os.chmod('/etc/hosts.allow', 0644)
                        os.chown('/etc/hosts.allow', 0, 0)

                # If file hosts.deny does not exist, create it with the correct
                # config
                if not os.path.exists('/etc/hosts.deny'):

                    f = open('/etc/hosts.deny', 'w')
                    content = HOSTSDENYDEFAULT
                    f.write(content)
                    f.close()

                    os.chmod('/etc/hosts.deny', 0644)
                    os.chown('/etc/hosts.deny', 0, 0)

                else:

                    # If /etc/hosts.deny file does exist, make sure it has the
                    # default deny banners config line and the correct
                    # permissions on it
                    if not self.denycfgline:

                        content = HOSTSDENYDEFAULT
                        tf = open('/etc/hosts.deny.stonixtmp', 'w')
                        tf.write(content)
                        tf.close()

                        event = {'eventtype': 'conf',
                                 'filename': '/etc/hosts.deny'}

                        self.iditer += 1
                        myid = '001300' + str(self.iditer)

                        self.statechglogger.recordchgevent(myid, event)
                        self.statechglogger.recordfilechange('/etc/hosts.deny',
                                                             '/etc/hosts.deny.stonixtmp',
                                                             myid)
                        os.rename('/etc/hosts.deny.stonixtmp',
                                  '/etc/hosts.deny')

                        os.chmod('/etc/hosts.deny', 0644)
                        os.chown('/etc/hosts.deny', 0, 0)
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
