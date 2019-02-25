###############################################################################
#                                                                             #
# Copyright 2015-2019.  Los Alamos National Security, LLC. This material was  #
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
'''
Created on Apr 9, 2013

@author: Derek Walker
@change: 02/14/2014 Ekkehard Implemented self.detailedresults flow
@change: 04/18/2014 Dave Kennel replaced old style CI with new
@change: 06/02/2014 Dave Kennel removed extraneous arg from setperms call on 864
@change: 2014/10/17 Ekkehard OS X Yosemite 10.10 Update
@change: 2015/04/15 Dave Kennel updated for new isApplicable
@change: 2015/10/07 Eric Ball Help text/PEP8 cleanup
@change: 2015/11/16 Eric Ball Moved all file creation from report to fix
@change: 2017/6/29  Brandon Gonzales Added fix in ReportLinux for machines that have
                            deprecated "ifconfig"
@change: 2017/07/07 Ekkehard - make eligible for macOS High Sierra 10.13
@change: 2017/08/28 rsn Fixing to use new help text methods
@change: 2017/10/23 rsn - change to new service helper interface
@change: 2017/11/13 Ekkehard - make eligible for OS X El Capitan 10.11+
@change: 2018/04/10 Dave Kennel - commented out module killing code and set
                        default to False per artf48817
@change: 2018/06/08 Ekkehard - make eligible for macOS Mojave 10.14
@change: 2018/11/15 Breen Malmberg - change to location configurations are being placed
@change: 11/20/2018 Breen Malmberg - rule refactor
'''

from __future__ import absolute_import

import traceback
import os
import re

from ..rule import Rule
from ..stonixutilityfunctions import iterate
from ..logdispatcher import LogPriority
from ..CommandHelper import CommandHelper


class DisableIPV6(Rule):

    def __init__(self, config, environ, logger, statechglogger):
        Rule.__init__(self, config, environ, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 123
        self.rulename = "DisableIPV6"
        self.formatDetailedResults("initialize")
        self.guidance = ["NSA 2.5.3.1"]
        self.applicable = {'type': 'white',
                           'family': ['linux'],
                           'os': {'Mac OS X': ['10.11', 'r', '10.14.10']}}

        datatype = 'bool'
        key = 'DISABLEIPV6'
        instructions = "To disable ipv6 on all interfaces for this system, set the value of DISABLEIPV6 to True."
        default = False
        self.ci = self.initCi(datatype, key, instructions, default)

        self.sethelptext()

    def report(self):
        '''

        @return: self.compliant
        @rtype: bool
        @author: Derek Walker
        @change: Breen Malmberg - 11/20/2018 - rule refactor
        '''

        self.detailedresults = ""
        self.compliant = True
        self.ch = CommandHelper(self.logger)

        try:

            if self.environ.getosfamily() == "linux":
                if not self.reportLinux():
                    self.compliant = False
            elif self.environ.getosfamily() == "darwin":
                if not self.reportMac():
                    self.compliant = False

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

    def reportLinux(self):
        '''
        check for ipv6 functionality on linux systems

        @return: compliant
        @rtype: bool
        @author: Derek Walker
        @change: Breen Malmberg - 11/20/2018 - rule refactor
        '''

        self.detailedresults = ""
        compliant = True
        self.sysctl = ""
        sysctllocs = ["/sbin/sysctl", "/usr/sbin/sysctl"]
        for loc in sysctllocs:
            if os.path.exists(loc):
                self.sysctl = loc
        directives = {"net.ipv6.conf.all.disable_ipv6 = 1": False,
                      "net.ipv6.conf.default.disable_ipv6 = 1": False}
        showoptscmd = self.sysctl + " -a | grep -i net.ipv6.conf"

        try:

            self.ch.executeCommand(showoptscmd)
            retcode = self.ch.getReturnCode()
            if retcode != 0:
                compliant = False
                self.detailedresults += "\nFailed to retrieve sysctl options list"
            else:
                output = self.ch.getOutput()
                for line in output:
                    for d in directives:
                        if re.search(d, line, re.IGNORECASE):
                            directives[d] = True

            for d in directives:
                if not directives[d]:
                    compliant = False
                    self.detailedresults += "\nMissing configuration option: " + d

        except Exception:
            raise

        return compliant

    def reportMac(self):
        '''
        check for ipv6 functionality on all network services for macOS X

        @return: compliant
        @rtype: bool
        @author: Derek Walker
        @change: Breen Malmberg - 11/20/2018 - rule refactor
        '''

        compliant = True
        networksetup = "/usr/sbin/networksetup"
        listnetworkservices = networksetup + " -listallnetworkservices"
        ipv6status = "^IPv6:\s+On"
        getinfo = networksetup + " -getinfo"

        self.logger.log(LogPriority.DEBUG, "Checking network services for ipv6...")

        self.logger.log(LogPriority.DEBUG, "Getting list of network services...")

        try:

            self.ch.executeCommand(listnetworkservices)
            retcode = self.ch.getReturnCode()
            if retcode != 0:
                compliant = False
                self.detailedresults += "\nFailed to get list of network services"
            else:
                networkservices = self.ch.getOutput()
                for ns in networkservices:
                    # ignore non-network service output lines
                    if re.search("denotes that", ns, re.IGNORECASE):
                        continue
                    else:
                        self.logger.log(LogPriority.DEBUG, "Getting information for network service: " + ns)
                        self.ch.executeCommand(getinfo + ' "' + ns + '"')
                        retcode = self.ch.getReturnCode()
                        if retcode != 0:
                            compliant = False
                            self.detailedresults += "\nFailed to get information for network service: " + ns
                        else:
                            nsinfo = self.ch.getOutput()
                            for line in nsinfo:
                                if re.search(ipv6status, line, re.IGNORECASE):
                                    compliant = False
                                    self.detailedresults += "\nNetwork Service " + ns + " has ipv6 enabled"

        except Exception:
            raise

        return compliant

    def fix(self):
        '''
        remove ipv6 functionality from all interfaces

        @return: self.rulesuccess
        @rtype: bool
        @author: Derek Walker
        @change: Breen Malmberg - 11/20/2018 - rule refactor
        '''

        self.detailedresults = ""
        self.rulesuccess = True
        self.iditerator = 0

        try:

            if not self.ci.getcurrvalue():
                return self.rulesuccess

            if self.environ.getosfamily() == "linux":
                if not self.fixLinux():
                    self.rulesuccess = False
            elif self.environ.getosfamily() == "darwin":
                if not self.fixMac():
                    self.rulesuccess = False

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults = traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.rulesuccess

    def fixLinux(self):
        '''
        remove ipv6 functionality for all interfaces on linux

        @return: success
        @rtype: bool
        @author: Derek Walker
        @change: Breen Malmberg - 11/20/2018 - rule refactor
        '''

        directives = ["net.ipv6.conf.all.disable_ipv6",
                      "net.ipv6.conf.default.disable_ipv6"]
        success = True

        self.logger.log(LogPriority.DEBUG, "Disabling ipv6 for all interfaces...")

        try:

            # write configuration changes
            self.logger.log(LogPriority.DEBUG, "Writing configuration changes...")
            for d in directives:
                self.ch.executeCommand(self.sysctl + " -w " + d + "=1")
                retcode = self.ch.getReturnCode()
                if retcode != 0:
                    success = False
                    self.detailedresults += "\nFailed to write configuration change: " + d + "=1"
                # record undo info
                else:
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    event = {'eventtype': 'comm',
                             'command': self.sysctl + " -w " + d + "=0"}
                    self.statechglogger.recordchgevent(myid, event)

            # load new configuration / re-read configuration changes
            self.logger.log(LogPriority.DEBUG, "Loading new configuration changes...")
            self.ch.executeCommand(self.sysctl + " -p")
            retcode = self.ch.getReturnCode()
            if retcode != 0:
                success = False
                self.detailedresults += "\nFailed to load new configuration changes"

        except Exception:
            raise

        return success

    def fixMac(self):
        '''
        remove ipv6 functionality for all network services on macOS X

        @return: success
        @rtype: bool
        @author: Derek Walker
        @change: Breen Malmberg - 11/20/2018 - rule refactor
        '''

        success = True
        networksetup = "/usr/sbin/networksetup"
        disableipv6 = networksetup + " -setv6off"
        listnetworkservices = networksetup + " -listallnetworkservices"

        try:

            self.logger.log(LogPriority.DEBUG, "Getting list of network services for mac os...")

            # first get a list of all network services (interfaces)
            self.ch.executeCommand(listnetworkservices)
            networkservices = self.ch.getOutput()

            # iterate through list, setting ipv6 off for each network service
            for ns in networkservices:
                # ignore non-network service output lines
                if re.search("denotes that", ns, re.IGNORECASE):
                    continue
                else:
                    self.logger.log(LogPriority.DEBUG, "Attempting to disable ipv6 on " + ns)
                    self.ch.executeCommand(disableipv6 + ' "' + ns + '"')
                    retcode = self.ch.getReturnCode()
                    # record undo info
                    if retcode == 0:
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        event = {'eventtype': 'comm',
                                 'command': networksetup + ' -setv6automatic ' + '"' + ns + '"'}
                        self.statechglogger.recordchgevent(myid, event)
                        self.logger.log(LogPriority.DEBUG, "Successfully disabled ipv6 for " + ns)
                    else:
                        success = False
                        self.detailedresults += "\nFailed to turn off ipv6 for: " + ns

        except Exception:
            raise

        return success
