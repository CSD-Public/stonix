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
"""
Created on Apr 7, 2016

The system should not be acting as a network sniffer, which can capture
all traffic on the network to which it is connected.
Check to see if any network interface on the current system is running
in promiscuous mode or not.

@author: Breen Malmberg
@change: 2017/07/07 Ekkehard - make eligible for macOS High Sierra 10.13
@change: 2017/11/13 Ekkehard - make eligible for OS X El Capitan 10.11+
@change: 2018/06/08 Ekkehard - make eligible for macOS Mojave 10.14
"""

from __future__ import absolute_import

import re
import traceback
import os

from ..rule import Rule
from ..logdispatcher import LogPriority
from ..CommandHelper import CommandHelper


class AuditNetworkSniffing(Rule):
    """
    The system should not be acting as a network sniffer, which can capture
    all traffic on the network to which it is connected.
    Check to see if any network interface on the current system is running
    in promiscuous mode or not.
    """
    def __init__(self, config, environ, logger, statechglogger):
        """
        Constructor
        """
        Rule.__init__(self, config, environ, logger, statechglogger)
        self.config = config
        self.environ = environ
        self.logger = logger
        self.statechglogger = statechglogger
        self.rulenumber = 81
        self.rulename = 'AuditNetworkSniffing'
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.sethelptext()
        self.rootrequired = True
        self.guidance = ['CCE-RHEL7-CCE-TBD 2.5.3']
        self.applicable = {'type': 'white',
                           'family': ['linux'],
                           'os': {'Mac OS X': ['10.11', 'r', '10.14.10']}}

        self.auditonly = True

        self.initobjs()
        self.localize()

    def initobjs(self):
        """
        initialize objects to be used by this class

        @author: Breen Malmberg
        """

        self.ch = CommandHelper(self.logger)

    def localize(self):
        """
        set variables according to which platform this is running on

        @author: Breen Malmberg
        """

        self.osname = self.environ.getosname()
        tools = ["/usr/sbin/ifconfig", "/usr/sbin/ip"]
        commands = {"/usr/sbin/ifconfig": "/usr/sbin/ifconfig",
                    "/usr/sbin/ip": "/usr/sbin/ip -4 a"}
        self.tool = ""
        for t in tools:
            if os.path.exists(t):
                self.tool = t
                break
        try:
            self.command = commands[self.tool]
        except:
            self.command = ""

        if self.osname == "Mac OS":
            # on mac we only want to find interfaces in promiscuous mode if they are active
            self.searchterm = "flags=.*<UP.*PROMISC"
        else:
            self.searchterm = "<.*PROMISC"

    def report(self):
        """
        detect whether any interface is running in promiscuous mode

        @return: self.compliant
        @rtype: bool
        @author: Breen Malmberg
        """

        self.detailedresults = ""
        self.compliant = True

        try:

            promisc_interfaces = []

            self.ch.executeCommand(self.command)
            output = self.ch.getOutput()
            for line in output:
                if re.search(self.searchterm, line):
                    sline = line.split()
                    if re.search("^[0-9].\:", sline[0]):
                        promisc_interfaces.append(str(sline[1][:-1]))
                    else:
                        promisc_interfaces.append(str(sline[0][:-1]))
            if promisc_interfaces:
                self.compliant = False
                self.detailedresults += "\nThe following interfaces are running in PROMISCUOUS mode:\n- " + "\n- ".join(promisc_interfaces)
            else:
                self.detailedresults += "\nNo interfaces were found to be running in promiscuous mode"

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.detailedresults += "\n" + traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)

        return self.compliant
