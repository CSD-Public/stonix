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
@change: 2019/06/13 Breen Malmberg - updated documentation to reST format;
        added missing documentation
@change: 2019/08/07 ekkehard - enable for macOS Catalina 10.15 only
"""



import re
import traceback
import os

from ..rule import Rule
from ..logdispatcher import LogPriority
from ..CommandHelper import CommandHelper


class AuditNetworkSniffing(Rule):
    """The system should not be acting as a network sniffer, which can capture
    all traffic on the network to which it is connected.
    Check to see if any network interface on the current system is running
    in promiscuous mode or not.


    """
    def __init__(self, config, environ, logger, statechglogger):
        """
        private method to initialize the module

        :param config: configuration object instance
        :param environ: environment object instance
        :param logger: logdispatcher object instance
        :param statechglogger: statechglogger object instance
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
                           'os': {'Mac OS X': ['10.15', 'r', '10.15.10']}}

        self.auditonly = True

        self.initobjs()
        self.localize()

    def initobjs(self):
        """initialize objects to be used by this class

        """

        self.ch = CommandHelper(self.logger)

    def localize(self):
        """set variables according to which platform this is running on

        """

        self.osname = self.environ.getosname()
        tools = ["/usr/sbin/ifconfig", "/usr/sbin/ip", "/sbin/ifconfig", "/sbin/ip"]
        commands = {"/usr/sbin/ifconfig": "/usr/sbin/ifconfig",
                    "/usr/sbin/ip": "/usr/sbin/ip -4 a",
                    "/sbin/ifconfig": "/sbin/ifconfig",
                    "/sbin/ip": "/sbin/ip -4 a"}
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
        """detect whether any network interface is running in 'promiscuous' mode

        :returns: self.compliant - boolean; True if compliant, False if not compliant

        """

        self.detailedresults = ""
        self.compliant = True

        try:

            if not self.command:
                self.compliant = False
                self.logger.log(LogPriority.DEBUG, "Unable to identify the correct command line network utility location on this system")
                self.formatDetailedResults("report", self.compliant, self.detailedresults)
                return self.compliant

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
            self.compliant = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant, self.detailedresults)
        self.logger.log(LogPriority.INFO, self.detailedresults)

        return self.compliant
