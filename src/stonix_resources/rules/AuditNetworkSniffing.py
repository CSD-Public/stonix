###############################################################################
#                                                                             #
# Copyright 2015-2018.  Los Alamos National Security, LLC. This material was  #
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
Created on Apr 7, 2016

The system should not be acting as a network sniffer, which can capture
all traffic on the network to which it is connected.
Check to see if any network interface on the current system is running
in promiscuous mode or not.

@author: Breen Malmberg
@change: 2017/07/07 ekkehard - make eligible for macOS High Sierra 10.13
@change: 2017/11/13 ekkehard - make eligible for OS X El Capitan 10.11+
'''

from __future__ import absolute_import

import re
import traceback

from ..rule import Rule
from ..logdispatcher import LogPriority
from ..CommandHelper import CommandHelper


class AuditNetworkSniffing(Rule):
    '''
    The system should not be acting as a network sniffer, which can capture
all traffic on the network to which it is connected.
Check to see if any network interface on the current system is running
in promiscuous mode or not.
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
        self.rulenumber = 81
        self.rulename = 'AuditNetworkSniffing'
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.sethelptext()
        self.rootrequired = True
        self.guidance = ['CCE-RHEL7-CCE-TBD 2.5.3']
        self.applicable = {'type': 'white',
                           'family': ['linux'],
                           'os': {'Mac OS X': ['10.11', 'r', '10.13.10']}}

        self.auditonly = True
        # set up class var's and objects
        self.setup()

    def setup(self):
        '''

        @author: Breen Malmberg
        '''

        self.logger.log(LogPriority.DEBUG, "Running setup()...")

        self.initobjs()

        self.localize()

    def initobjs(self):
        '''
        initialize objects to be used by this class

        @author: Breen Malmberg
        '''

        self.logger.log(LogPriority.DEBUG, "Running initobjs()...")

        self.cmdhelper = CommandHelper(self.logger)

    def localize(self):
        '''
        set variables according to which platform this is running on

        @author: Breen Malmberg
        '''

        self.logger.log(LogPriority.DEBUG, "Running localize()...")

        # override this variable value in one or both of the setxxxx() methods if necessary
        self.searchterm = "PROMISC"

        familyname = self.environ.getosfamily()
        if familyname == 'darwin':
            self.logger.log(LogPriority.DEBUG, "System type detected as: Mac OS")
            self.setdarwin()
        elif familyname == 'linux':
            self.logger.log(LogPriority.DEBUG, "System type detected as: Linux")
            self.setlinux()
        else:
            self.logger.log(LogPriority.WARNING, "Could not determine the OS/Platform type!")

    def setdarwin(self):
        '''
        set variables for mac os x

        @author: Breen Malmberg
        '''

        self.logger.log(LogPriority.DEBUG, "Running setdarwin()...")

        # self.searchterm = "PROMISC"
        self.cmdlinetool = "/sbin/ifconfig"
        self.command = [self.cmdlinetool]

        # list index search location; the numbered index location to search in the list for the interface name; see line 181
        self.lisl = 0

    def setlinux(self):
        '''
        set variables for linux

        @author: Breen Malmberg
        '''

        self.logger.log(LogPriority.DEBUG, "Running setlinux()...")

        # self.searchterm = "PROMISC"
        self.cmdlinetool = "/sbin/ip"
        self.command = [self.cmdlinetool, "link"]

        # list index search location; the numbered index location to search in the list for the interface name; see line 181
        self.lisl = 1

    def searchOutput(self, searchlist, searchterm):
        '''
        search given list for searchterm
        init self.interfacenames to empty

        @return: promiscfound
        @rtype: bool
        @param searchlist: list of strings
        @param searchterm: the string to search for in list
        @author: Breen Malmberg
        '''

        self.logger.log(LogPriority.DEBUG, "Running searchOutput()...")

        if not isinstance(searchlist, list):
            self.logger.log(LogPriority.DEBUG, "Parameter searchlist needs to be a list and was not passed as a list.")
            return False

        if not isinstance(searchterm, basestring):
            self.logger.log(LogPriority.DEBUG, "Parameter searchterm needs to be a string and was not passed as a string.")
            return False

        promiscfound = False
        self.interfacenames = []

        for line in searchlist:
            if re.search(searchterm, line):
                promiscfound = True
                self.appendiName(line)

        return promiscfound

    def appendiName(self, searchline):
        '''
        get the names of the interfaces which are running in promiscuous mode
        and append them to self.interfacenames

        @param searchline: the string of text to search, for the interface name
        @author: Breen Malmberg
        '''

        self.logger.log(LogPriority.DEBUG, "Running appendiName()...")

        if not isinstance(self.lisl, int):
            self.logger.log(LogPriority.WARNING, "Variable self.lisl needs to be an integer and has not been defined as one!")
            return

        if not isinstance(searchline, basestring):
            self.logger.log(LogPriority.WARNING, "Parameter searchline needs to be a string and has not be passed as a string!")
            return

        namefound = False

        # the format for the output of searchline should be in one of the following formats:
        # [number]: interfacename: other info
        # interfacename: other info
        # depending on which type of platform the get network interfaces command was run on
        sline = searchline.split(":")

        try:
            self.interfacenames.append(str(sline[int(self.lisl)]).strip())
            namefound = True
        except LookupError:
            namefound = False
        if not namefound:
            self.interfacenames.append("(Could not determine name of network interface)")

    def report(self):
        '''
        detect whether any interface is running in promiscuous mode

        @return: self.compliant
        @retval: bool
        @author: Breen Malmberg
        '''

        self.logger.log(LogPriority.DEBUG, "Starting report()...")

        self.detailedresults = ""
        self.compliant = True

        try:

            self.cmdhelper.executeCommand(self.command)
            outputlines = self.cmdhelper.getOutput()
            retcode = self.cmdhelper.getReturnCode()

            if retcode != 0 and outputlines != []:
                self.detailedresults += "\nThere was a problem getting the list of interfaces on this system."
                self.logger.log(LogPriority.DEBUG, "There was a problem getting the list of interfaces on this system.")
                self.compliant = False
            else:
                promiscfound = self.searchOutput(outputlines, self.searchterm)
                if promiscfound:
                    self.compliant = False
                    for iname in self.interfacenames:
                        self.detailedresults += "\nInterface: " + iname + " is currently running in promiscuous/monitor mode on this system."

            if not self.interfacenames:
                self.detailedresults += "\nNo network interfaces are running in promiscuous/monitor mode on this system."

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.detailedresults += "\n" + traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

    def undo(self):
        '''
        there is no undo for this rule. inform the user.

        @author: Breen Malmberg
        '''

        self.detailedresults += "\nThere is no undo action for this rule because there is no fix and so there is nothing to do."
        self.logger.log(LogPriority.DEBUG, "The undo method was run but there is no undo action for this rule.")
