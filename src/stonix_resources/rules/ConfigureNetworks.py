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
This method runs all the report methods for RuleKVEditors in defined in the
dictionary

@author: ekkehard j. koch
@change: 2014/03/10 ekkehard Original Implementation
@change: 2014/10/17 ekkehard OS X Yosemite 10.10 Update
@change: 2014/10/20 ekkehard Artifact artf34318 : ConfigureNetworks(122)
@change: 2015/04/14 dkennel updated for new isApplicable
@change: 2017/07/07 ekkehard - make eligible for macOS High Sierra 10.13
@change: 2017/08/28 ekkehard - Added self.sethelptext()
'''
from __future__ import absolute_import
import traceback
import re

from ..localize import DNS
from ..localize import PROXY
from ..localize import PROXYCONFIGURATIONFILE
from ..localize import PROXYDOMAIN
from ..ruleKVEditor import RuleKVEditor
from ..CommandHelper import CommandHelper
from ..ServiceHelper import ServiceHelper
from ..logdispatcher import LogPriority
from ..networksetup import networksetup
from ..stonixutilityfunctions import iterate


class ConfigureNetworks(RuleKVEditor):
    '''

    @author: ekkehard j. koch
    @change: Breen Malmberg - 12/20/2016 - (see method doc strings)
    '''

###############################################################################

    def __init__(self, config, environ, logdispatcher, statechglogger):
        RuleKVEditor.__init__(self, config, environ, logdispatcher,
                              statechglogger)
        self.rulenumber = 122
        self.rulename = 'ConfigureNetworks'
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.sethelptext()
        self.rootrequired = True
        self.guidance = []
        self.iditerator = 0
        self.statechglogger = statechglogger
        self.applicable = {'type': 'white',
                           'os': {'Mac OS X': ['10.9', 'r', '10.13.10']}}

        ## this section added to prevent code, which relies on constants in localize.py,
        # from running if those constants are not defined or are set to 'None'
#         if DNS == None:
#             self.logdispatch.log(LogPriority.DEBUG, "Please ensure that the following constants, in localize.py, are correctly defined and are not None: DNS, PROXY, PROXYCONFIGURATIONFILE, PROXYDOMAIN. ConfigureNetworks will not function without these!")
#             exit
#         if PROXY == None:
#             self.logdispatch.log(LogPriority.DEBUG, "Please ensure that the following constants, in localize.py, are correctly defined and are not None: DNS, PROXY, PROXYCONFIGURATIONFILE, PROXYDOMAIN. ConfigureNetworks will not function without these!")
#             exit
#         if PROXYCONFIGURATIONFILE == None:
#             self.logdispatch.log(LogPriority.DEBUG, "Please ensure that the following constants, in localize.py, are correctly defined and are not None: DNS, PROXY, PROXYCONFIGURATIONFILE, PROXYDOMAIN. ConfigureNetworks will not function without these!")
#             exit
#         if PROXYDOMAIN == None:
#             self.logdispatch.log(LogPriority.DEBUG, "Please ensure that the following constants, in localize.py, are correctly defined and are not None: DNS, PROXY, PROXYCONFIGURATIONFILE, PROXYDOMAIN. ConfigureNetworks will not function without these!")
#             exit
        # this section added to prevent code, which relies on constants in localize.py,
        ## from running if those constants are not defined or are set to 'None'

        self.nsobject = None

        self.nsobject = networksetup(self.logdispatch)

        if self.nsobject != None:
            self.ch = CommandHelper(self.logdispatch)
            self.sh = ServiceHelper(self.environ, self.logdispatch)
            self.addKVEditor("DisableBluetoothUserInterface",
                             "defaults",
                             "/Library/Preferences/com.apple.Bluetooth",
                             "",
                             {"ControllerPowerState": ["0", "-int 0"]},
                             "present",
                             "",
                             "Disable Bluetooth User Interface.",
                             None,
                             False,
                             {})
            self.addKVEditor("DisableBluetoothInternetSharing",
                             "defaults",
                             "/Library/Preferences/com.apple.Bluetooth",
                             "",
                             {"PANServices": ["0", "-int 0"]},
                             "present",
                             "",
                             "Disable Bluetooth Internet Sharing.",
                             None,
                             False,
                             {})

    def report(self):
        '''
        determine the compliance status of ConfigureNetworks
        on the current system

        @return: self.compliant
        @rtype: bool
        @author: ekkehard j. koch
        @change: Breen Malmberg - 12/20/2016 - added doc string; 
        '''

        # CHANGES REQUIRED IN INIT OF THIS RULE IF THE CONSTANTS, THAT NETWORKSETUP.PY USE, ARE CHANGED
        # ALSO CHANGE THE DETAILEDRESULTS OUTPUT HERE IF THOSE CONSTANTS CHANGE
        if self.nsobject == None:
            self.compliant = False
            self.detailedresults += "\nPlease ensure that the following constants, in localize.py, are correctly defined and are not None: DNS, PROXY, PROXYCONFIGURATIONFILE, PROXYDOMAIN"
            self.formatDetailedResults("report", self.compliant, self.detailedresults)
            return self.compliant

        self.logdispatch.log(LogPriority.DEBUG, "Entering ConfigureNetworks.report()...")

        self.detailedresults = ""
        self.compliant = True
        compliant = True
        kvcompliant = True

        try:

            if not RuleKVEditor.report(self, True):
                kvcompliant = False
                self.logdispatch.log(LogPriority.DEBUG, "KVeditor.report() returned False.")

            if not self.nsobject.getLocation():
                compliant = False
                self.logdispatch.log(LogPriority.DEBUG, "nsobject.getLocation() returned False. Will not run nsobject.updateCurrentNetworkConfigurationDictionary()!")

            if compliant:
                if not self.nsobject.updateCurrentNetworkConfigurationDictionary():
                    compliant = False
                    self.logdispatch.log(LogPriority.DEBUG, "nsobject.updateCurrentNetworkConfigurationDictionary() returned False. Will not run nsobject.report()!")

            if compliant:
                if not self.nsobject.report():
                    compliant = False
                    self.logdispatch.log(LogPriority.DEBUG, "nsobject.report() returned False.")
                self.resultAppend(self.nsobject.getDetailedresults())

            self.logdispatch.log(LogPriority.DEBUG, "compliant=" + str(compliant))
            self.logdispatch.log(LogPriority.DEBUG, "kvcompliant=" + str(kvcompliant))

            self.compliant = compliant and kvcompliant

            self.logdispatch.log(LogPriority.DEBUG, "Exiting ConfigureNetworks.report() and returning self.compliant=" + str(self.compliant))

        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception, err:
            self.rulesuccess = False
            messagestring = str(err) + " - " + str(traceback.format_exc())
            self.resultAppend(messagestring)
            self.logdispatch.log(LogPriority.ERROR, messagestring)
        self.formatDetailedResults("report", self.compliant,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)

        return self.compliant

###############################################################################

    def fix(self):
        '''
        run fix actions for ConfigureNetworks
        return True if all succeed

        @return: fixed
        @rtype: bool
        @author: ekkehard j. koch
        @change: Breen Malmberg - 12/20/2016 - added doc string; detailedresults
                and fixed var's moved to before try; 
        @change: Breen Malmberg - 1/12/2017 - added debug logging; default init kvfixed to True
        '''

        # CHANGES REQUIRED IN INIT OF THIS RULE IF THE CONSTANTS, THAT NETWORKSETUP.PY USE, ARE CHANGED
        if self.nsobject == None:
            fixed = False
            self.formatDetailedResults("fix", fixed, self.detailedresults)
            return fixed

        self.logdispatch.log(LogPriority.DEBUG, "Entering ConfigureNetworks.fix()...")

        self.detailedresults = ""
        fixed = True
        kvfixed = True

        try:

            self.logdispatch.log(LogPriority.DEBUG, "Running nsobject.getLocation()...")
            if not self.nsobject.getLocation():
                fixed = False

            if not fixed:
                self.logdispatch.log(LogPriority.DEBUG, "nsobject.getLocation() returned False! Will not run updateCurrentNetworkConfigurationDictionary() or nsobject.fix()!")

            if fixed:
                if not self.nsobject.updateCurrentNetworkConfigurationDictionary():
                    fixed = False

            if not fixed:
                self.logdispatch.log(LogPriority.DEBUG, "updateCurrentNetworkConfigurationDictionary() returned False! Will not run nsobject.fix()!")

            if fixed:
                self.logdispatch.log(LogPriority.DEBUG, "Running nsobject.fix()...")
                if not self.nsobject.fix():
                    fixed = False
                    self.logdispatch.log(LogPriority.DEBUG, "nsobject.fix() failed. fixed set to False.")
                self.resultAppend(self.nsobject.getDetailedresults())

            if not RuleKVEditor.fix(self, True):
                kvfixed = False
                self.logdispatch.log(LogPriority.DEBUG, "Kveditor fix failed. kvfixed set to False.")

            fixed = fixed and kvfixed

            self.logdispatch.log(LogPriority.DEBUG, "Exiting ConfigureNetworks.fix() and returning fixed=" + str(fixed) + "...")

        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception, err:
            self.rulesuccess = False
            fixed = False
            messagestring = str(err) + " - " + str(traceback.format_exc())
            self.resultAppend(messagestring)
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", fixed, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return fixed

###############################################################################

    def afterfix(self):
        '''
        restart the service after fix

        @return: afterfixsuccessful
        @rtype: bool
        @author: ekkehard j. koch
        @change: Breen Malmberg - 12/20/2016 - added doc string; var init before
                try
        @change: ekkehard - 2017/10/04 - temporary launchctl fix
        '''

        afterfixsuccessful = True

        try:
# TODO: This code needs to be fixed after implementation [artf39626]: ServiceHelper Enhancement
# FIXME: SystemHelper version 2 [artf39626]: ServiceHelper Enhancement
#            service = "/System/Library/LaunchDaemons/com.apple.blued.plist"
            servicename = "system/com.apple.blued"
#            if afterfixsuccessful:
#                afterfixsuccessful = self.sh.auditservice(service, servicename)
#            if afterfixsuccessful:
#                afterfixsuccessful = self.sh.disableservice(service, servicename)
#            if afterfixsuccessful:
#                afterfixsuccessful = self.sh.enableservice(service, servicename)
            if afterfixsuccessful:
                command = ["/bin/launchctl", "stop", servicename]
                afterfixsuccessful = self.ch.executeCommand(command)
            if afterfixsuccessful:
                command = ["/bin/launchctl", "disable", servicename]
                afterfixsuccessful = self.ch.executeCommand(command)
            if afterfixsuccessful:
                self.iditerator =+ 1
                myID = iterate(self.iditerator, self.rulenumber)
                command = ["/bin/launchctl", "enable", servicename]
                event = {"eventtype": "comm",
                         "command": command}
                self.statechglogger.recordchgevent(myID, event)
                self.iditerator =+ 1
                myID = iterate(self.iditerator, self.rulenumber)
                command = ["/bin/launchctl", "start", servicename]
                event = {"eventtype": "comm",
                         "command": command}
                self.statechglogger.recordchgevent(myID, event)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as err:
            self.rulesuccess = False
            afterfixsuccessful = False
            messagestring = str(err) + " - " + str(traceback.format_exc())
            self.resultAppend(messagestring)
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        return afterfixsuccessful
