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
This objects encapsulates the complexities of the networksetup command on 
macOS (OS X) for use with stonix4mac.

@author: ekkehard j. koch
@change: 2015/05/07 ekkehard Original Implementation
@change: 2015/09/18 ekkehard add startup and casper options
@change: 2016/03/23 Breen Malmberg wifi disablement fix
@change: 2016/03/30 ekkehard setAdvancedNetworkSetup fix
@change: 2016/03/30 ekkehard localize.py fix
@change: 2017/09/23 ekkehard __init__ fix
@change: 2017/10/04 ekkehard updateCurrentNetworkConfigurationDictionary fix
@change: 2017/10/13 ekkehard re-factor updateCurrentNetworkConfigurationDictionary
@change: 2018/02/06 ekkehard fix traceback
@change: 2018/03/06 Roy Nielsen - Fixes including stripping variables
                                  when acquiring data from commands,
                                  and splitting on non-space values.
                                  Also making sure commands run
                                  correctly by Device rather than name.
'''
import re
import types
from .localize import DNS
from .localize import PROXY
from .localize import PROXYCONFIGURATIONFILE
from .localize import PROXYDOMAIN
from .localize import PROXYDOMAINBYPASS
from .CommandHelper import CommandHelper
from .logdispatcher import LogPriority


class networksetup():
    '''This objects encapsulates the complexities of the networksetup command
    on macOS (OS X)
    
    @author: ekkehard j. koch


    '''

###############################################################################

    def __init__(self, logdispatcher):
        self.location = ""
        self.locationIsValidWiFiLocation = False
        self.locationInitialized = False
        self.ns = {}
        self.nsInitialized = False
        self.nso = {}
        self.nsInitialized = False
        self.resultReset()
        self.nsc = "/usr/sbin/networksetup"
        self.logdispatch = logdispatcher

        # This class can, in no way, continue if
        # These constants are undefined, or set to
        # None
        if not DNS:
            self.logdispatch.log(LogPriority.DEBUG, "Please ensure that the following constants, in localize.py, are correctly defined and are not None: DNS, PROXY, PROXYCONFIGURATIONFILE, PROXYDOMAIN. Networksetup.py will not function without these!")
            return None
        elif DNS == None:
            self.logdispatch.log(LogPriority.DEBUG, "Please ensure that the following constants, in localize.py, are correctly defined and are not None: DNS, PROXY, PROXYCONFIGURATIONFILE, PROXYDOMAIN. Networksetup.py will not function without these!")
            return None
        if not PROXY:
            self.logdispatch.log(LogPriority.DEBUG, "Please ensure that the following constants, in localize.py, are correctly defined and are not None: DNS, PROXY, PROXYCONFIGURATIONFILE, PROXYDOMAIN. Networksetup.py will not function without these!")
            return None
        elif PROXY == None:
            self.logdispatch.log(LogPriority.DEBUG, "Please ensure that the following constants, in localize.py, are correctly defined and are not None: DNS, PROXY, PROXYCONFIGURATIONFILE, PROXYDOMAIN. Networksetup.py will not function without these!")
            return None
        if not PROXYCONFIGURATIONFILE:
            self.logdispatch.log(LogPriority.DEBUG, "Please ensure that the following constants, in localize.py, are correctly defined and are not None: DNS, PROXY, PROXYCONFIGURATIONFILE, PROXYDOMAIN. Networksetup.py will not function without these!")
            return None
        elif PROXYCONFIGURATIONFILE == None:
            self.logdispatch.log(LogPriority.DEBUG, "Please ensure that the following constants, in localize.py, are correctly defined and are not None: DNS, PROXY, PROXYCONFIGURATIONFILE, PROXYDOMAIN. Networksetup.py will not function without these!")
            return None
        if not PROXYDOMAIN:
            self.logdispatch.log(LogPriority.DEBUG, "Please ensure that the following constants, in localize.py, are correctly defined and are not None: DNS, PROXY, PROXYCONFIGURATIONFILE, PROXYDOMAIN. Networksetup.py will not function without these!")
            return None
        elif PROXYDOMAIN == None:
            self.logdispatch.log(LogPriority.DEBUG, "Please ensure that the following constants, in localize.py, are correctly defined and are not None: DNS, PROXY, PROXYCONFIGURATIONFILE, PROXYDOMAIN. Networksetup.py will not function without these!")
            return None

        fullproxy = PROXY
        self.ps = fullproxy.split(":")[-2].strip('//')
        self.pp = fullproxy.split(":")[-1]
        self.pf = PROXYCONFIGURATIONFILE
        self.dns = DNS
        self.searchdomain = PROXYDOMAIN
        self.domainByPass = PROXYDOMAINBYPASS
        self.ch = CommandHelper(self.logdispatch)
        self.initialized = False
        self.nameofdevice = ""
        self.notinservicelist = False
        self.detailedresults = ""

###############################################################################

    def report(self):
        '''report is designed to implement the report portion of the stonix rule

        :param self: essential if you override this definition
        @author: ekkehard j. koch
        @change: Breen Malmberg - 12/21/2016 - doc string revision; minor refactor;
                try/except
        :returns: compliant
        :rtype: bool

        '''

        self.logdispatch.log(LogPriority.DEBUG, "Entering networksetup.report()...\n")

        compliant = True
        if not self.initialize():
            self.logdispatch.log(LogPriority.DEBUG, "self.initialize() failed!")
        self.resultReset()

        try:

            if self.locationIsValidWiFiLocation:
                self.resultAppend("WiFi Network Setup for " + \
                                  "services for location named " + \
                                  str(self.location))
            else:
                self.resultAppend("Non-WiFi Network Setup for " + \
                                  "services for location named " + \
                                  str(self.location))

            for key in sorted(self.nso):
                network = self.nso[key]
                networkvalues = self.ns[network]

                networkname = networkvalues["name"]
                networktype = networkvalues["type"]
                networkenabled = networkvalues["enabled"]

                self.logdispatch.log(LogPriority.DEBUG, "key is " + str(key) + "\n")
                self.logdispatch.log(LogPriority.DEBUG, "network name is " + str(networkname) + "\n")
                self.logdispatch.log(LogPriority.DEBUG, "networktype is " + str(networktype) + "\n")
                self.logdispatch.log(LogPriority.DEBUG, "networkenabled is " + str(networkenabled) + "\n")
                self.logdispatch.log(LogPriority.DEBUG, "self.locationIsValidWiFiLocation is " + str(self.locationIsValidWiFiLocation) + "\n")

                if networktype == "bluetooth" and networkenabled:
                    self.logdispatch.log(LogPriority.DEBUG, "networktype is bluetooth and it is enabled. Setting compliant to False!")
                    compliant = False
                    networkvalues["compliant"] = False
                elif networktype == "wi-fi" and networkenabled and not self.locationIsValidWiFiLocation:
                    self.logdispatch.log(LogPriority.DEBUG, "networktype is wi-fi and it is enabled. This is not a valid wi-fi location. Setting compliant to False!")
                    compliant = False
                    networkvalues["compliant"] = False
                else:
                    networkvalues["compliant"] = True

                if networkvalues["compliant"]:
                    messagestring = str(networkname) + " is compliant " + \
                    ": " + str(networkvalues)
                else:
                    messagestring = str(networkname) + " is NOT " + \
                    "compliant : " + str(networkvalues)
                self.resultAppend(str(key) + " - " + messagestring)

            self.logdispatch.log(LogPriority.DEBUG, "Exiting networksetup.report() with compliant = " + str(compliant) + "\n")

        except Exception:
            raise
        return compliant

###############################################################################

    def fix(self):
        '''fix is designed to implement the fix portion of the stonix rule


        :returns: fixed

        :rtype: bool
@author: ekkehard j. koch
@change: Breen Malmberg - 1/12/2017 - added debug logging; doc string edit;
        added try/except

        '''

        self.logdispatch.log(LogPriority.DEBUG, "Entering networksetup.fix()...")

        fixed = True

        self.logdispatch.log(LogPriority.DEBUG, "Running self.initialize()...")
        if not self.initialize():
            self.logdispatch.log(LogPriority.DEBUG, "self.initialize() failed!")
        self.resultReset()

        messagestring = "for location = " + str(self.location)

        try:

            for key in sorted(self.nso):
                network = self.nso[key]
                networkvalues = self.ns[network]
                networkname = networkvalues["name"]
                networktype = networkvalues["type"]
                networkenabled = networkvalues["enabled"]

                self.logdispatch.log(LogPriority.DEBUG, "ns(key, network, networktype, networkenabled) = (" + str(key) + ", " + str(network) + ", " + str(networktype) + ", " + str(networkenabled) + ")")
                self.logdispatch.log(LogPriority.DEBUG, "self.locationIsValidWiFiLocation is " + str(self.locationIsValidWiFiLocation) + "\n")

                if networktype == "bluetooth" and networkenabled:
                    self.logdispatch.log(LogPriority.DEBUG, "Running disableNetworkService(" + str(networkname) + ")...")
                    fixedWorked = self.disableNetworkService(networkname)
                    if fixedWorked:
                        networkvalues["compliant"] = True
                        messagestring = str(networkname) + " fixed " + \
                        ": " + str(networkvalues)
                    else:
                        fixed = False

                elif networktype == "wi-fi" and networkenabled and not self.locationIsValidWiFiLocation:
                    self.logdispatch.log(LogPriority.DEBUG, "Running disableNetworkService(" + str(networkname) + ")...")
                    fixedWorked = self.disableNetworkService(networkname)
                    if fixedWorked:
                        self.logdispatch.log(LogPriority.DEBUG, "Fix worked!")
                        networkvalues["compliant"] = True
                        messagestring = str(networkname) + " fixed " + \
                        ": " + str(networkvalues)
                    else:
                        self.logdispatch.log(LogPriority.DEBUG, "Fix did NOT work!")
                        fixed = False

                elif networktype == "wi-fi" and not networkenabled and self.locationIsValidWiFiLocation:
                    self.logdispatch.log(LogPriority.DEBUG, "Running enableNetwork(" + str(networkname) + ")...")
                    fixedWorked = self.enableNetwork(networkname)
                    if fixedWorked:
                        networkvalues["compliant"] = True
                        messagestring = str(networkname) + " fixed " + \
                        ": " + str(networkvalues)
                    else:
                        fixed = False

                else:
                    networkvalues["compliant"] = True
                    messagestring = ""
                if not messagestring == "":
                    self.resultAppend(messagestring)

        except Exception:
            raise
        return fixed

###############################################################################

    def disableNetworkService(self, pNetworkName):
        '''disable network service
        
        @author: ekkehard j. koch

        :param self: essential if you override this definition
        :param pNetworkName: name of network
        :returns: boolean - true
        @note: None
        @change: Breen Malmberg - 3/23/2016 - wifi will now be disabled via
                setairportpower if not found in the service list.
        @change: Breen Malmberg - 12/20/2016 - minor refactor; parameter validation
                ;logging
        @change: Breen Malmberg - 1/12/2017 - added more debug logging

        '''

        self.logdispatch.log(LogPriority.DEBUG, "Entering networksetup.disableNetworkService()...")

        success = True
        networkName = pNetworkName.strip()

        try:

            if not isinstance(pNetworkName, basestring):
                self.logdispatch.log(LogPriority.DEBUG, "Specified parameter: pNetworkName must be of type: string. Got: " + str(type(pNetworkName)))
                success = False

            if not pNetworkName:
                self.logdispatch.log(LogPriority.DEBUG, "Specified parameter: pNetworkName is blank or None!")
                success = False

            self.logdispatch.log(LogPriority.DEBUG, "\nnetworkName = " + str(networkName).strip().lower() + "\n")
            self.logdispatch.log(LogPriority.DEBUG, "\nself.nameofdevice = " + str(self.nameofdevice).strip().lower() + "\n")

            if str(networkName).strip().lower() == str(self.nameofdevice).strip().lower():

                self.logdispatch.log(LogPriority.DEBUG, "networkName matches self.nameofdevice. Running airportpower disable command...")

                disablecommand = [self.nsc, "-setairportpower", networkName, "off"]

                self.ch.executeCommand(disablecommand)
                
                if self.ch.getReturnCode() != 0:
                    success = False
                    self.logdispatch.log(LogPriority.DEBUG, "Execution of command failed: " + str(disablecommand))
                else:
                    self.logdispatch.log(LogPriority.DEBUG, "Command executed successfully: " + str(disablecommand))
            else:
                if success:
                    command = [self.nsc, "-setnetworkserviceenabled", networkName, "off"]
                    self.ch.executeCommand(command)
                    if self.ch.getReturnCode() != 0:
                        success = False
                        self.logdispatch.log(LogPriority.DEBUG, "Execution of command failed: " + str(command))

            if not success:
                self.logdispatch.log(LogPriority.DEBUG, "networksetup.disableNetworkService() Failed")
            else:
                self.logdispatch.log(LogPriority.DEBUG, "networksetup.disableNetworkService() was Successful")

            self.logdispatch.log(LogPriority.DEBUG, "Exiting networksetup.disableNetworkService()")

        except Exception:
            success = False
            raise
        return success

###############################################################################

    def enableNetwork(self, pNetworkName):
        '''enable network service
        
        @author: ekkehard j. koch

        :param self: essential if you override this definition
        :param pNetworkName: name of network
        :returns: boolean - true
        @note: None
        @change: Breen Malmberg - 3/23/2016 - wifi will now be enabled via
            setairportpower if not found in the service list.
        @change: Breen Malmberg - 12/20/2016 - minor refactor; parameter validation
                ;logging

        '''

        self.logdispatch.log(LogPriority.DEBUG, "Entering networksetup.enableNetwork()...")

        success = True
        networkName = pNetworkName.strip()

        try:

            if not isinstance(pNetworkName, basestring):
                self.logdispatch.log(LogPriority.DEBUG, "Specified parameter: pNetworkName must be of type: string. Got: " + str(type(pNetworkName)))
                success = False

            if not pNetworkName:
                self.logdispatch.log(LogPriority.DEBUG, "Specified parameter: pNetworkName is blank or None!")
                success = False

            if str(networkName).strip().lower() == str(self.nameofdevice).strip().lower() and self.notinservicelist:
                enablecommand = [self.nsc, "-setairportpower", networkName, "on"]
                self.ch.executeCommand(enablecommand)
                if self.ch.getReturnCode() != 0:
                    success = False
                    self.logdispatch.log(LogPriority.DEBUG, "Execution of command failed: " + str(enablecommand))
            else:
                if networkName == "":
                    success = False
                if success:
                    command = [self.nsc, "-setnetworkserviceenabled", networkName, "on"]
                    self.ch.executeCommand(command)
                    if self.ch.getReturnCode() != 0:
                        success = False
                        self.logdispatch.log(LogPriority.DEBUG, "Execution of command failed: " + str(command))

            if not success:
                self.logdispatch.log(LogPriority.DEBUG, "networksetup.enableNetwork() Failed")
            else:
                self.logdispatch.log(LogPriority.DEBUG, "networksetup.enableNetwork() was Successful")

            self.logdispatch.log(LogPriority.DEBUG, "Exiting networksetup.enableNetwork()")

        except (KeyboardInterrupt, SystemExit):
# User initiated exit
            raise
        except Exception:
            raise
        return success

###############################################################################

    def getDetailedresults(self):
        '''get the detailed results text
        
        @author: ekkehard j. koch

        :param self: essential if you override this definition
        :param pLocationName: location name
        :returns: string: detailedresults
        @note: None

        '''
        return self.detailedresults

###############################################################################

    def getLocation(self):
        '''get the location used by on the mac
        
        @author: ekkehard j. koch

        :param self: essential if you override this definition
        :returns: boolean - true
        @note: None

        '''
        try:
            success = True
            command = [self.nsc, "-getcurrentlocation"]
            self.ch.executeCommand(command)
            for line in self.ch.getOutput():
                lineprocessed = line.strip()
                self.location = lineprocessed
                self.locationInitialized = True
            self.locationIsValidWiFiLocation = self.isValidLocationName(self.location)

            self.logdispatch.log(LogPriority.DEBUG, "Is this a valid WiFi location? " + str(self.locationIsValidWiFiLocation))

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            success = False
            raise
        return success

###############################################################################

    def initialize(self):
        '''initialize the object
        
        @author: ekkehard j. koch


        :returns: self.initalized

        :rtype: bool
@change: Breen Malmberg - 1/12/2017 doc string fix; default init self.initialized to False;
        added try/except

        '''

        self.initialized = False

        try:

            if not self.initialized:
                self.getLocation()
                self.updateCurrentNetworkConfigurationDictionary()
                self.initialized = True

        except Exception:
            raise
        return self.initialized

###############################################################################

    def isValidLocationName(self, pLocationName=""):
        '''determine if this is a valid wifi location
        
        @author: ekkehard j. koch

        :param self: essential if you override this definition
        :param pLocationName: location name (Default value = "")
        :returns: boolean - true
        @note: None

        '''
        success = False
        pLocationName = pLocationName.strip()
        if pLocationName == "" or re.match("^\s+$", pLocationName):
            locationName = self.location.lower().strip()
        else:
            locationName = pLocationName.lower()
        if 'wi-fi' in locationName:
            success = True
        elif 'wifi' in locationName:
            success = True
        elif 'wireless' in locationName:
            success = True
        elif 'airport' in locationName:
            success = True
        elif 'off-site' in locationName:
            success = True
        elif 'offsite' in locationName:
            success = True
        else:
            success = False
        return success

###############################################################################

    def networksetupistnetworkserviceorderoutputprocessing(self, outputLines):

        success = True
        order = -1
        networkenabled = False
        newserviceonnexline = False
        newservice = False
        servicename = ""
        networktype = False
        for line in outputLines:
            lineprocessed = line.strip()
            if newserviceonnexline:
                newservice = True
                newserviceonnexline = False
            else:
                newservice = False
                newserviceonnexline = False
            if lineprocessed == "An asterisk (*) denotes that a network service is disabled.":
                infoOnThisLine = False
                newserviceonnexline = True
            elif lineprocessed == "":
                infoOnThisLine = False
                newserviceonnexline = True
            else:
                infoOnThisLine = True
            if newservice and infoOnThisLine:
                self.logdispatch.log(LogPriority.DEBUG, "New service and info line: " + str(line))
                order = order + 1
# see if network is enabled
                if lineprocessed[:3] == "(*)":
                    networkenabled = False
                else:
                    networkenabled = True
                linearray = lineprocessed.split()
                linearray = linearray[1:]
                servicename = ""
                for item in linearray:
                    if servicename == "":
                        servicename = item
                    else:
                        servicename = servicename + " " + item

                if "ethernet" in servicename.lower():
                    networktype = "ethernet"
                elif "lan" in servicename.lower():
                    #####
                    # The belkin dongles LANL has chosen to use for Apple
                    # laptops does not identify itself vi convention,
                    # so this is the choice roy is making to indicate the
                    # mapping between "Belkin USB-C LAN" and ethernet.
                    networktype = "ethernet"
                elif "bluetooth" in servicename.lower():
                    networktype = "bluetooth"
                elif "usb" in servicename.lower():
                    networktype = "usb"
                elif "wi-fi" in item.lower():
                    networktype = "wi-fi"
                elif "firewire" in servicename.lower():
                    networktype = "firewire"
                elif "thunderbolt" in servicename.lower():
                    networktype = "thunderbolt"
                else:
                    networktype = "unknown"
                self.ns[servicename] = {"name": servicename.strip(),
                                        "hardware port":  servicename.strip(),
                                        "enabled": networkenabled,
                                        "type": networktype.strip()}
# determine network type
            elif infoOnThisLine:
                self.logdispatch.log(LogPriority.DEBUG, "Info line: " + str(line))
                lineprocessed = lineprocessed.strip("(")
                lineprocessed = lineprocessed.strip(")")
                linearray = lineprocessed.split(",")
                for item in linearray:
                    lineprocessed = item.strip()
                    itemarray = lineprocessed.split(":")
                    if servicename <> "":
                        if len(itemarray) > 1:
                            self.ns[servicename][itemarray[0].strip().lower()] = itemarray[1].strip()
# update dictionary entry for network
                    self.logdispatch.log(LogPriority.DEBUG, "(servicename, enabled, networktype): (" + \
                                         str(servicename).strip() + ", " + str(networkenabled) + ", " + \
                                         str(networktype).strip() + ")")
# create an ordered list to look up later
                    orderkey = str(order).zfill(4)
                    self.nso[orderkey] = servicename.strip()
                    self.updateNetworkConfigurationDictionaryEntry(servicename.strip())
        self.setNetworkServiceOrder()
        return success

###############################################################################

    def networksetuplistallhardwareportsoutputprocessing(self, outputLines):

        success = True
        newserviceonnexline = False
        newservice = False
        servicename = ""
        # noinfo = False
        for line in outputLines:
            lineprocessed = line.strip()
            if newserviceonnexline:
                newservice = True
                newserviceonnexline = False
            else:
                newservice = False
                newserviceonnexline = False
            if lineprocessed == "":
                infoOnThisLine = False
                newserviceonnexline = True
            else:
                infoOnThisLine = True
# Get info from first new service line
            if newserviceonnexline and not servicename == "":
                self.updateNetworkConfigurationDictionaryEntry(servicename)
            elif lineprocessed == "VLAN Configurations":
                break
            elif newservice and infoOnThisLine:
                self.logdispatch.log(LogPriority.DEBUG, "New service and info line: " + str(line))
                linearray = lineprocessed.split(":")
                linearray = linearray[1:]
                servicename = ""
                for item in linearray:
                    if servicename == "":
                        servicename = item.strip()
                    else:
                        servicename = servicename + " " + item.strip()
                if "ethernet" in servicename.lower():
                    networktype = "ethernet"
                elif "lan" in servicename.lower():
                    #####
                    # The belkin dongles LANL has chosen to use for Apple
                    # laptops does not identify itself vi convention,
                    # so this is the choice roy is making to indicate the
                    # mapping between "Belkin USB-C LAN" and ethernet.
                    networktype = "ethernet"
                elif "bluetooth" in servicename.lower():
                    networktype = "bluetooth"
                elif "usb" in servicename.lower():
                    networktype = "usb"
                elif "wi-fi" in servicename.lower():
                    networktype = "wi-fi"
                elif "firewire" in servicename.lower():
                    networktype = "firewire"
                elif "thunderbolt" in servicename.lower():
                    networktype = "thunderbolt"
                else:
                    networktype = "unknown"
                self.ns[servicename] = {"name": servicename.strip(),
                                        "hardware port": servicename.strip(),
                                        "type": networktype.strip()}
# determine network type
            elif infoOnThisLine:
                self.logdispatch.log(LogPriority.DEBUG, "Info line: " + str(line))
                linearray = lineprocessed.split()
                colonFound = False
                nameOfItem = ""
                valueOfItem = ""
                for item in linearray:
                    processedItem = item.strip()
                    if not colonFound:
                        if ":" in item:
                            colonFound = True
                            processedItem = item.strip(":")
                        if nameOfItem == "":
                            nameOfItem = processedItem.lower()
                        else:
                            nameOfItem = nameOfItem + " " + processedItem.lower()
                    else:
                        if valueOfItem == "":
                            valueOfItem = processedItem
                        else:
                            valueOfItem = valueOfItem + " " + processedItem
                if not valueOfItem == "" and not nameOfItem == "":
                    self.ns[servicename][nameOfItem] = valueOfItem.strip()
        return success

###############################################################################

    def resultAppend(self, pMessage=""):
        '''reset the current kveditor values to their defaults.
        @author: ekkehard j. koch

        :param self: essential if you override this definition
        :param pMessage: message to be appended (Default value = "")
        :returns: boolean - true
        @note: None

        '''
        datatype = type(pMessage)
        if datatype == types.StringType:
            if not (pMessage == ""):
                messagestring = pMessage
                if (self.detailedresults == ""):
                    self.detailedresults = messagestring
                else:
                    self.detailedresults = self.detailedresults + "\n" + \
                                           messagestring
        elif datatype == types.ListType:
            if not (pMessage == []):
                for item in pMessage:
                    messagestring = item
                    if (self.detailedresults == ""):
                        self.detailedresults = messagestring
                    else:
                        self.detailedresults = self.detailedresults + "\n" + \
                        messagestring
        else:
            raise TypeError("pMessage with value" + str(pMessage) + \
                            "is of type " + str(datatype) + " not of " + \
                            "type " + str(types.StringType) + \
                            " or type " + str(types.ListType) + \
                            " as expected!")

###############################################################################

    def resultReset(self):
        '''reset the current kveditor values to their defaults.
        @author: ekkehard j. koch

        :param self: essential if you override this definition
        :returns: boolean - true
        @note: kveditorName is essential

        '''
        self.detailedresults = ""

###############################################################################

    def setAdvancedNetworkSetup(self, pHardwarePort = None):
        '''Set proxies up for normal first configuration that has a network
        connection.
        
        @author: Roy Nielsen

        :param self: essential if you override this definition
        :param pNetworkName: name of the network to fix
        :param pHardwarePort:  (Default value = None)
        :returns: boolean - true
        @note: None

        '''
        success = True
        if pHardwarePort == None:
            self.initialize()
            self.setNetworkServiceOrder()
            for key in sorted(self.nso):
                network = self.nso[key]
                networkvalues = self.ns[network]
                networkname = networkvalues["name"]
                networktype = networkvalues["type"]
                networkhardwarePort = networkvalues["hardware port"]
                networkenabled = networkvalues["enabled"]
                msg = "networkname " + str(networkname) + "; networktype " + str(networktype) + \
                "; networkhardwarePort " + str(networkhardwarePort) + "; networkenabled " + \
                str(networkenabled)
                self.logdispatch.log(LogPriority.DEBUG, msg)
                if networkenabled and (networktype == "wifi" or networktype == "ethernet"):
                    msg = "Enabled Network Found; " + msg
                    self.logdispatch.log(LogPriority.DEBUG, msg)
                    break
        else:
            networkhardwarePort = pHardwarePort.strip()
            networkenabled = True
# Set the DNS servers
        if not networkhardwarePort == "" and networkenabled:
            command = self.nsc + " -setdnsservers '" + str(networkhardwarePort) + "' " + self.dns
            self.ch.executeCommand(command)
            if self.ch.getError():
                msg = command + " output: " + str(self.ch.getOutput())
                self.logdispatch.log(LogPriority.DEBUG, msg)
                success = False
# Set the Search Domain
            command = self.nsc + " -setsearchdomains '" + str(networkhardwarePort) + "' " + self.searchdomain
            self.ch.executeCommand(command)
            if self.ch.getError():
                msg = command + " output: " + str(self.ch.getOutput())
                self.logdispatch.log(LogPriority.DEBUG, msg)
                success = False
# set up the auto proxy URL
            command = self.nsc + " -setautoproxyurl '" + str(networkhardwarePort) + "' " + self.pf
            self.ch.executeCommand(command)
            if self.ch.getError():
                msg = command + " output: " + str(self.ch.getOutput())
                self.logdispatch.log(LogPriority.DEBUG, msg)
                success = False
# Set up the FTP proxy
            command = self.nsc + " -setftpproxy '" + str(networkhardwarePort) + "' " + self.ps + " " + self.pp
            self.ch.executeCommand(command)
            if self.ch.getError():
                msg = command + " output: " + str(self.ch.getOutput())
                self.logdispatch.log(LogPriority.DEBUG, msg)
                success = False
# Set up the HTTPS proxy
            command = self.nsc + " -setsecurewebproxy '" + str(networkhardwarePort) + "' " + self.ps + " " + self.pp
            self.ch.executeCommand(command)
            if self.ch.getError():
                msg = command + " output: " + str(self.ch.getOutput())
                self.logdispatch.log(LogPriority.DEBUG, msg)
                success = False
# Set up the web proxy
            command = self.nsc + " -setwebproxy '" + str(networkhardwarePort) + "' " + self.ps + " " + self.pp
            self.ch.executeCommand(command)
            if self.ch.getError():
                msg = command + " output: " + str(self.ch.getOutput())
                self.logdispatch.log(LogPriority.DEBUG, msg)
                success = False
# Get current proxy bypass domains and add self.searchdomain
            command = self.nsc + " -getproxybypassdomains '" + str(networkhardwarePort) + "' "
            self.ch.executeCommand(command)
            if not self.ch.getError():
                command = self.nsc + " -setproxybypassdomains '" + str(networkhardwarePort) + "'"
                for item in self.ch.getOutput() :
                    if not re.match("^\s*$", item) :
                        command = command + " " + str(item.strip())
                if not self.domainByPass in command:
                    command = command + " " + str(self.domainByPass)
                    self.ch.executeCommand(command)
                    if not self.ch.getError():
                        success = False
            else:
                msg = command + " output: " + str(self.ch.getOutput())
                self.logdispatch.log(LogPriority.DEBUG, msg)
                success = False
        return success

###############################################################################

    def setNetworkServiceOrder(self):
        ''' '''
        #####
        # Find the interface that needs to be at the top of the self.nso order
        cmd = ["/sbin/route", "get", "default"]

        self.ch.executeCommand(cmd)
        defaultInterface = None

        for line in self.ch.getOutput():
            try:
                interface_match = re.match("\s+interface:\s+(\w+)", line)
                defaultInterface = interface_match.group(1)
            except (IndexError, KeyError, AttributeError), err:
                self.logdispatch.log(LogPriority.DEBUG, str(line) + " : " + str(err))
            else:
                self.logdispatch.log(LogPriority.DEBUG, "Found: " + str(line))
                break

        #####
        # Find the interface/service name via networksetup -listallhardwareports
        cmd = ["/usr/sbin/networksetup", "-listallhardwareports"]

        self.ch.executeCommand(cmd)

        hardwarePort = ""
        device = ""
        enet = ""

        for line in self.ch.getOutput():
            try:
                hw_match = re.match("^Hardware Port:\s+(.*)\s*$", line)
                hardwarePort = hw_match.group(1)
                #print hardwarePort
            except AttributeError, err:
                pass
            try:
                #print line
                dev_match = re.match("^Device:\s+(.*)\s*$", line)
                device = dev_match.group(1)
                #print str(device)
            except AttributeError, err:
                pass
            try:
                enet_match = re.match("^Ethernet Address:\s+(\w+:\w+:\w+:\w+:\w+:\w+)\s*$", line)
                enet = enet_match.group(1)
                self.logger.log(LogPriority.DEBUG, "enet: " + str(enet))
            except AttributeError, err:
                pass

            if re.match("^$", line) or re.match("^\s+$", line):
                if re.match("^%s$"%str(device), str(defaultInterface)):
                    self.logdispatch.log(LogPriority.DEBUG, device)
                    self.logdispatch.log(LogPriority.DEBUG,  defaultInterface)
                    break
                hardwarePort = ""
                device = ""
                enet = ""

        #####
        # Reset NSO order if the defaultInterface is not at the top of the list
        newnso = {}
        i = 1

        self.logdispatch.log(LogPriority.DEBUG, str(self.nso))
        self.logdispatch.log(LogPriority.DEBUG, "hardware port: " + hardwarePort)

        for key, value in sorted(self.nso.iteritems()):
            #print str(key) + " : " + str(value)
            if re.match("^%s$"%hardwarePort.strip(), value.strip()):
                key = re.sub("^\d\d\d\d$", "0000", key)
                newnso[key] = value
            else:
                orderkey = str(i).zfill(4)
                newnso[orderkey] = value
                i = i + 1
                self.logdispatch.log(LogPriority.DEBUG, str(newnso))
        #print str(newnso)
        self.nso = newnso
        self.logdispatch.log(LogPriority.DEBUG, str(self.nso))
        for key, value in sorted(self.nso.iteritems()):
            self.logdispatch.log(LogPriority.DEBUG, str(key) + " : " + str(value))

        for item in self.ns: 
            if re.match("^%s$"%hardwarePort.strip(), self.ns[item]["name"]) and self.ns[item]["type"] is "unknown" and re.match("^en", defaultInterface):
                self.ns[item]["type"] = "ethernet"

###############################################################################

    def startup(self):
        '''startup is designed to implement the startup portion of the stonix rule
        
        @author: ekkehard j. koch


        '''
        disabled = True
        self.initialize()
        messagestring = "for location = " + str(self.location)
        for key in sorted(self.nso):
            network = self.nso[key]
            networkvalues = self.ns[network]
            networkname = networkvalues["name"]
            networktype = networkvalues["type"]
            networkenabled = networkvalues["enabled"]
            if networktype == "bluetooth" and networkenabled:
                fixedWorked = self.disableNetworkService(networkname)
                if fixedWorked:
                    networkvalues["compliant"] = True
                    messagestring = str(networkname) + " fixed " + \
                    ": " + str(networkvalues)
                else:
                    disabled = False
            elif networktype == "wi-fi" and networkenabled:
                fixedWorked = self.disableNetworkService(networkname)
                if fixedWorked:
                    networkvalues["compliant"] = True
                    messagestring = str(networkname) + " fixed " + \
                    ": " + str(networkvalues)
                else:
                    disabled = False
            else:
                networkvalues["compliant"] = True
                messagestring = ""
            if not messagestring == "":
                self.resultAppend(messagestring)
        return disabled

###############################################################################

    def updateCurrentNetworkConfigurationDictionary(self):
        '''update the network configuration dictianry
        
        @author: ekkehard j. koch

        :param self: essential if you override this definition
        :returns: boolean - true
        @note: None
        @change: Breen Malmberg - 3/23/2016 - added code to find and disable
                wi-fi on el capitan, via hardware ports instead of just service

        '''

        self.logdispatch.log(LogPriority.DEBUG, "Entering updateCurrentNetworkConfigurationDictionary()...")

        try:

            success = True

# issue networksetup -listallhardwareports to get all network services
            if success:
                command = [self.nsc, "-listallhardwareports"]
                self.ch.executeCommand(command)
                self.logdispatch.log(LogPriority.DEBUG, "Building ns dictionary from command: " + str(command))
                success = self.networksetuplistallhardwareportsoutputprocessing(self.ch.getOutput())

# issue networksetup -listallnetworkservices to get all network services
            if success:
                command = [self.nsc, "-listnetworkserviceorder"]
                self.ch.executeCommand(command)
                self.logdispatch.log(LogPriority.DEBUG, "Building ns dictionary from command: " + str(command))
                success = self.networksetupistnetworkserviceorderoutputprocessing(self.ch.getOutput())

# set ns init and nso init status
            self.nsInitialized = True
            self.nsoInitialized = True

            self.logdispatch.log(LogPriority.DEBUG, "Exiting updateCurrentNetworkConfigurationDictionary()...")

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            success = False
            raise
        return success

###############################################################################

    def updateNetworkConfigurationDictionaryEntry(self, pKey):
        '''update a single network configuration dictionary entry
        
        @author: ekkehard j. koch

        :param self: essential if you override this definition
        :param pkey: key for the dictinary entry
        :param pKey: 
        :returns: boolean - true
        @note: None
        @change: Breen Malmberg - 1/12/2017 - doc string edit; added debug logging;
                default var init success to True; added code to update the Wi-Fi entry;
        @change: Roy Nielsen - 3/6/2018 - Changed algo to look at
                                          'Device' rather than 'name'
                                          when getting the airport power
                                          status

        '''
        pKey = pKey.strip()
        self.logdispatch.log(LogPriority.DEBUG, "Entering networksetup.updateNetworkConfigurationDictionaryEntry() with pKey=" + str(pKey) + "...")

        success = True
        key = pKey

        try:
            success = True
            key = pKey
            entry = self.ns[key]

            if success:
                if entry == None:
                    success = False
                    self.logdispatch.log(LogPriority.DEBUG, "self.ns[" + str(key) + "] was not found! success set to False.")

            if success:
                command = [self.nsc, "-getmacaddress", key]
                self.ch.executeCommand(command)
                for line in self.ch.getOutput():
                    try:
                        macaddress = re.search("(\w\w:\w\w:\w\w:\w\w:\w\w:\w\w)",
                                               line.strip()).group(1)
                    except:
                        macaddress = ""
                    self.ns[key]["macaddress"] = macaddress

            if success:
                # added for disabling by device name 1/11/2017
                if key == "Wi-Fi":
                    self.logdispatch.log(LogPriority.DEBUG, "Updating Wi-Fi device entry for: " + str(self.ns[key]["name"]))
                    command = [self.nsc, "-getairportpower", self.ns[key]["Device"]]
                    self.ch.executeCommand(command)
                    for line in self.ch.getOutput():
                        if re.search("Wi-Fi\s+Power.*On", line, re.IGNORECASE):
                            self.ns[key]["enabled"] = True
                            self.logdispatch.log(LogPriority.DEBUG, "airportpower for device " + str(self.ns[key]["name"]) + " is: On")
                        else:
                            self.ns[key]["enabled"] = False
                            self.logdispatch.log(LogPriority.DEBUG, "airportpower for device " + str(self.ns[key]["name"]) + " is: Off")
                else:
                    # original code (only for services)
                    command = [self.nsc,
                           "-getnetworkserviceenabled", key]
                    self.ch.executeCommand(command)
                    for line in self.ch.getOutput():
                        lineprocessed = line.strip()
                        if lineprocessed == "Enabled":
                            self.ns[key]["enabled"] = True
                        else:
                            self.ns[key]["enabled"] = False

            self.logdispatch.log(LogPriority.DEBUG, "Exiting networksetup.updateNetworkConfigurationDictionaryEntry() and returning success=" + str(success))
        except KeyError:
            self.logdispatch.log(LogPriority.DEBUG, "Key error...")
        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception:
            success = False
            raise

        return success
