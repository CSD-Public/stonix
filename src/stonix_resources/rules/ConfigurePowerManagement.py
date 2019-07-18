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
This method runs all the report methods for RuleKVEditors in defined in the
dictionary

@author: ekkehard j. koch
@change: 2014/08/27 - ekkehard - Original Implementation
@change: 2014/10/17 ekkehard OS X Yosemite 10.10 Update
@change: 2015/02/15 ekkehard - Artifact artf35701 : COSMETIC - ConfigurePowerManagement - Poor help text 
@change: 2015/04/14 dkennel updated to use new isApplicable
@change: 2015/09/17 ekkehard BatteryDiskSleep should have disksleep value not display sleep.
@change: 2015/11/16 eball Re-enabled getting values from CIs rather than static dict
@change: 2017/07/07 ekkehard - make eligible for macOS High Sierra 10.13
@change: 2017/08/28 ekkehard - Added self.sethelptext()
@change: 2017/11/13 ekkehard - make eligible for OS X El Capitan 10.11+
@change: 2018/06/08 ekkehard - make eligible for macOS Mojave 10.14
@change: 2019/03/12 ekkehard - make eligible for macOS Sierra 10.12+
'''



import traceback
import types
from ..rule import Rule
from ..CommandHelper import CommandHelper
from ..logdispatcher import LogPriority


class ConfigurePowerManagement(Rule):
    '''This Mac Only rule does the following:
    - Sets the Mac to stay awake if power is plugged-in.
    - Set the display to sleep after 30 minutes if inactivity (if plugged-in) or after 15 minutes of inactivity (if on laptop battery power)
    - Sets the hard drives to sleep after ten minutes of inactivity.
    - Sets the computer not to wake up if the computer is connected to a phone modem and the phone rings.
    - Sets the hard drives to sleep after ten minutes of inactivity.
    - Sets the computer not to wake up if the computer is connected to a phone modem and the phone rings.
    - Sets the Mac's wake-on-magic-ping option (Wake for Network Access or WakeOnLAN) off.
    - Disables the Start up automatically after a power failure feature in the Energy Saver System Pref. This feature is not available on all computers. This rule should be called disableAutoRestart, but it's not. Sorry.
    
    @author: ekkehard j. koch


    '''

###############################################################################

    def __init__(self, config, environ, logdispatcher, statechglogger):
        Rule.__init__(self, config, environ, logdispatcher,
                              statechglogger)
        self.rulenumber = 258
        self.rulename = 'ConfigurePowerManagement'
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.sethelptext()
        self.rootrequired = True
        self.guidance = []
        self.applicable = {'type': 'white',
                           'os': {'Mac OS X': ['10.12', 'r', '10.14.10']}}
        self.psconfiguration = \
        {"ACDisableSystemSleep":
         {"HelpText": "Sets the Mac to stay awake if power is plugged-in. Default(AC Power, sleep, 0).",
          "PowerType": "AC Power",
          "PowerSetting": "sleep",
          "PowerSettingValue": 0,
          "PowerSettingMinimum": 0,
          "PowerSettingMaximum": 60},
         "ACDisplaySleep":
         {"HelpText": "Set Display Sleep  minutes on AC Power. Default(AC Power, displaysleep, 30).",
          "PowerType": "AC Power",
          "PowerSetting": "displaysleep",
          "PowerSettingValue": 30,
          "PowerSettingMinimum": 0,
          "PowerSettingMaximum": 60},
         "ACDiskSleep":
         {"HelpText": "Set Disk Sleep minutes on AC Power. Default(AC Power, disksleep, 10).",
          "PowerType": "AC Power",
          "PowerSetting": "disksleep",
          "PowerSettingValue": 10,
          "PowerSettingMinimum": 0,
          "PowerSettingMaximum": 60},
         "BatteryDisplaySleep":
         {"HelpText": "Set Display Sleep minutes on Battery Power. Default(Battery Power, displaysleep, 15).",
          "PowerType": "Battery Power",
          "PowerSetting": "displaysleep",
          "PowerSettingValue": 15,
          "PowerSettingMinimum": 0,
          "PowerSettingMaximum": 60},
         "BatteryDiskSleep":
         {"HelpText": "Set Disk Sleep minutes on Battery Power. Default(Battery Power, disksleep, 10).",
          "PowerType": "Battery Power",
          "PowerSetting": "disksleep",
          "PowerSettingValue": 10,
          "PowerSettingMinimum": 0,
          "PowerSettingMaximum": 60}
         }
        self.ci = {}
        index = -1
        for pslabel, psinfo in sorted(self.psconfiguration.items()):
            datatype = 'int'
            key = pslabel
            instructions = psinfo["HelpText"]
            defaultInteger = psinfo["PowerSettingValue"]
            index = index + 1
            self.ci[pslabel] = self.initCi(datatype, key, instructions, defaultInteger)
        self.pmset = "/usr/bin/pmset"
        self.psd = {}
        self.psACPowerAvailable = False
        self.psACBatteryPowerAvailable = False
        self.ch = CommandHelper(self.logdispatch)

    def report(self):
        '''Go through power settings dictionary and see if they match

        :param self: essential if you override this definition
        :returns: boolean - true if applicable false if not

        '''
        try:
            self.detailedresults = ""
            self.initializePowerSetting(True)
            self.compliant = True
            for pslabel, psinfo in sorted(self.psconfiguration.items()):
                powerType = psinfo["PowerType"]
                if (powerType == "AC Power" and self.psACPowerAvailable) or (powerType == "Battery Power" and self.psACBatteryPowerAvailable):
                    powerSetting = psinfo["PowerSetting"]
                    powerSettingValue = self.ci[pslabel].getcurrvalue()
                    powerSettingActual = self.getPowerSetting(powerType, powerSetting, False)
                    powerSettingActualValue = int(powerSettingActual)
                    powerSettingInfo = "(" + str(powerType) + ", " + str(powerSetting) + \
                    ", [desired, actual][" + str(powerSettingValue) + ", " + str(powerSettingActual) +"])"
                    if powerSettingValue == powerSettingActualValue:
                        self.resultAppend(pslabel + " is compliant. " + powerSettingInfo)
                    else:
                        self.resultAppend(pslabel + " is not compliant! " + powerSettingInfo)
                        self.compliant = False

            self.logdispatch.log(LogPriority.DEBUG, self.detailedresults)
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

###############################################################################

    def fix(self):
        '''Go through power settings and fix the one we are supposed to

        :param self: essential if you override this definition
        :returns: boolean - true if applicable false if not

        '''
        try:
            self.detailedresults = ""
            success = True
            self.initializePowerSetting(True)
            for pslabel, psinfo in sorted(self.psconfiguration.items()):
                powerType = psinfo["PowerType"]
                if (powerType == "AC Power" and self.psACPowerAvailable) or (powerType == "Battery Power" and self.psACBatteryPowerAvailable):
                    powerSetting = psinfo["PowerSetting"]
                    powerSettingValue = self.ci[pslabel].getcurrvalue()
                    powerSettingActual = self.getPowerSetting(powerType, powerSetting, False)
                    powerSettingActualValue = int(powerSettingActual)
                    powerSettingInfo = "(" + str(powerType) + ", " + str(powerSetting) + \
                    ", [desired, actual][" + str(powerSettingValue) + ", " + str(powerSettingActual)+"])"
                    if powerSettingValue == powerSettingActualValue:
                        self.resultAppend(pslabel + " was correctly set. " + powerSettingInfo)
                    else:
                        newPowerSettingValue = self.setPowerSetting(powerType, powerSetting, powerSettingValue)
                        powerSettingActual = self.getPowerSetting(powerType, powerSetting, True)
                        powerSettingActualValue = int(powerSettingActual)
                        powerSettingInfo = "(" + str(powerType) + ", " + str(powerSetting) + \
                        ", [desired, actual][" + str(powerSettingValue) + ", " + str(powerSettingActual)+"])"
                        if powerSettingValue == powerSettingActualValue:
                            self.resultAppend(pslabel + " is now compliant! "  + powerSettingInfo)
                        else:
                            self.resultAppend(pslabel + " setting still not compliant! " + powerSettingInfo)
                            success = False
            self.rulesuccess = success
            self.logdispatch.log(LogPriority.DEBUG, self.detailedresults)
        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception as err:
            self.rulesuccess = False
            self.detailedresults = self.detailedresults + "\n" + str(err) + \
            " - " + str(traceback.format_exc())
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.compliant,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.rulesuccess

###############################################################################

    def initializePowerSetting(self, forceUpdate=False):
        '''Initialize Power Setting Dictionary (psd) with output from pmset command

        :param self: essential if you override this definition
        :param forceUpdate: Force Dictionary Reset (Default value = False)
        :returns: boolean - true if applicable false if not

        '''
        success = True
        if forceUpdate:
            self.psd = {}
            self.psACPowerAvailable = False
            self.psACBatteryPowerAvailable = False
        if self.psd == {}:
            itemType = ""
            item = {}
            command = [self.pmset, "-g", "disk"]
            self.ch.executeCommand(command)
            output = self.ch.getOutput()
            for line in output:
                linestripped = line.strip()
                values = linestripped.split()
                if linestripped == "Battery Power:":
                    if not itemType == "":
                        self.psd[itemType] = item
                        item = {}
                    itemType = "Battery Power"
                    self.psACBatteryPowerAvailable = True
                elif linestripped == "AC Power:":
                    if not itemType == "":
                        self.psd[itemType] = item
                        item = {}
                    itemType = "AC Power"
                    self.psACPowerAvailable = True
                elif not itemType == "":
                    name = ""
                    for namepart in values[:-1]:
                        name = name + " " + str(namepart)
                    name = name.strip()
                    value = str(values[-1])
                    try:
                        item[name] = int(value)
                    except Exception:
                        item[name] = value
                    messagestring = "[" + str(itemType) + ", " + str(name) + "] = " + \
                    str(item[name])
                    self.logdispatch.log(LogPriority.DEBUG, messagestring)
            if not itemType == "":
                self.psd[itemType] = item
        return success

###############################################################################

    def getPowerSetting(self, powerType, powerSetting, forceUpdate=False):
        '''Get a power setting on a system
        @author: ekkehard j. koch

        :param self: essential if you override this definition
        :param powerType: Like AC Power or Battery Power
        :param powerSetting: Like sleep or disksleep
        :param forceUpdate: Get new values from system if true (Default value = False)
        :returns: boolean - true
        @note: None

        '''
        try:
            self.initializePowerSetting(forceUpdate)
            powerSettingValueString = self.psd[powerType][powerSetting]
            if powerSettingValueString == "":
                powerSettingValue = 0
            else:
                powerSettingValue = int(powerSettingValueString)
            messagestring = "[" + str(powerType) + ", " + str(powerSetting) + \
            "] = " + str(powerSettingValue)
            self.logdispatch.log(LogPriority.DEBUG, messagestring)
        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception:
            powerSettingValue = 0
        return powerSettingValue

###############################################################################

    def setPowerSetting(self, powerType, powerSetting, powerSettingValue):
        '''Set a power setting on a system
        @author: ekkehard j. koch

        :param self: essential if you override this definition
        :param powerType: Like AC Power or Battery Power
        :param powerSetting: Like sleep or disksleep
        :param powerSettingValue: Value to set setting to
        :returns: boolean - true
        @note: None

        '''
        success = False
        if not powerSettingValue == self.getPowerSetting(powerType, powerSetting):
            if powerType == "Battery Power":
                command = [self.pmset, "-b", powerSetting, str(powerSettingValue)]
                self.ch.executeCommand(command)
            elif powerType == "AC Power":
                command = [self.pmset, "-c", powerSetting, str(powerSettingValue)]
                self.ch.executeCommand(command)
            if powerSettingValue == self.getPowerSetting(powerType, powerSetting, True):
                success = True
        else:
            success = True
        return success

###############################################################################

    def resultAppend(self, pMessage=""):
        '''reset the current kveditor values to their defaults.
        @author: ekkehard j. koch

        :param self: essential if you override this definition
        :param pMessage:  (Default value = "")
        :returns: boolean - true
        @note: kveditorName is essential

        '''
        datatype = type(pMessage)
        if datatype == bytes:
            if not (pMessage == ""):
                messagestring = pMessage
                if (self.detailedresults == ""):
                    self.detailedresults = messagestring
                else:
                    self.detailedresults = self.detailedresults + "\n" + \
                    messagestring
        elif datatype == list:
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
                            "type " + str(bytes) + \
                            " or type " + str(list) + \
                            " as expected!")
