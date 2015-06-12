#!/usr/bin/python

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

@author: ekkehard j. koch
@change: 2015/03/10 ekkehard original implementation
@change: 2015/03/11 ekkehard streamlined for stonix & comments
@change: 2015/06/10 ekkehard enhance LDAP lookup
'''
import re
import traceback
import types
from CommandHelper import CommandHelper
from logdispatcher import LogPriority


class MacInfoLANL():
    '''
    lanlMacInfo gets information from the mac and LDAP to help set basi
    computer data for the mac this includes:
    ComputerName
    HostName
    LocalHostname
    asset_id (property number)
    endUserName (owner)
    @author: ekkehard
    '''

    def __init__(self, logger):
        '''
        initialize lanlMacInfo
        @author: ekkehard
        '''
        self.logdispatch = logger
# Make sure we have the full path for all commands
        self.ch = CommandHelper(logger)
        self.LANLAssetTagNVRAM = ""
        self.LANLAssetTagFilesystem = ""
        self.macAddressDictionary = {}
        self.dictionary = {}
        self.accuracyDictionary = {}
        self.dictionaryItem = None
        self.keys = None
        self.key = None
        self.keyIndexNumber = 0
        self.keysNumberOf = 0
        self.entries = -1
        self.computerName = ""
        self.computerNameDiskUtility = ""
        self.hostName = ""
        self.hostNameDiskUtility = ""
        self.localHostname = ""
        self.localHostnameDiskUtility = ""
        self.endUsername = ""
        self.assetTag = ""
        self.macAddress = ""
        self.ipAddress = ""
        self.ipAddressActive = []
# Make sure we have the full path for all commands
        self.ns = "/usr/sbin/networksetup"
        self.scutil = "/usr/sbin/scutil"
        self.jamf = "/usr/sbin/jamf"
        self.nvram = "/usr/sbin/nvram"
        self.ldap = "/usr/bin/ldapsearch"
        self.lanl_property_file = "/Library/Preferences/lanl_property_number.txt"
# Initialize accuracy modules
        self.updateAssetTagAccuracy(True, 0, "", True)
        self.updateEndUserNameAccuracy(True, 0, "", True)
        self.updateComputerNameAccuracy(True, 0, "", True)
# reset messages and initialize everyting
        self.messageReset()
        self.initializeLanlAssetTagNVRAM()
        self.initializeLanlAssetTagFilesystem()
        self.initializeDiskUtilityInfo()
        self.populateFromMac()
        self.determinAccuracy()
    
    def gotoFirstItemLDAP(self):
        '''
        go to the first entry in the LDAP dictionary
        @author: ekkehard
        @return: dictionary entry
        '''
        self.keyIndexNumber = 0
        self.keys = sorted(self.dictionary.keys())
        self.keysNumberOf = len(self.keys)
        if self.keysNumberOf > self.keyIndexNumber:
            self.key = self.keys[self.keyIndexNumber]
            self.dictionaryItem = self.dictionary[self.key]
        else:
            self.key = None
            self.dictionaryItem = None
        return self.dictionaryItem

    def gotoNextItemLDAP(self):
        '''
        go to the next entry in the LDAP dictionary
        @author: ekkehard
        @return: dictionary entry
        '''
        self.keyIndexNumber = self.keyIndexNumber + 1
        self.keys = sorted(self.dictionary.keys())
        self.keysNumberOf = len(self.keys)
        if (self.keysNumberOf - 1) < self.keyIndexNumber:
            self.keyIndexNumber = 0
            self.dictionaryItem = None
        else:
            self.key = self.keys[self.keyIndexNumber]
            self.dictionaryItem = self.dictionary[self.key]
        return self.dictionaryItem

    def getCurrentItemLDAP(self):
        '''
        get the current item in the LDAP dictionary
        @author: ekkehard
        @return: dictionary entry
        '''
        return self.dictionaryItem

    def getComputerInfoCompliance(self):
        '''
        see if all is set correctly
        @author: ekkehard
        @return: boolean - True of False
        '''
        success = True
        compliant = True
# Check computername
        messagestring = "ComputerName Confidence level of " + \
        str(self.getSuggestedComputerNameConfidenceOnly()) + "%"
        if not(self.getSuggestedComputerNameConfidenceOnly() == 100):
            compliant = False
            messagestring = messagestring + " is less than 100%"
        messagestring = messagestring + "; ComputerName (" + \
        self.getDiskUtilityComputerName() + ") and proposed ComputerName (" + \
        self.getSuggestedComputerName() + ")"
        if not(self.getDiskUtilityComputerName() == self.getSuggestedComputerName()):
            compliant = False
            messagestring = messagestring + " are not equal;"
        else:
            messagestring = messagestring + " are equal;"
        if not compliant:
            messagestring = "- Not compliant; " + messagestring
            if not(self.computerNameAccuracyLevelWhy == "" ):
                messagestring = messagestring + " - " + self.computerNameAccuracyLevelWhy + ";"
            success = False
        else:
            messagestring = "- compliant; " + messagestring
        self.messageAppend(messagestring)
# Check hostname
        compliant = True
        messagestring = "HostName confidence level of " + \
        str(self.getSuggestedComputerNameConfidenceOnly()) + "%"
        if not(self.getSuggestedComputerNameConfidenceOnly() == 100):
            compliant = False
            messagestring = messagestring + " is less than 100%"
        messagestring = messagestring + "; HostName (" + \
        self.getDiskUtilityHostName() + ") and proposed HostName (" + \
        self.getSuggestedHostName() + ")"
        if not(self.getDiskUtilityHostName() == self.getSuggestedHostName()):
            compliant = False
            messagestring = messagestring + " are not equal;"
        else:
            messagestring = messagestring + " are equal;"
        if not compliant:
            messagestring = "- Not compliant; " + messagestring
            if not(self.computerNameAccuracyLevelWhy == "" ):
                messagestring = messagestring + " - " + self.computerNameAccuracyLevelWhy + ";"
            success = False
        else:
            messagestring = "- compliant; " + messagestring
        self.messageAppend(messagestring)
# Check localhostname
        compliant = True
        messagestring = "LocalHostName confidence level of " + \
        str(self.getSuggestedComputerNameConfidenceOnly()) + "%"
        if not(self.getSuggestedComputerNameConfidenceOnly() == 100):
            compliant = False
            messagestring = messagestring + " is less than 100%"
        messagestring = messagestring + "; LocalHostName (" + \
        self.getDiskUtilityLocalHostName() + ") and proposed LocalHostName (" + \
        self.getSuggestedLocalHostName() + ")"
        if not(self.getDiskUtilityLocalHostName() == self.getSuggestedLocalHostName()):
            compliant = False
            messagestring = messagestring + " are not equal;"
        else:
            messagestring = messagestring + " are equal;"
        if not compliant:
            messagestring = "- Not compliant; " + messagestring
            if not(self.computerNameAccuracyLevelWhy == "" ):
                messagestring = messagestring + " - " + self.computerNameAccuracyLevelWhy + ";"
            success = False
        else:
            messagestring = "- compliant; " + messagestring
        self.messageAppend(messagestring)
        return success

    def getDiskUtilityComputerName(self):
        '''
        get the ComputerName determined by disk utility
        @author: ekkehard
        @return: string
        '''
        return self.computerNameDiskUtility

    def getDiskUtilityHostName(self):
        '''
        get the HostName determined by disk utility
        @author: ekkehard
        @return: string
        '''
        return self.hostNameDiskUtility

    def getDiskUtilityLocalHostName(self):
        '''
        get the LocalHostName determined by disk utility
        @author: ekkehard
        @return: string
        '''
        return self.localHostnameDiskUtility

    def getLANLAssetTagNVRAM(self):
        '''
        get the asset_id set in NVRAM determined
        @author: ekkehard
        @return: string
        '''
        return str(self.LANLAssetTagNVRAM)

    def getLANLAssetTagFilesystem(self):
        '''
        get the asset_id set in file system
        @author: ekkehard
        @return: string
        '''
        return str(self.LANLAssetTagFilesystem)

    def getSuggestedAssetTag(self):
        '''
        get the suggested asset_id
        @author: ekkehard
        @return: string
        '''
        if self.assetTag == "":
            self.assetTag = self.getLANLAssetTagNVRAM()
        if self.assetTag == "":
            self.assetTag = self.computerNameDiskUtilityAssetTag
        if self.assetTag == "":
            self.assetTag = self.getLANLAssetTagFilesystem()
        return self.assetTag
    
    def getSuggestedAssetTagConfidence(self):
        '''
        get the suggested asset_id and asset_id confidence level
        @author: ekkehard
        @return: string
        '''
        displayValue = str(self.getSuggestedAssetTag()) + " (" + str(self.assetTagAccuracyLevel) + "%)"
        return displayValue
    
    def getSuggestedAssetTagConfidenceOnly(self):
        '''
        get the suggested asset_id confidence level
        @author: ekkehard
        @return: real
        '''
        return self.assetTagAccuracyLevel

    def getSuggestedComputerName(self):
        '''
        get the suggested ComputerName
        @author: ekkehard
        @return: string
        '''
        if self.computerName == "":
            self.computerName = self.getDiskUtilityComputerName()
        return self.computerName
    
    def getSuggestedComputerNameConfidence(self):
        '''
        get the suggested ComputerName and ComputerName confidence level
        @author: ekkehard
        @return: string
        '''
        displayValue = str(self.getSuggestedComputerName()) + " (" + str(self.computerNameAccuracyLevel) + "%)"
        return displayValue
    
    def getSuggestedComputerNameConfidenceOnly(self):
        '''
        get the suggested ComputerName confidence level
        @author: ekkehard
        @return: real
        '''
        return self.computerNameAccuracyLevel

    def getSuggestedHostName(self):
        '''
        get the suggested HostName
        @author: ekkehard
        @return: string
        '''
        return self.hostName
    
    def getSuggestedHostNameConfidence(self):
        '''
        get the suggested HostName and HostName confidence level
        @author: ekkehard
        @return: string
        '''
        displayValue = str(self.hostName) + " (" + str(self.computerNameAccuracyLevel) + "%)"
        return displayValue
    
    def getSuggestedHostNameConfidenceOnly(self):
        '''
        get the suggested HostName confidence level
        @author: ekkehard
        @return: real
        '''
        return self.computerNameAccuracyLevel

    def getSuggestedLocalHostName(self):
        '''
        get the suggested LocalHostName
        @author: ekkehard
        @return: string
        '''
        return self.localHostname
    
    def getSuggestedLocalHostNameConfidence(self):
        '''
        get the suggested LocalHostName and LocalHostName confidence level
        @author: ekkehard
        @return: string
        '''
        displayValue = str(self.localHostname) + " (" + str(self.computerNameAccuracyLevel) + "%)"
        return displayValue
    
    def getSuggestedLocalHostNameConfidenceOnly(self):
        '''
        get the suggested LocalHostName confidence level
        @author: ekkehard
        @return: real
        '''
        return self.computerNameAccuracyLevel

    def getSuggestedEndUsername(self):
        '''
        get the suggested EndUserName or Owner
        @author: ekkehard
        @return: string
        '''
        return self.endUsername
    
    def getSuggestedEndUsernameConfidence(self):
        '''
        get the suggested EndUserName or Owner and EndUserName or Owner confidence level
        @author: ekkehard
        @return: string
        '''
        displayValue = str(self.endUsername) + " (" + str(self.endUserNameAccuracyLevel) + "%)"
        return displayValue
    
    def getSuggestedEndUsernameConfidenceOnly(self):
        '''
        get the suggested EndUserName or Owner confidence level
        @author: ekkehard
        @return: real
        '''
        return self.endUserNameAccuracyLevel

    def setComputerInfo(self):
        '''
        set the computer info on the computer
        @author: ekkehard
        @return: boolean - True
        '''
        try:
            success = True
            updatesWhereMade = False
            output = []
            computerName = self.getSuggestedComputerName()
            hostname = self.getSuggestedHostName()
            localHostName = self.getSuggestedLocalHostName()
            if self.computerNameAccuracyLevel == 100:
                if not(self.computerNameDiskUtility == computerName):
                    command = [self.scutil,"--set", "ComputerName", computerName]
                    self.ch.executeCommand(command)
                    errorcode = self.ch.getError()
                    output = self.ch.getOutput()
                    updatesWhereMade = True
                    messagestring = " - ComputerName set to " + computerName
                    self.messageAppend(messagestring)
                else:
                    messagestring = " - ComputerName was alreday " + computerName
                    self.messageAppend(messagestring)
                if not(self.hostNameDiskUtility == hostname):
                    command = [self.scutil,"--set", "HostName", hostname]
                    self.ch.executeCommand(command)
                    errorcode = self.ch.getError()
                    output = self.ch.getOutput()
                    updatesWhereMade = True
                    messagestring = " - HostName set to " + hostname
                    self.messageAppend(messagestring)
                else:
                    messagestring = " - HostName was alreday " + hostname
                    self.messageAppend(messagestring)
                if not(self.localHostnameDiskUtility == localHostName):
                    command = [self.scutil,"--set", "LocalHostName", localHostName]
                    errorcode = self.ch.getError()
                    self.ch.executeCommand(command)
                    output = self.ch.getOutput()
                    updatesWhereMade = True
                    messagestring = " - LocalHostName set to " + localHostName
                    self.messageAppend(messagestring)
                else:
                    messagestring = " - LocalHostName was alreday " + localHostName
                    self.messageAppend(messagestring)
        except(KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            messagestring = traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, messagestring)
        if updatesWhereMade == True:
            self.initializeDiskUtilityInfo()
        return success

    def setJAMFInfo(self):
        '''
        set the assetTag and endUserName via the jamf recon command
        @author: ekkehard
        @return: boolean - True
        '''
        try:
            success = True
            assetTag = self.getSuggestedAssetTag()
            endUser = self.getSuggestedEndUsername()
            if self.assetTagAccuracyLevel == 100 and self.endUserNameAccuracyLevel == 100:
                command = [self.jamf, "recon",
                           "-assetTag", assetTag,
                           "-endUsername", endUser]
                self.ch.executeCommand(command)
                output = self.ch.getOutput()
                messagestring = " - JAMF assetTag set to " + assetTag + " and endUsername set to " + endUser
                self.messageAppend(messagestring)
            elif self.assetTagAccuracyLevel == 100:
                command = [self.jamf, "recon", "-assetTag", assetTag]
                self.ch.executeCommand(command)
                output = self.ch.getOutput()
                endUser = ""
                messagestring = " - JAMF assetTag set to " + assetTag
                self.messageAppend(messagestring)
            elif self.endUserNameAccuracyLevel == 100:
                command = [self.jamf, "recon", "-endUsername", endUser]
                self.ch.executeCommand(command)
                output = self.ch.getOutput()
                assetTag = ""
                messagestring = " - JAMF endUsername set to " + endUser
                self.messageAppend(messagestring)
            else:
                success = False
                messagestring = " - JAMF settings were not changed because confidence was only " + \
                str(self.assetTagAccuracyLevel) + "%"
                self.messageAppend(messagestring)
        except(KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            messagestring = traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, messagestring)
        return success
        
    def setLANLAssetTagNVRAM(self):
        '''
        set the assetTag and endUserName via the jamf recon command
        @author: ekkehard
        @return: boolean - True
        '''
        try:
            assetTag = self.getSuggestedAssetTag()
            if self.assetTagAccuracyLevel == 100:
                if not(self.getLANLAssetTagNVRAM() == assetTag):
                    command = [self.nvram, "asset_id=" + assetTag]
                    self.ch.executeCommand(command)
                    self.initializeLanlAssetTagNVRAM()
                    messagestring = " - NVRAM asset_id set to " + assetTag
                    self.messageAppend(messagestring)
                else:
                    messagestring = " - NVRAM asset_id was already set to " + assetTag
                    self.messageAppend(messagestring)
            else:
                assetTag = ""
                messagestring = " - NVRAM asset_id was not changed because confidence was only " + \
                str(self.assetTagAccuracyLevel) + "%"
                self.messageAppend(messagestring)
        except(KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            messagestring = traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, messagestring)
        return assetTag
        
    def setLANLAssetTagFilesystem(self):
        '''
        set the assetTag on the file system
        @author: ekkehard
        @return: boolean - True
        '''
        try:
            assetTag = self.getSuggestedAssetTag()
            if self.assetTagAccuracyLevel == 100:
                if not(self.getLANLAssetTagFilesystem() == assetTag):
                    try :
                        filepointer = open(self.lanl_property_file, "w")
                        filepointer.write(assetTag)
                        filepointer.close()
                        self.initializeLanlAssetTagFilesystem()
                        assetTag = self.getLANLAssetTagFilesystem()
                    except Exception, err :
                        messagestring = "Problem writing: " + self.lanl_property_file + \
                        " error: " + str(err)
                        self.logdispatch.log(LogPriority.DEBUG, messagestring)
            else:
                assetTag = ""
                messagestring = " - Filesystem asset_id was not changed because confidence was only " + \
                str(self.assetTagAccuracyLevel) + "%"
                self.messageAppend(messagestring)
        except(KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            messagestring = traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, messagestring)
        return assetTag
                
    def determinAccuracy(self):
        '''
        go through all our data and see how good it is
        @author: ekkehard
        @return: boolean - True
        '''
        self.updateAssetTagAccuracy(True, 0, "", True)
        self.updateEndUserNameAccuracy(True, 0, "", True)
        self.updateComputerNameAccuracy(True, 0, "", True)
        self.computerName = ""
        self.hostName = ""
        self.localHostname = ""
        self.endUsername = ""
        self.assetTag = ""
# AssetTag for NVRAM & Filsystem do not match that is not good worth 1000
        if not(self.getLANLAssetTagNVRAM() == "") and not(self.getLANLAssetTagFilesystem() == ""):
            self.updateAssetTagAccuracy(self.getLANLAssetTagFilesystem() == self.getLANLAssetTagNVRAM(),
                                        1000, "LANLAssetTagNVRAM is not equal to LANLAssetTagFilesystem;")
        self.gotoFirstItemLDAP()
# Build a dictionary based upon assetTag. If all is right there should only be one.
        while not(self.getCurrentItemLDAP() == None):
# If the assetTag is not in the dictionary add an entry
            if not(self.dictionaryItem["assetTag"] in self.accuracyDictionary):
                if self.dictionaryItem["macAddress"] == "":
                    newMacAddress = []
                else:
                    newMacAddress = [self.dictionaryItem["macAddress"]]
                if self.dictionaryItem["ipAddress"] == "":
                    newIpAddress = []
                else:
                    newIpAddress = [self.dictionaryItem["ipAddress"]]
                if self.dictionaryItem["ComputerName"] == "":
                    newComputerName = []
                else:
                    newComputerName = [self.dictionaryItem["ComputerName"]]
                if self.dictionaryItem["endUsername"] == "":
                    newEndUsername = []
                else:
                    newEndUsername = [self.dictionaryItem["endUsername"]]
                item = {"macAddress": newMacAddress,
                        "ipAddress": newIpAddress,
                        "ComputerName": newComputerName,
                        "endUsername": newEndUsername,
                        "Number": 1}
                self.accuracyDictionary[self.dictionaryItem["assetTag"]] = item
# If the assetTag has a dictionary add an entry add extra data
            else:
                self.accuracyDictionary[self.dictionaryItem["assetTag"]]["Number"] = self.accuracyDictionary[self.dictionaryItem["assetTag"]]["Number"] + 1
# The macAddress is not in the list of macAddresses to append it
                if not(self.dictionaryItem["macAddress"] == ""):
                    if not(self.dictionaryItem["macAddress"] in self.accuracyDictionary[self.dictionaryItem["assetTag"]]["macAddress"]):
                        self.accuracyDictionary[self.dictionaryItem["assetTag"]]["macAddress"].append(self.dictionaryItem["macAddress"])
# The ipAddress is not in the list of ipAddresses to append it
                if not(self.dictionaryItem["ipAddress"] == ""):
                    if not(self.dictionaryItem["ipAddress"] in self.accuracyDictionary[self.dictionaryItem["assetTag"]]["ipAddress"]):
                        self.accuracyDictionary[self.dictionaryItem["assetTag"]]["ipAddress"].append(self.dictionaryItem["ipAddress"])
# The ComputerName is not in the list of computer names add it
                if not(self.dictionaryItem["ComputerName"] in self.accuracyDictionary[self.dictionaryItem["assetTag"]]["ComputerName"]):
                    self.accuracyDictionary[self.dictionaryItem["assetTag"]]["ComputerName"].append(self.dictionaryItem["ComputerName"])
# The endUserName is not in the list of endUserNames so append it
                if not(self.dictionaryItem["endUsername"] in self.accuracyDictionary[self.dictionaryItem["assetTag"]]["endUsername"]):
                    self.accuracyDictionary[self.dictionaryItem["assetTag"]]["endUsername"].append(self.dictionaryItem["endUsername"])
            self.gotoNextItemLDAP()
        self.updateAssetTagAccuracy(len(self.accuracyDictionary) == 1,
                                    0, "# of entries in accuracyDictionary is " + str(len(self.accuracyDictionary)) + ";")
        keys = sorted(self.accuracyDictionary.keys())
        currentNumber = -1
        key = ""
# pick the assetTag that has the most entries in LDAP
        for currentkey in keys:
            if self.accuracyDictionary[currentkey]["Number"] > currentNumber:
                currentNumber = self.accuracyDictionary[currentkey]["Number"]
                key = currentkey
# evaluate what we found
        if keys == None:
            numberOfKeys = 0
        else:
            numberOfKeys = len(keys)
# If there is more than one assetTag then all values accuracy is questionable
        self.updateAssetTagAccuracy(numberOfKeys == 1,
                                    1000, "# of assetTags found was " + str(numberOfKeys) + ";")
        self.updateComputerNameAccuracy(numberOfKeys == 1,
                                        1000, "# of assetTags found was " + str(numberOfKeys) + ";")
        self.updateEndUserNameAccuracy(numberOfKeys == 1,
                                       1000, "# of assetTags found was " + str(numberOfKeys) + ";")
        if not key == "":
            self.assetTag = key
# ComputerName, HostName, LocalHostname
            if not(self.accuracyDictionary[key]["ComputerName"] == []):
                self.computerName = self.accuracyDictionary[key]["ComputerName"][0]
                self.hostName = self.computerName
                temp = self.computerName.split(".")
                self.localHostname = temp[0].strip()
# If there are multiple ComputerNames we cannot rely on the ComputerName we pick
                self.updateComputerNameAccuracy(len(self.accuracyDictionary[key]["ComputerName"]) <= 1,
                                                1000, "# of ComputerNames is " + \
                                                str(len(self.accuracyDictionary[key]["ComputerName"])) + ";")
            else:
                self.computerName = ""
                self.hostName = ""
                self.localHostname = ""
                self.updateComputerNameAccuracy(not(self.computerName == ""),
                                                1000, "ComputerName is blank;")

# AssetTag
            if not(self.getLANLAssetTagNVRAM() == ""):
# If the NVRAM assetTage value is not equal to the most prominent assetTag that is an issue
                self.updateAssetTagAccuracy(self.getLANLAssetTagNVRAM() == self.assetTag,
                                            1000, "LANLAssetTagNVRAM is not equal to suggested assetTag;")
            if not(self.getLANLAssetTagFilesystem() == ""):
# If the Filesystem assetTag value is not equal to the most prominent assetTag that is an issue
                self.updateAssetTagAccuracy(self.getLANLAssetTagFilesystem() == self.assetTag,
                                            10, "LANLAssetTagFilesystem is not equal to suggested assetTag;")
            elif not(self.getLANLAssetTagNVRAM() == ""):
                if not(self.getLANLAssetTagNVRAM() == self.getLANLAssetTagFilesystem()):
# If the Filesystem assetTag value is not equal to NVRAM assetTag that is an issue
                    self.updateAssetTagAccuracy(self.getLANLAssetTagNVRAM() == self.getLANLAssetTagFilesystem(),
                                                10, "LANLAssetTagNVRAM is not equal to LANLAssetTagFilesystem;")
            if not(self.computerNameDiskUtilityAssetTag == ""):
                self.updateAssetTagAccuracy(self.computerNameDiskUtilityAssetTag == self.assetTag,
                                            500, "AssetTag in ComputerName is not equal to suggested assetTag;")
# Endusername
            if not(self.accuracyDictionary[key]["endUsername"] == []):
                self.endUsername = self.accuracyDictionary[key]["endUsername"][0]
# If there are multiple endUserNames we cannot rely on the endUserNames we pick
                self.updateEndUserNameAccuracy(len(self.accuracyDictionary[key]["endUsername"]) <= 1, 1000,
                                               "# of endUsername is " + \
                                               str(len(self.accuracyDictionary[key]["endUsername"])) + ";")
            else:
                self.endUsername = ""
# If endUserNames is blank we cannot rely on the endUserNames we pick
                self.updateEndUserNameAccuracy(not(self.endUsername == ""), 1000,
                                               "endUsername is blank;")
# macAddress
            if not(self.accuracyDictionary[key]["macAddress"] == []):
                self.macAddress = self.accuracyDictionary[key]["macAddress"][0]
            else:
                self.macAddress = ""
# ipAddress
            if not(self.ipAddressActive == []):
                self.ipAddress = self.ipAddressActive[0]
            elif not(self.accuracyDictionary[key]["ipAddress"] == []):
                self.ipAddress = self.accuracyDictionary[key]["ipAddress"][0]
            else:
                self.ipAddress = ""
        return self.assetTagAccuracyLevel
        
    def initializeDictionaryItemLDAP(self, key):
        '''
        initialize a new LDAP dictionary entry
        @author: ekkehard
        @return: dictionary item
        '''
        item = {"hardwarePort": "",
                "device": "",
                "macAddress": "",
                "ipAddress": "",
                "ComputerName": "",
                "HostName": "",
                "LocalHostname": "",
                "assetTag": "",
                "endUsername": ""}
        self.dictionary[key] = item
        self.dictionaryItem = self.dictionary[key]
        return self.dictionaryItem

    def initializeLanlAssetTagFilesystem(self):
        '''
        get assetTag from the file system
        @author: ekkehard
        @return: string
        '''
        self.LANLAssetTagFilesystem = ""
        try:
            fileToOpen = open(self.lanl_property_file, "r")
        except Exception, err:
            messagestring = "Cannot open: " + self.lanl_property_file + \
            "Exception: " + str(err)
            self.logdispatch.log(LogPriority.DEBUG, messagestring)
        else:
            try :
                for line in fileToOpen:
                    if re.match("[0-9]+", line.strip()):
                        self.LANLAssetTagFilesystem = line.strip()
                        messagestring = self.lanl_property_file + \
                        " property number = " + self.LANLAssetTagFilesystem
                        self.logdispatch.log(LogPriority.DEBUG, messagestring)
                        break
                    else :
                        self.LANLAssetTagFilesystem = ""
            except Exception, err:
                messagestring = str(err) + " - Can't find a line in the file: " + \
                self.LANLAssetTagFilesystem
                self.logdispatch.log(LogPriority.DEBUG, messagestring)
                self.LANLAssetTagFilesystem = ""
            else:
                fileToOpen.close()
        return self.LANLAssetTagFilesystem

    def initializeDiskUtilityInfo(self):
        '''
        get ComputerName, HostName, LocalHostName of the current computer
        @author: ekkehard
        @return: boolean - True
        '''
        success = True
        self.computerNameDiskUtility = ""
        self.hostNameDiskUtility = ""
        self.localHostnameDiskUtility = ""
        try:
            command = [self.scutil,"--get", "ComputerName"]
            self.ch.executeCommand(command)
            errorcode = self.ch.getError()
            output = self.ch.getOutput()
            if len(output) >= 1:
                self.computerNameDiskUtility = output[0].strip()
                
                namesplit = self.computerNameDiskUtility.split(".")
                firstPartOfComputerNameDiskUtility = namesplit[0].strip()
                mo = re.search('[0-9]{7}', firstPartOfComputerNameDiskUtility)
                if not(mo == None):
                    self.computerNameDiskUtilityAssetTag = mo.group()
                else:
                    self.computerNameDiskUtilityAssetTag = ""
                if not(re.search('[\s\c]', firstPartOfComputerNameDiskUtility)):
                    self.computerNameDiskUtilityHostName = firstPartOfComputerNameDiskUtility + \
                    ".lanl.gov"
                else:
                    self.computerNameDiskUtilityHostName = ""
            else:
                self.computerNameDiskUtility = ""
                self.computerNameDiskUtilityAssetTag = ""
                self.computerNameDiskUtilityHostName = ""
        except(KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            messagestring = traceback.format_exc()
            self.logdispatch.log(LogPriority.DEBUG, messagestring)
        try:
            command = [self.scutil,"--get", "HostName"]
            self.ch.executeCommand(command)
            errorcode = self.ch.getError()
            output = self.ch.getOutput()
            if len(output) >= 1:
                self.hostNameDiskUtility = output[0].strip()
            else:
                self.hostNameDiskUtility = ""
        except(KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            messagestring = traceback.format_exc()
            self.logdispatch.log(LogPriority.DEBUG, messagestring)
        try:
            command = [self.scutil,"--get", "LocalHostName"]
            errorcode = self.ch.getError()
            self.ch.executeCommand(command)
            output = self.ch.getOutput()
            if len(output) >= 1:
                self.localHostnameDiskUtility = output[0].strip()
            else:
                self.localHostnameDiskUtility = ""
        except(KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            messagestring = traceback.format_exc()
            self.logdispatch.log(LogPriority.DEBUG, messagestring)
        return success

    def initializeLanlAssetTagNVRAM(self):
        '''
        get assetTag from NVRAM
        @author: ekkehard
        @return: boolean - True
        '''
        success = True
        try:
            self.LANLAssetTagNVRAM = ""
            command = [self.nvram, "asset_id"]
            self.ch.executeCommand(command)
            output = self.ch.getOutput()
            if len(output) >= 1:
                self.LANLAssetTagNVRAM = str(output[-1].strip().split("\t")[1])
            else:
                self.LANLAssetTagNVRAM = ""
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            messagestring = traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, messagestring)
        return success

    def populateDataFromLDAP(self, addressType, address, hardwarePort, device):
        '''
        get LDAP data from
        @author: ekkehard j. koch
        @param self:essential if you override this definition
        @return: boolean - true
        @note: None
        '''
        try:
# lookup in LDAP based on macAddress
            success = True
            command = [self.ldap,
                       "-x",
                       "-h",
                       "ldap-adhoc.lanl.gov",
                       "-b",
                       "dc=lanl,dc=gov",
                       addressType + "=" + address]
            self.ch.executeCommand(command)
            output = self.ch.getOutput()
            macAddress = ""
            ipAddress = ""
            computerName = ""
            localHostname = ""
            endUsername = ""
            assetTag = ""
            newRecord = False
            for line in output:
                try:
                    if re.search("^dn:", line):
                        newRecord = True
                    else:
                        newRecord = False
                    if re.search("^ipHostNumber:", line):
                        temp = line.split(": ")
                        ipAddress = temp[1].strip()
                    if re.search("^macAddress:", line):
                        temp = line.split(": ")
                        macAddress = temp[1].strip()
                    if re.search("^cn:", line):
                        temp = line.split(": ")
                        computerName = temp[1].strip()
                        temp = computerName.split(".")
                        localHostname = temp[0].strip()
                    if re.search("^owner:", line):
                        temp = line.split(",")
                        temp = temp[0].split("=")
                        endUsername = temp[1].strip()
                    if re.search("^lanlPN:", line):
                        temp = line.split(" ")
                        assetTag = temp[1].strip()
                    if newRecord:
                        if not(assetTag == ""):
                            self.entries = self.entries + 1
                            self.initializeDictionaryItemLDAP(self.entries)
                            self.dictionaryItem["hardwarePort"] = hardwarePort
                            self.dictionaryItem["device"] = device
                            self.dictionaryItem["macAddress"] = macAddress
                            self.dictionaryItem["ipAddress"] = ipAddress
                            self.dictionaryItem["ComputerName"] = computerName
                            self.dictionaryItem["HostName"] = computerName
                            self.dictionaryItem["LocalHostname"] = localHostname
                            self.dictionaryItem["assetTag"] = assetTag
                            self.dictionaryItem["endUsername"] = endUsername
                        macAddress = ""
                        ipAddress = ""
                        computerName = ""
                        localHostname = ""
                        assetTag = ""
                        endUsername = ""
                except Exception, err:
                    messagestring = str(err) + " - " + str(traceback.format_exc())
                    self.logdispatch.log(LogPriority.DEBUG, messagestring)
                    continue
            if not(assetTag == ""):
                self.entries = self.entries + 1
                self.initializeDictionaryItemLDAP(self.entries)
                self.dictionaryItem["hardwarePort"] = hardwarePort
                self.dictionaryItem["device"] = device
                self.dictionaryItem["macAddress"] = macAddress
                self.dictionaryItem["ipAddress"] = ipAddress
                self.dictionaryItem["ComputerName"] = computerName
                self.dictionaryItem["HostName"] = computerName
                self.dictionaryItem["LocalHostname"] = localHostname
                self.dictionaryItem["assetTag"] = assetTag
                self.dictionaryItem["endUsername"] = endUsername
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            success = False
            messagestring = traceback.format_exc()
            self.logdispatch.log(LogPriority.DEBUG, messagestring)
        return success
    
    def populateFromMac(self):
        '''
        get network data from the local machine
        @author: ekkehard j. koch
        @param self:essential if you override this definition
        @return: boolean - true
        @note: None
        '''
        success = True
        try:
            macAddress = ""
            hardwarePort = ""
            device = ""
# networksetup -listaallhardwarereports
            command = [self.ns, "-listallhardwareports"]
            self.ch.executeCommand(command)
            output = self.ch.getOutput()
            for line in output:
                if re.search("^Hardware Port:", line):
                    temp = line.split(":")
                    hardwarePort = temp[1].strip()
                if re.search("^Device:", line):
                    temp = line.split(":")
                    device = temp[1].strip()
                if re.search("^Ethernet Address:", line):
                    temp = line.split(": ")
                    macAddress = temp[1].strip()
                    if not(macAddress == "N/A"):
                        item = {"macAddress": macAddress,
                                "hardwarePort": hardwarePort,
                                "device": device,
                                "IP address": "",
                                "IPv6": ""}
                        self.macAddressDictionary[macAddress] = item
                    macAddress = ""
                    hardwarePort = ""
                    device = ""
        except Exception, err:
            success = False
            messagestring = str(err) + " - " + str(traceback.format_exc())
            self.logdispatch.log(LogPriority.DEBUG, messagestring)
# go and pouplate the LDAP data
        keys = sorted(self.macAddressDictionary.keys())
        for key in keys:
            item = self.macAddressDictionary[key]
            command = [self.ns, "-getinfo", item["hardwarePort"]]
            self.ch.executeCommand(command)
            output = self.ch.getOutput()
            for line in output:
                if re.search("^IP address:", line):
                    temp = line.split(":")
                    ipaddress = temp[1].strip()
                    item["IP address"] = ipaddress
                if re.search("^IPv6:", line):
                    temp = line.split(":")
                    ipv6status = temp[1].strip()
                    item["IPv6"] = ipv6status
            self.populateDataFromLDAP("macAddress", item["macAddress"],
                                      item["hardwarePort"], item["device"])
            if not(item["IP address"] == ""):
                if not(item["IP address"] in self.ipAddressActive):
                    self.ipAddressActive.append(item["IP address"])
                self.populateDataFromLDAP("ipHostNumber", item["IP address"],
                                      item["hardwarePort"], item["device"])
# add entries from property number in computer name
        if not(self.computerNameDiskUtilityAssetTag == ""):
            self.populateDataFromLDAP("lanlPN", self.computerNameDiskUtilityAssetTag,
                                      "", "")
# add potenetial entries from computer name as hostname
        if not(self.computerNameDiskUtilityHostName == ""):
            self.populateDataFromLDAP("cn", self.computerNameDiskUtilityHostName,
                                      "", "")
        return success

    def report(self):
        self.messageReset()
        self.getComputerInfoCompliance()
        messagestring = "Determined Values:"
        self.messageAppend(messagestring)
        messagestring = "AssetTag=" + self.getSuggestedAssetTagConfidence() + ";"
        if not(self.assetTagAccuracyLevelWhy == "" ):
            messagestring = messagestring + " - " + self.assetTagAccuracyLevelWhy + ";"
        self.messageAppend(messagestring)
        messagestring = "Owner=" + self.getSuggestedEndUsernameConfidence() + ";"
        if not(self.endUserNameAccuracyLevelWhy == "" ):
            messagestring = messagestring + " - " + self.endUserNameAccuracyLevelWhy + ";"
        self.messageAppend(messagestring)
        messagestring = "ComputerName=" + self.getSuggestedComputerNameConfidence() + ";"
        messagestring = messagestring + " Hostname=" + self.getSuggestedHostNameConfidence() + ";"
        messagestring = messagestring + " LocalHostname=" + self.getSuggestedLocalHostNameConfidence() + ";"
        if not(self.computerNameAccuracyLevelWhy == "" ):
            messagestring = messagestring + " - " + self.computerNameAccuracyLevelWhy + ";"
        self.messageAppend(messagestring)
        messagestring = ""
        self.messageAppend(messagestring)
        self.reportAssetValues()
        messagestring = ""
        self.messageAppend(messagestring)
        self.reportLDAP()
        return self.messageGet()

    def reportAssetValues(self):
        '''
        report on asset values
        @author: ekkehard j. koch
        @param self:essential if you override this definition
        @return: string
        @note: None
        '''
        messagestring = "List Of Asset Values:"
        self.messageAppend(messagestring)
        messagestring = "macAddress=" + self.macAddress + ";"
        self.messageAppend(messagestring)
        messagestring = "ipAddress=" + self.ipAddress + ";"
        self.messageAppend(messagestring)
        messagestring = "ipAddressesActive=" + str(self.ipAddressActive) + ";"
        self.messageAppend(messagestring)
        messagestring = "LANLAssetTagNVRAM=" + self.getLANLAssetTagNVRAM() + ";"
        self.messageAppend(messagestring)
        messagestring = "LANLAssetTagFilesystem=" + self.getLANLAssetTagFilesystem() + ";"
        self.messageAppend(messagestring)
        return self.messageGet()

    def reportLDAP(self):
        '''
        report values availabel in the LDAP dictionary
        @author: ekkehard j. koch
        @param self:essential if you override this definition
        @return: real
        @note: None
        '''
        messagestring = "List Of LDAP Entries:"
        self.messageAppend(messagestring)
        self.gotoFirstItemLDAP()
        while not(self.getCurrentItemLDAP() == None):
            messagestring = " - macAddress=" + str(self.dictionaryItem["macAddress"]) + ";"
            messagestring = messagestring + " ipAddress=" + str(self.dictionaryItem["ipAddress"]) + ";"
            messagestring = messagestring + " hardwarePort=" + str(self.dictionaryItem["hardwarePort"]) + ";"
            messagestring = messagestring + " device=" + str(self.dictionaryItem["device"]) + ";"
            messagestring = messagestring + " ComputerName=" + str(self.dictionaryItem["ComputerName"]) + ";"
            messagestring = messagestring + " HostName=" + str(self.dictionaryItem["HostName"]) + ";"
            messagestring = messagestring + " LocalHostname=" + str(self.dictionaryItem["LocalHostname"]) + ";"
            messagestring = messagestring + " endUsername=" + str(self.dictionaryItem["endUsername"]) + ";"
            messagestring = messagestring + " assetTag=" + str(self.dictionaryItem["assetTag"]) + ";"
            self.messageAppend(messagestring)
            self.gotoNextItemLDAP()
        return self.messageGet()

    def updateComputerNameAccuracy(self, condition, point, message, reset=False):
        '''
        set ComputerName accuracy.
        @author: ekkehard j. koch
        @param self:essential if you override this definition
        @return: real
        @note: None
        '''
        if reset:
            self.computerNameAccuracyLevelWhy = ""
            self.computerNameAccuracyLevelTotal = 0
            self.computerNameAccuracyLevelMax = 0
            self.computerNameAccuracyLevel = 0
        if condition:
            self.computerNameAccuracyLevelTotal = self.computerNameAccuracyLevelTotal + point
        else:
            self.computerNameAccuracyLevelWhy = (self.computerNameAccuracyLevelWhy + " " + message).strip()
        self.computerNameAccuracyLevelMax = self.computerNameAccuracyLevelMax + point
        if self.computerNameAccuracyLevelMax > 0:
            percentagefloat = float(self.computerNameAccuracyLevelTotal) / float(self.computerNameAccuracyLevelMax)
            percentagefloat = percentagefloat * 100
            self.computerNameAccuracyLevel = int(percentagefloat)
        else:
            self.computerNameAccuracyLevel = 0
        return self.computerNameAccuracyLevel

    def updateAssetTagAccuracy(self, condition, point, message, reset=False):
        '''
        set assetTag accuracy.
        @author: ekkehard j. koch
        @param self:essential if you override this definition
        @return: real
        @note: None
        '''
        if reset:
            self.assetTagAccuracyLevelWhy = ""
            self.assetTagAccuracyLevelTotal = 0
            self.assetTagAccuracyLevelMax = 0
            self.assetTagAccuracyLevel = 0
        if condition:
            self.assetTagAccuracyLevelTotal = self.assetTagAccuracyLevelTotal + point
        else:
            self.assetTagAccuracyLevelWhy = (self.assetTagAccuracyLevelWhy + " " + message).strip()
        self.assetTagAccuracyLevelMax = self.assetTagAccuracyLevelMax + point
        if self.assetTagAccuracyLevelMax > 0:
            percentagefloat = float(self.assetTagAccuracyLevelTotal) / float(self.assetTagAccuracyLevelMax)
            percentagefloat = percentagefloat * 100.0
            self.assetTagAccuracyLevel = int(percentagefloat)
        else:
            self.assetTagAccuracyLevel = 0
        return self.assetTagAccuracyLevel

    def updateEndUserNameAccuracy(self, condition, point, message, reset=False):
        '''
        set EndUserName accuracy.
        @author: ekkehard j. koch
        @param self:essential if you override this definition
        @return: real
        @note: None
        '''
        if reset:
            self.endUserNameAccuracyLevelWhy = ""
            self.endUserNameAccuracyLevelTotal = 0
            self.endUserNameAccuracyLevelMax = 0
            self.endUserNameAccuracyLevel = 0
        if condition:
            self.endUserNameAccuracyLevelTotal = self.endUserNameAccuracyLevelTotal + point
        else:
            self.endUserNameAccuracyLevelWhy = (self.endUserNameAccuracyLevelWhy + " " + message).strip()
        self.endUserNameAccuracyLevelMax = self.endUserNameAccuracyLevelMax + point
        if self.endUserNameAccuracyLevelMax > 0:
            percentagefloat = float(self.endUserNameAccuracyLevelTotal) / float(self.endUserNameAccuracyLevelMax)
            percentagefloat = percentagefloat * 100.0
            self.endUserNameAccuracyLevel = int(percentagefloat)
        else:
            self.endUserNameAccuracyLevel = 0
        return self.endUserNameAccuracyLevel

    def messageGet(self):
        '''
        get the formatted message string.
        @author: ekkehard j. koch
        @param self:essential if you override this definition
        @return: string
        @note: None
        '''
        return self.messagestring

    def messageAppend(self, pMessage=""):
        '''
        append and format message to the message string.
        @author: ekkehard j. koch
        @param self:essential if you override this definition
        @return: boolean - true
        @note: None
        '''
        datatype = type(pMessage)
        if datatype == types.StringType:
            if not (pMessage == ""):
                messagestring = pMessage
                if (self.messagestring == ""):
                    self.messagestring = messagestring
                else:
                    self.messagestring = self.messagestring + "\n" + \
                    messagestring
        elif datatype == types.ListType:
            if not (pMessage == []):
                for item in pMessage:
                    messagestring = item
                    if (self.messagestring == ""):
                        self.messagestring = messagestring
                    else:
                        self.messagestring = self.messagestring + "\n" + \
                        messagestring
        else:
            raise TypeError("pMessage with value" + str(pMessage) + \
                            "is of type " + str(datatype) + " not of " + \
                            "type " + str(types.StringType) + \
                            " or type " + str(types.ListType) + \
                            " as expected!")
        return self.messagestring

    def messageReset(self):
        '''
        reset the message string.
        @author: ekkehard j. koch
        @param self:essential if you override this definition
        @return: boolean - true
        @note: none
        '''
        self.messagestring = ""
        return self.messagestring