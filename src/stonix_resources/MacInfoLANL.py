#!/usr/bin/python

'''
###############################################################################
#                                                                             #
# Copyright 2015-2016.  Los Alamos National Security, LLC. This material was  #
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
@change: 2015/09/22 ekkehard improve evaluation of file system asset tag
@change: 2015/10/05 ekkehard change to new jamf location
@change: 2015/11/05 ekkehard added imaged File system tag & getIPAddress
@change: 2015/12/14 ekkehard implemented lazy initialization
@change: 2016/01/19 ekkehard bug fixes
@change: 2016/01/26 ekkehard real bug fixes
@change: 2016/01/26 ekkehard add property database lookup
@change: 2016/08/05 ekkehard improve setComputerInfo with /usr/local/bin/jamf setComputerName -name "computerName"
@change: 2016/08/05 ekkehard add setInternalComputerName
@change: 2016/08/11 ekkehard bug fixes
@change: 2016/08/16 ekkehard bug fixes
@change: 2016/08/19 ekkehard self.lanl_property_web_service updated to csd-web
'''
import os
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

    def __init__(self, logdispatcher):
        '''
        initialize lanlMacInfo
        @author: ekkehard
        '''
        self.logpriority="debug"
        self.logsyslog_level=None
# Make sure we have the full path for all commands
        self.logdispatch = logdispatcher
        self.ch = CommandHelper(self.logdispatch)
        self.LANLAssetTagFromProperty = ""
        self.LANLAssetTagNVRAM = ""
        self.LANLAssetTagFilesystem = ""
        self.macAddressDictionary = {}
        self.accuracyDictionary = {}
        self.dictionary = {}
        self.dictionaryItem = None
        self.dictionaryWeight = 100
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
        self.computerNameDiskUtilityAssetTag = ""
        self.endUsername = ""
        self.assetTag = ""
        self.macAddress = ""
        self.ipAddress = ""
        self.ipAddressActive = []
        self.ldapnotworking = False
        self.serialnumber = ""
# Set all initialization boolean
        self.initializeLANLAssetTagFromPropertyBoolean = False
        self.initializeLANLAssetTagNVRAMBoolean = False
        self.initializeLANLAssetTagFilesystemBoolean = False
        self.initializeLANLImagedFilesystemBoolean = False
        self.initializeDiskUtilityInfoBoolean = False
        self.initializePopulateFromMacBoolean = False
        self.initializeAccuracyDeterminationBoolean = False
# Make sure we have the full path for all commands
        jamflocation = "/usr/local/bin/jamf"
        if not os.path.exists(jamflocation):
            jamflocation = "/usr/sbin/jamf"
        self.jamf = jamflocation
        self.ns = "/usr/sbin/networksetup"
        self.scutil = "/usr/sbin/scutil"
        self.jamf = jamflocation
        self.nvram = "/usr/sbin/nvram"
        self.ldap = "/usr/bin/ldapsearch"
        self.lanl_property_file = "/Library/Preferences/gov.lanl.asset.tag.txt"
        self.lanl_property_file_old = "/Library/Preferences/lanl_property_number.txt"
        self.lanl_imaged_files = ["/etc/dds.txt", "/var/log/dds.log"]
        self.lanl_property_web_service = "https://csd-web.lanl.gov/public/getPropertyNumber.php?serial"
# Reset messages
        self.messageReset()
# Initialize Accuracy stuff
        self.updateAssetTagAccuracy(True, 0, "", True)
        self.updateEndUserNameAccuracy(True, 0, "", True)
        self.updateComputerNameAccuracy(True, 0, "", True)
    
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

    def getNumberOfLDAPEntries(self):
        '''
        get current number of items in the LDAP dictionary
        @author: ekkehard
        @return: dictionary entry
        '''
        return len(self.dictionary.keys())

    def getComputerInfoCompliance(self):
        '''
        see if all is set correctly
        @author: ekkehard
        @return: boolean - True of False
        '''
        self.initializeDiskUtilityInfo()
        self.initializePopulateFromMac()
        self.initializeAccuracyDetermination()
        success = True
        compliant = True
# Check computername
        msg = "ComputerName Confidence level of " + \
        str(self.getSuggestedComputerNameConfidenceOnly()) + "%"
        if not(self.getSuggestedComputerNameConfidenceOnly() == 100):
            compliant = False
            msg = msg + " is less than 100%"
        msg = msg + "; ComputerName (" + \
        self.getDiskUtilityComputerName() + ") and proposed ComputerName (" + \
        self.getSuggestedComputerName() + ")"
        if not(self.getDiskUtilityComputerName() == self.getSuggestedComputerName()):
            compliant = False
            msg = msg + " are not equal;"
        else:
            msg = msg + " are equal;"
        if not compliant:
            msg = "- Not compliant; " + msg
            if not(self.computerNameAccuracyLevelWhy == "" ):
                msg = msg + " - " + self.computerNameAccuracyLevelWhy
            success = False
        else:
            msg = "- compliant; " + msg
        self.messageAppend(msg)
# Check hostname
        compliant = True
        msg = "HostName confidence level of " + \
        str(self.getSuggestedComputerNameConfidenceOnly()) + "%"
        if not(self.getSuggestedComputerNameConfidenceOnly() == 100):
            compliant = False
            msg = msg + " is less than 100%"
        msg = msg + "; HostName (" + \
        self.getDiskUtilityHostName() + ") and proposed HostName (" + \
        self.getSuggestedHostName() + ")"
        if not(self.getDiskUtilityHostName() == self.getSuggestedHostName()):
            compliant = False
            msg = msg + " are not equal;"
        else:
            msg = msg + " are equal;"
        if not compliant:
            msg = "- Not compliant; " + msg
            if not(self.computerNameAccuracyLevelWhy == "" ):
                msg = msg + " - " + self.computerNameAccuracyLevelWhy
            success = False
        else:
            msg = "- compliant; " + msg
        self.messageAppend(msg)
# Check localhostname
        compliant = True
        msg = "LocalHostName confidence level of " + \
        str(self.getSuggestedComputerNameConfidenceOnly()) + "%"
        if not(self.getSuggestedComputerNameConfidenceOnly() == 100):
            compliant = False
            msg = msg + " is less than 100%"
        msg = msg + "; LocalHostName (" + \
        self.getDiskUtilityLocalHostName() + ") and proposed LocalHostName (" + \
        self.getSuggestedLocalHostName() + ")"
        if not(self.getDiskUtilityLocalHostName() == self.getSuggestedLocalHostName()):
            compliant = False
            msg = msg + " are not equal;"
        else:
            msg = msg + " are equal;"
        if not compliant:
            msg = "- Not compliant; " + msg
            if not(self.computerNameAccuracyLevelWhy == "" ):
                msg = msg + " - " + self.computerNameAccuracyLevelWhy
            success = False
        else:
            msg = "- compliant; " + msg
        self.messageAppend(msg)
        return success

    def getDiskUtilityComputerName(self):
        '''
        get the ComputerName determined by disk utility
        @author: ekkehard
        @return: string
        '''
        self.initializeDiskUtilityInfo()
        return self.computerNameDiskUtility

    def getDiskUtilityHostName(self):
        '''
        get the HostName determined by disk utility
        @author: ekkehard
        @return: string
        '''
        self.initializeDiskUtilityInfo()
        return self.hostNameDiskUtility

    def getDiskUtilityLocalHostName(self):
        '''
        get the LocalHostName determined by disk utility
        @author: ekkehard
        @return: string
        '''
        self.initializeDiskUtilityInfo()
        return self.localHostnameDiskUtility

    def getIPAddress(self):
        '''
        get the IPAddress
        @author: ekkehard
        @return: string
        '''
        self.initializePopulateFromMac()
        return self.ipAddress

    def getLANLAssetTagFromProperty(self):
        '''
        get the AssetTag from the LANL property Database
        @author: ekkehard
        @return: string
        '''
        self.initializeLANLAssetTagFromProperty()
        return str(self.LANLAssetTagFromProperty)

    def getLANLAssetTagNVRAM(self):
        '''
        get the asset_id set in NVRAM determined
        @author: ekkehard
        @return: string
        '''
        self.initializeLANLAssetTagNVRAM()
        return str(self.LANLAssetTagNVRAM)

    def getLANLAssetTagFilesystem(self):
        '''
        get the asset_id set in file system
        @author: ekkehard
        @return: string
        '''
        self.initializeLANLAssetTagFilesystem()
        return str(self.LANLAssetTagFilesystem)

    def getLANLImagedFilesystem(self):
        '''
        get the imaged set in file system
        @author: ekkehard
        @return: string
        '''
        self.initializeLANLImagedFilesystem()
        return str(self.LANLImaged)

    def getSerialNumber(self):
        '''
        get the serialnumber
        @author: ekkehard
        @return: string
        '''
        self.initializeLANLAssetTagFromProperty()
        return str(self.serialnumber)

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
        self.initializeLANLAssetTagNVRAM()
        self.initializeLANLAssetTagFilesystem()
        self.initializeDiskUtilityInfo()
        self.initializePopulateFromMac()
        self.initializeAccuracyDetermination()
        displayValue = str(self.getSuggestedAssetTag()) + " (" + str(self.assetTagAccuracyLevel) + "%)"
        return displayValue
    
    def getSuggestedAssetTagConfidenceOnly(self):
        '''
        get the suggested asset_id confidence level
        @author: ekkehard
        @return: real
        '''
        self.initializeLANLAssetTagNVRAM()
        self.initializeLANLAssetTagFilesystem()
        self.initializeDiskUtilityInfo()
        self.initializePopulateFromMac()
        self.initializeAccuracyDetermination()
        return self.assetTagAccuracyLevel

    def getSuggestedComputerName(self):
        '''
        get the suggested ComputerName
        @author: ekkehard
        @return: string
        '''
        self.initializeLANLAssetTagNVRAM()
        self.initializeLANLAssetTagFilesystem()
        self.initializeDiskUtilityInfo()
        self.initializePopulateFromMac()
        self.initializeAccuracyDetermination()
        if self.computerName == "":
            self.computerName = self.getDiskUtilityComputerName()
        return self.computerName
    
    def getSuggestedComputerNameConfidence(self):
        '''
        get the suggested ComputerName and ComputerName confidence level
        @author: ekkehard
        @return: string
        '''
        self.initializeLANLAssetTagNVRAM()
        self.initializeLANLAssetTagFilesystem()
        self.initializeDiskUtilityInfo()
        self.initializePopulateFromMac()
        self.initializeAccuracyDetermination()
        displayValue = str(self.getSuggestedComputerName()) + " (" + str(self.computerNameAccuracyLevel) + "%)"
        return displayValue
    
    def getSuggestedComputerNameConfidenceOnly(self):
        '''
        get the suggested ComputerName confidence level
        @author: ekkehard
        @return: real
        '''
        self.initializeLANLAssetTagNVRAM()
        self.initializeLANLAssetTagFilesystem()
        self.initializeDiskUtilityInfo()
        self.initializePopulateFromMac()
        self.initializeAccuracyDetermination()
        return self.computerNameAccuracyLevel

    def getSuggestedHostName(self):
        '''
        get the suggested HostName
        @author: ekkehard
        @return: string
        '''
        self.initializeLANLAssetTagNVRAM()
        self.initializeLANLAssetTagFilesystem()
        self.initializeDiskUtilityInfo()
        self.initializePopulateFromMac()
        self.initializeAccuracyDetermination()
        return self.hostName
    
    def getSuggestedHostNameConfidence(self):
        '''
        get the suggested HostName and HostName confidence level
        @author: ekkehard
        @return: string
        '''
        self.initializeLANLAssetTagNVRAM()
        self.initializeLANLAssetTagFilesystem()
        self.initializeDiskUtilityInfo()
        self.initializePopulateFromMac()
        self.initializeAccuracyDetermination()
        displayValue = str(self.hostName) + " (" + str(self.computerNameAccuracyLevel) + "%)"
        return displayValue
    
    def getSuggestedHostNameConfidenceOnly(self):
        '''
        get the suggested HostName confidence level
        @author: ekkehard
        @return: real
        '''
        self.initializeLANLAssetTagNVRAM()
        self.initializeLANLAssetTagFilesystem()
        self.initializeDiskUtilityInfo()
        self.initializePopulateFromMac()
        self.initializeAccuracyDetermination()
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
        self.initializeLANLAssetTagNVRAM()
        self.initializeLANLAssetTagFilesystem()
        self.initializeDiskUtilityInfo()
        self.initializePopulateFromMac()
        self.initializeAccuracyDetermination()
        displayValue = str(self.localHostname) + " (" + str(self.computerNameAccuracyLevel) + "%)"
        return displayValue
    
    def getSuggestedLocalHostNameConfidenceOnly(self):
        '''
        get the suggested LocalHostName confidence level
        @author: ekkehard
        @return: real
        '''
        self.initializeLANLAssetTagNVRAM()
        self.initializeLANLAssetTagFilesystem()
        self.initializeDiskUtilityInfo()
        self.initializePopulateFromMac()
        self.initializeAccuracyDetermination()
        return self.computerNameAccuracyLevel

    def getSuggestedEndUsername(self):
        '''
        get the suggested EndUserName or Owner
        @author: ekkehard
        @return: string
        '''
        self.initializeLANLAssetTagNVRAM()
        self.initializeLANLAssetTagFilesystem()
        self.initializeDiskUtilityInfo()
        self.initializePopulateFromMac()
        self.initializeAccuracyDetermination()
        return self.endUsername
    
    def getSuggestedEndUsernameConfidence(self):
        '''
        get the suggested EndUserName or Owner and EndUserName or Owner confidence level
        @author: ekkehard
        @return: string
        '''
        self.initializeLANLAssetTagNVRAM()
        self.initializeLANLAssetTagFilesystem()
        self.initializeDiskUtilityInfo()
        self.initializePopulateFromMac()
        self.initializeAccuracyDetermination()
        displayValue = str(self.endUsername) + " (" + str(self.endUserNameAccuracyLevel) + "%)"
        return displayValue
    
    def getSuggestedEndUsernameConfidenceOnly(self):
        '''
        get the suggested EndUserName or Owner confidence level
        @author: ekkehard
        @return: real
        '''
        self.initializeLANLAssetTagNVRAM()
        self.initializeLANLAssetTagFilesystem()
        self.initializeDiskUtilityInfo()
        self.initializePopulateFromMac()
        self.initializeAccuracyDetermination()
        return self.endUserNameAccuracyLevel

    def setComputerInfo(self):
        '''
        set the computer info on the computer
        @author: ekkehard
        @return: boolean - True
        '''
        try:
            success = True
            errorcode = None
            output = None
            updatesWhereMade = False
            output = []
            computerName = self.getSuggestedComputerName()
            hostname = self.getSuggestedHostName()
            localHostName = self.getSuggestedLocalHostName()
            if self.computerNameAccuracyLevel == 100:
                if os.path.exists(self.jamf):
                    if not(self.computerNameDiskUtility == computerName) \
                    or not(self.hostNameDiskUtility == hostname) \
                    or not(self.localHostnameDiskUtility == localHostName):
                        command = [self.jamf,"setComputerName", "-name", computerName]
                        self.ch.executeCommand(command)
                        errorcode = self.ch.getError()
                        output = self.ch.getOutput()
                        updatesWhereMade = True
                        msg = " - ComputerName, HostName, and LocalHostName set to [" +\
                        computerName + ", " + hostname + ", " + localHostName + "]"
                        self.messageAppend(msg)
                    else:
                        msg = " - ComputerName, HostName, and LocalHostName were already set to [" +\
                        computerName + ", " + hostname + ", " + localHostName + "]"
                        self.messageAppend(msg)
                else:
                    if not(self.computerNameDiskUtility == computerName):
                        command = [self.scutil,"--set", "ComputerName", computerName]
                        self.ch.executeCommand(command)
                        errorcode = self.ch.getError()
                        output = self.ch.getOutput()
                        updatesWhereMade = True
                        msg = " - ComputerName set to " + computerName
                        self.messageAppend(msg)
                    else:
                        msg = " - ComputerName was alreday " + computerName
                        self.messageAppend(msg)
                    if not(self.hostNameDiskUtility == hostname):
                        command = [self.scutil,"--set", "HostName", hostname]
                        self.ch.executeCommand(command)
                        errorcode = self.ch.getError()
                        output = self.ch.getOutput()
                        updatesWhereMade = True
                        msg = " - HostName set to " + hostname
                        self.messageAppend(msg)
                    else:
                        msg = " - HostName was alreday " + hostname
                        self.messageAppend(msg)
                if not(self.localHostnameDiskUtility == localHostName):
                    command = [self.scutil,"--set", "LocalHostName", localHostName]
                    errorcode = self.ch.getError()
                    self.ch.executeCommand(command)
                    output = self.ch.getOutput()
                    updatesWhereMade = True
                    msg = " - LocalHostName set to " + localHostName
                    self.messageAppend(msg)
                else:
                    msg = " - LocalHostName was alreday " + localHostName
                    self.messageAppend(msg)
        except(KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            msg = traceback.format_exc() + " - " + str(errorcode) + " - " + str(output)
            self.logdispatch.log(LogPriority.ERROR, msg)
        if updatesWhereMade == True:
            self.initializeDiskUtilityInfo(True)
        return success

<<<<<<< HEAD
    def setInternalPropertyNumber(self, propertyNumber=False):
=======
    def setInternalComputerName(self, computerName=""):
        '''
        set the internal computerName, hostName and localHostName, as well as confidence at 100%
        @param: computerName - FQDN
        @author: ekkehard
        '''
        success = False
        #####
# Make sure this is a stripped string
        computerName = str(computerName).strip()
# Validate that this is FQDN
        if re.match("(?=^.{1,254}$)(^(?:(?!\d+\.|-)[a-zA-Z0-9_\-]{1,63}(?<!-)\.)+(?:[a-zA-Z]{2,})$)",\
                    computerName):
            computerNameList = computerName.split(".")
            self.computerName = computerName
            self.hostName = computerName
            self.localHostname = computerNameList[0]
            self.updateComputerNameAccuracy(True, 100, "", True)
            success = True
            self.initializePopulateFromMacBoolean = success
            self.initializeAccuracyDeterminationBoolean = success
        return success

    def setInternalPropertyNumber(self, propertyNumber=""):
>>>>>>> lanl-stonix-0.9.13
        '''
        set the internal class property number, as well as confidence at 100%
        @param: propertyNumber - seven digit property number
        @author: Roy Nielsen
        '''
        success = False
        #####
        # Perform input validation before setting the internal variable.
        if re.match("^\d\d\d\d\d\d\d$", str(propertyNumber).strip()):
            self.assetTag = str(propertyNumber).strip()
<<<<<<< HEAD
            self.assetTagAccuracyLevel = 100
            success = True
=======
            self.updateAssetTagAccuracy(True, 100, "", True)
            success = True
            self.initializePopulateFromMacBoolean = success
            self.initializeAccuracyDeterminationBoolean = success
>>>>>>> lanl-stonix-0.9.13
        return success

    def setJAMFInfo(self):
        '''
        set the assetTag and endUserName via the jamf recon command
        @author: ekkehard
        @return: boolean - True
        '''
        try:
            success = True
            errorcode = None
            output = None
            assetTag = self.getSuggestedAssetTag()
            endUser = self.getSuggestedEndUsername()
            if self.assetTagAccuracyLevel == 100 and self.endUserNameAccuracyLevel == 100:
                command = [self.jamf, "recon",
                           "-assetTag", assetTag,
                           "-endUsername", endUser]
                self.ch.executeCommand(command)
                errorcode = self.ch.getError()
                output = self.ch.getOutput()
                msg = " - JAMF assetTag set to " + assetTag + " and endUsername set to " + endUser
                self.messageAppend(msg)
            elif self.assetTagAccuracyLevel == 100:
                command = [self.jamf, "recon", "-assetTag", assetTag]
                self.ch.executeCommand(command)
                errorcode = self.ch.getError()
                output = self.ch.getOutput()
                endUser = ""
                msg = " - JAMF assetTag set to " + assetTag
                self.messageAppend(msg)
            elif self.endUserNameAccuracyLevel == 100:
                command = [self.jamf, "recon", "-endUsername", endUser]
                self.ch.executeCommand(command)
                errorcode = self.ch.getError()
                output = self.ch.getOutput()
                assetTag = ""
                msg = " - JAMF endUsername set to " + endUser
                self.messageAppend(msg)
            else:
                success = False
                msg = " - JAMF settings were not changed because confidence was only " + \
                str(self.assetTagAccuracyLevel) + "%"
                self.messageAppend(msg)
        except(KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            msg = traceback.format_exc() + " - " + str(errorcode) + " - " + str(output)
            self.logdispatch.log(LogPriority.ERROR, msg)
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
                    self.initializeLANLAssetTagNVRAM(True)
                    msg = " - NVRAM asset_id set to " + assetTag
                    self.messageAppend(msg)
                else:
                    msg = " - NVRAM asset_id was already set to " + assetTag
                    self.messageAppend(msg)
            else:
                assetTag = ""
                msg = " - NVRAM asset_id was not changed because confidence was only " + \
                str(self.assetTagAccuracyLevel) + "%"
                self.messageAppend(msg)
        except(KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            msg = traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, msg)
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
                        self.initializeLANLAssetTagFilesystem(True)
                        assetTag = self.getLANLAssetTagFilesystem()
                    except Exception, err :
                        msg = "Problem writing: " + self.lanl_property_file + \
                        " error: " + str(err)
                        self.logdispatch.log(LogPriority.ERROR, msg)
            else:
                assetTag = ""
                msg = " - Filesystem asset_id was not changed because confidence was only " + \
                str(self.assetTagAccuracyLevel) + "%"
                self.messageAppend(msg)
        except(KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            msg = traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, msg)
        return assetTag

    def setLANLImagedFilesystem(self, imagedString = ""):
        '''
        set the imaged on the file system
        @author: ekkehard
        @return: boolean - True
        '''
        try:
            imaged = imagedString
            oldimaged = self.getLANLImagedFilesystem()
            if not(oldimaged == imaged):
                for myfile in self.lanl_imaged_files:
                    try :
                        filepointer = open(myfile, "w")
                        filepointer.write(imaged)
                        filepointer.close()
                        msg = str(oldimaged) + " was replaced with " + str(imaged) + " in file " + str(myfile)
                        self.logdispatch.log(LogPriority.DEBUG, msg)
                    except Exception, err :
                        msg = "Problem writing: " + str(imaged) + " into " + str(myfile) + \
                        " error: " + str(err)
                        self.logdispatch.log(LogPriority.ERROR, msg)
                self.initializeLANLImagedFilesystem(True)
                imaged = self.getLANLImagedFilesystem()
            else:
                imaged = self.getLANLImagedFilesystem()
                msg = " - Filesystem imaged was not changed because it already was set to " + \
                str(imaged) + "!"
                self.messageAppend(msg)
        except(KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            msg = traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, msg)
        return imaged

    def initializeAccuracyDetermination(self, forceInitializtion = False):
        '''
        go through all our data and see how good it is
        @author: ekkehard
        @return: boolean - True
        '''
        if forceInitializtion:
            self.initializeAccuracyDeterminationBoolean = False
        if not self.initializeAccuracyDeterminationBoolean:
            self.initializeAccuracyDeterminationBoolean = True
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
# AssetTag for property database not equal to blank is worth 10000
            if not(self.getLANLAssetTagFromProperty() == ""):
                self.updateAssetTagAccuracy(self.getLANLAssetTagFromProperty() <> "",
                                                10000, "LANLAssetTagFromProperty is blank;")
            self.gotoFirstItemLDAP()
# Build a dictionary based upon assetTag. If all is right there should only be one.
            while not(self.getCurrentItemLDAP() == None):
                if self.dictionaryItem["Weight"] >= self.dictionaryWeight:
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
                elif not(self.getLANLAssetTagNVRAM() == "") and not(self.getLANLAssetTagFilesystem() == ""):
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
        item = {"Tag": "",
                "Weight": 100,
                "hardwarePort": "",
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

    def initializeLANLAssetTagFilesystem(self, forceInitializtion = False):
        '''
        get assetTag from the file system
        @author: ekkehard
        @return: string
        '''
        if forceInitializtion:
            self.initializeLANLAssetTagFilesystemBoolean = False
        if not self.initializeLANLAssetTagFilesystemBoolean:
            self.initializeLANLAssetTagFilesystemBoolean = True
            self.LANLAssetTagFilesystem = ""
            if os.path.exists(self.lanl_property_file_old):
                os.rename(self.lanl_property_file_old, self.lanl_property_file)
            if os.path.exists(self.lanl_property_file):
                try:
                    fileToOpen = open(self.lanl_property_file, "r")
                except Exception, err:
                    msg = "Cannot open: " + self.lanl_property_file + \
                        "\nException: " + str(err)
                    self.logdispatch.log(LogPriority.DEBUG, msg)
                else:
                    try:
                        for line in fileToOpen:
                            if re.match("[0-9]+", line.strip()):
                                self.LANLAssetTagFilesystem = line.strip()
                                msg = self.lanl_property_file + \
                                " property number = " + self.LANLAssetTagFilesystem
                                self.logdispatch.log(LogPriority.DEBUG, msg)
                                break
                            else :
                                self.LANLAssetTagFilesystem = ""
                    except Exception, err:
                        msg = str(err) + " - Can't find a line in the file: " + \
                        self.LANLAssetTagFilesystem
                        self.logdispatch.log(LogPriority.DEBUG, msg)
                        self.LANLAssetTagFilesystem = ""
                    else:
                        fileToOpen.close()
        return self.LANLAssetTagFilesystem

    def initializeLANLAssetTagNVRAM(self, forceInitializtion = False):
        '''
        get assetTag from NVRAM
        @author: ekkehard
        @return: boolean - True
        '''
        success = True
        try:
            if forceInitializtion:
                self.initializeLANLAssetTagNVRAMBoolean = False
            if not self.initializeLANLAssetTagNVRAMBoolean:
                self.initializeLANLAssetTagNVRAMBoolean = True
                self.LANLAssetTagNVRAM = ""
                command = [self.nvram, "asset_id"]
                self.ch.executeCommand(command)
                output = self.ch.getOutput()
                if len(output) >= 1:
                    self.LANLAssetTagNVRAM = str(output[-1].strip().split("\t")[1])
                else:
                    self.LANLAssetTagNVRAM = ""
            else:
                success = True
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            msg = traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, msg)
        return success

    def initializeLANLAssetTagFromProperty(self, forceInitializtion = False):
        '''
        get assetTag from Property Database
        @author: ekkehard
        @return: boolean - True
        '''
        success = True
        try:
            if forceInitializtion:
                self.initializeLANLAssetTagFromPropertyBoolean = False
            if not self.initializeLANLAssetTagFromPropertyBoolean:
                self.initializeLANLAssetTagFromPropertyBoolean = True
                self.LANLLANLAssetTagFromProperty = ""
                self.serialnumber = ''
                command = "/usr/sbin/system_profiler SPHardwareDataType | awk '/Serial/ {print $4}'"
                self.ch.executeCommand(command)
                errorcode = self.ch.getError()
                output = self.ch.getOutput()
                msg = "Error:" + str(errorcode) + "; output:" + str(output) + "; command:" + str(command)
                self.logdispatch.log(LogPriority.DEBUG, msg)
                if len(output) >= 1:
                    self.serialnumber = output[0].strip()
                if self.serialnumber <> "":
                    command = "/usr/bin/curl " + self.lanl_property_web_service + "=" + str(self.serialnumber)
                    self.ch.executeCommand(command)
                    errorcode = self.ch.getError()
                    output = self.ch.getOutput()
                    if len(output) >= 1:
                        self.LANLAssetTagFromProperty = output[0].strip()
            else:
                success = True
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            msg = traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, msg)
        return success
            

    def initializeLANLImagedFilesystem(self, forceInitializtion = False):
        '''
        get imaged info from the file system
        @author: ekkehard
        @return: string
        '''
        if forceInitializtion:
            self.initializeLANLImagedFilesystemBoolean = False
        if not self.initializeLANLImagedFilesystemBoolean:
            self.initializeLANLImagedFilesystemBoolean = True
            self.LANLImaged = "Not LANL Configured"   
            for myfile in self.lanl_imaged_files:
            
                try:
                    fileToOpen = open(myfile, "r")
                except Exception, err:
                    msg = "Cannot open: " + myfile + \
                        " - Exception: " + str(err)
                    self.logdispatch.log(LogPriority.DEBUG, msg)
                else:
                    try :
                        for line in fileToOpen:
                            if re.match("^Imaged", line.strip()):
                                self.LANLImaged = line.strip()
                                break                            
                    except Exception, err:
                        msg = "Can't find a line in the file to grep in "+ myfile + \
                            " - Exception: " + str(err)
                        self.logdispatch.log(LogPriority.DEBUG, msg)
                    else:
                        fileToOpen.close()
        return self.LANLImaged

    def initializeDiskUtilityInfo(self, forceInitializtion = False):
        '''
        get ComputerName, HostName, LocalHostName of the current computer
        @author: ekkehard
        @return: boolean - True
        '''
        success = True
        if forceInitializtion:
            self.initializeDiskUtilityInfoBoolean = False
        if not self.initializeDiskUtilityInfoBoolean:
            self.initializeDiskUtilityInfoBoolean = True
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
                msg = traceback.format_exc()
                self.logdispatch.log(LogPriority.ERROR, msg)
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
                msg = traceback.format_exc()
                self.logdispatch.log(LogPriority.ERROR, msg)
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
                msg = traceback.format_exc() + " - " + str(errorcode) + " - " + str(output)
                self.logdispatch.log(LogPriority.ERROR, msg)
        return success
    
    def initializePopulateFromMac(self, forceInitializtion = False):
        '''
        get network data from the local machine
        @author: ekkehard j. koch
        @param self:essential if you override this definition
        @return: boolean - true
        @note: None
        '''
        success = True
        if forceInitializtion:
            self.initializePopulateFromMacBoolean = False
        if not self.initializePopulateFromMacBoolean:
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
                msg = str(err) + " - " + str(traceback.format_exc())
                self.logdispatch.log(LogPriority.ERROR, msg)
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
# Make sure you are only searching for valid macAddress
                if not(item["macAddress"] == "00:00:00:00:00:00"):
                    self.populateDataFromLDAP("macAddress", 100, "macAddress", item["macAddress"],
                                              item["hardwarePort"], item["device"])
                else:
                    msg = "Invalid macAddress item['macAddress'] = " + \
                    str(item["macAddress"])
                    self.logdispatch.log(LogPriority.DEBUG, msg)
# Make sure you are only searching for valid IP address
                if not(item["IP address"] == "") and not(item["IP address"] == "0.0.0.0"):
                    if not(item["IP address"] in self.ipAddressActive):
                        self.ipAddressActive.append(item["IP address"])
                    self.populateDataFromLDAP("IP", 100, "ipHostNumber", item["IP address"],
                                          item["hardwarePort"], item["device"])
                else:
                    msg = "Invalid IP address item['IP address'] = " + \
                    str(item["IP address"])
                    self.logdispatch.log(LogPriority.DEBUG, msg)
# add entries from property number in computer name
            if not(self.computerNameDiskUtilityAssetTag == "") and not(int(self.computerNameDiskUtilityAssetTag) == 0):
                self.populateDataFromLDAP("ComputerName", 100, "lanlPN", self.computerNameDiskUtilityAssetTag,
                                          "", "")
            else:
                msg = "Invalid Asset Tag computerNameDiskUtitilyAssetTag = " + \
                str(self.computerNameDiskUtilityAssetTag)
                self.logdispatch.log(LogPriority.DEBUG, msg)
# add potenetial entries from computer name as hostname
            if not(self.computerNameDiskUtilityHostName == ""):
                self.populateDataFromLDAP("ComputerName", 100, "cn", self.computerNameDiskUtilityHostName,
                                          "", "")
# add entries from property number in LANLAssetTagNVRAM
            if not(self.getLANLAssetTagNVRAM() == "")  and not(int(self.getLANLAssetTagNVRAM()) == 0):
                if self.getNumberOfLDAPEntries() > 0:
                    weight = 0
                else:
                    weight = 100
                self.populateDataFromLDAP("NVRAM", weight, "lanlPN", self.getLANLAssetTagNVRAM(),
                                          "", "")
# add entries from property number in LANLAssetTagNVRAM
            if not(self.getLANLAssetTagFilesystem() == "") and not(int(self.getLANLAssetTagFilesystem()) == 0):
                if self.getNumberOfLDAPEntries() > 0:
                    weight = 0
                else:
                    weight = 100
                self.populateDataFromLDAP("Filesystem", weight, "lanlPN", self.getLANLAssetTagFilesystem(),
                                          "", "")
            else:
                msg = "Invalid Asset Tag getLANLAssetTagFilesystem = " + \
                str(self.getLANLAssetTagFilesystem())
                self.logdispatch.log(LogPriority.DEBUG, msg)
            self.initializePopulateFromMacBoolean = True
        return success

    def populateDataFromLDAP(self, tag, weightValue, addressType, address, hardwarePort, device,
                             forceInitializtion = False):
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
            if self.ldapnotworking:
                output = []
            else:
                command = [self.ldap,
                           "-x",
                           "-h",
                           "ldap.lanl.gov",
                           "-b",
                           "dc=lanl,dc=gov",
                           addressType + "=" + address]
                self.ch.executeCommand(command)
                output = self.ch.getOutput()
                returncode = self.ch.returncode
                if returncode == 0:
                    self.ldapnotworking = False
                else:
                    self.ldapnotworking = True
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
                            self.dictionaryItem["Tag"] = tag
                            self.dictionaryItem["Weight"] = weightValue
                            self.dictionaryItem["searchTerm"] = addressType + "=" + address
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
                    msg = str(err) + " - " + str(traceback.format_exc())
                    self.logdispatch.log(LogPriority.ERROR, msg)
                    continue
            if not(assetTag == ""):
                self.entries = self.entries + 1
                self.initializeDictionaryItemLDAP(self.entries)
                self.dictionaryItem["Tag"] = tag
                self.dictionaryItem["Weight"] = weightValue
                self.dictionaryItem["searchTerm"] = addressType + "=" + address
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
            msg = traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, msg)
        return success

    def report(self):
        self.initializeLANLAssetTagNVRAM()
        self.initializeLANLAssetTagFilesystem()
        self.initializeLANLAssetTagFromProperty()
        self.initializeDiskUtilityInfo()
        self.initializePopulateFromMac()
        self.initializeAccuracyDetermination()
        self.messageReset()
        self.getComputerInfoCompliance()
        msg = "Determined Values:"
        self.messageAppend(msg)
        msg = "AssetTag=" + self.getSuggestedAssetTagConfidence() + ";"
        if not(self.assetTagAccuracyLevelWhy == "" ):
            msg = msg + " - " + self.assetTagAccuracyLevelWhy
        self.messageAppend(msg)
        msg = "Imaged=" + self.getLANLImagedFilesystem()+ ";"
        self.messageAppend(msg)
        msg = "Owner=" + self.getSuggestedEndUsernameConfidence() + ";"
        if not(self.endUserNameAccuracyLevelWhy == "" ):
            msg = msg + " - " + self.endUserNameAccuracyLevelWhy
        self.messageAppend(msg)
        msg = "ComputerName=" + self.getSuggestedComputerNameConfidence() + ";"
        msg = msg + " Hostname=" + self.getSuggestedHostNameConfidence() + ";"
        msg = msg + " LocalHostname=" + self.getSuggestedLocalHostNameConfidence() + ";"
        if not(self.computerNameAccuracyLevelWhy == "" ):
            msg = msg + " - " + self.computerNameAccuracyLevelWhy
        self.messageAppend(msg)
        msg = ""
        self.messageAppend(msg)
        self.reportAssetValues()
        msg = ""
        self.messageAppend(msg)
        self.reportLDAP()
        self.reportProperty()
        return self.messageGet()

    def reportAssetValues(self):
        '''
        report on asset values
        @author: ekkehard j. koch
        @param self:essential if you override this definition
        @return: string
        @note: None
        '''
        self.initializeLANLAssetTagNVRAM()
        self.initializeLANLAssetTagFilesystem()
        self.initializeDiskUtilityInfo()
        self.initializePopulateFromMac()
        self.initializeAccuracyDetermination()
        msg = "List Of Asset Values:"
        self.messageAppend(msg)
        msg = "macAddress=" + str(self.macAddress) + ";"
        self.messageAppend(msg)
        msg = "ipAddressesActive=" + str(self.ipAddress) + \
        "; ipAddressesActive=" + str(self.ipAddressActive) + ";"
        self.messageAppend(msg)
        msg = "LANLAssetTagNVRAM=" + self.getLANLAssetTagNVRAM() + ";"
        self.messageAppend(msg)
        msg = "LANLAssetTagFilesystem=" + self.getLANLAssetTagFilesystem() + ";"
        self.messageAppend(msg)
        msg = "LANLAssetTagFromProperty=" + self.getLANLAssetTagFromProperty() + ";"
        self.messageAppend(msg)
        return self.messageGet()

    def reportLDAP(self):
        '''
        report values availabel in the LDAP dictionary
        @author: ekkehard j. koch
        @param self:essential if you override this definition
        @return: real
        @note: None
        '''
        self.initializeLANLAssetTagNVRAM()
        self.initializeLANLAssetTagFilesystem()
        self.initializeDiskUtilityInfo()
        self.initializePopulateFromMac()
        self.initializeAccuracyDetermination()
        msg = "List Of LDAP Entries:"
        self.messageAppend(msg)
        self.gotoFirstItemLDAP()
        while not(self.getCurrentItemLDAP() == None):
            msg = " - Tag=" + str(self.dictionaryItem["Tag"]) + ";"
            msg = msg + " weight=" + str(self.dictionaryItem["Weight"]) + ";"
            msg = msg + " searchTerm='" + str(self.dictionaryItem["searchTerm"]) + "';"
            if not(self.dictionaryItem["assetTag"] == ""):
                msg = msg + " assetTag=" + str(self.dictionaryItem["assetTag"]) + ";"
            if not(self.dictionaryItem["endUsername"] == ""):
                msg = msg + " endUsername=" + str(self.dictionaryItem["endUsername"]) + ";"
            if not(self.dictionaryItem["ComputerName"] == ""):
                msg = msg + " ComputerName=" + str(self.dictionaryItem["ComputerName"]) + ";"
            if not(self.dictionaryItem["ipAddress"] == ""):
                msg = msg + " ipAddress=" + str(self.dictionaryItem["ipAddress"]) + ";"
            if not(self.dictionaryItem["macAddress"] == ""):
                msg = msg + " macAddress=" + str(self.dictionaryItem["macAddress"]) + ";"
            if not(self.dictionaryItem["hardwarePort"] == ""):
                msg = msg + " hardwarePort=" + str(self.dictionaryItem["hardwarePort"]) + ";"
            if not(self.dictionaryItem["device"] == ""):
                msg = msg + " device=" + str(self.dictionaryItem["device"]) + ";"
            self.messageAppend(msg)
            self.gotoNextItemLDAP()
        return self.messageGet()

    def reportProperty(self):
        '''
        report values available via property
        @author: ekkehard j. koch
        @param self:essential if you override this definition
        @return: real
        @note: None
        '''
        self.initializeLANLAssetTagFromProperty(False)
        msg = "List Of Property Database Info:"
        self.messageAppend(msg)
        msg = " - LANLAssetTagFromProperty=" + str(self.getLANLAssetTagFromProperty()) + ";"
        self.messageAppend(msg)
        msg = " - SerialNumber=" + str(self.getSerialNumber()) + ";"
        self.messageAppend(msg)
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
        return self.msg

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
                msg = pMessage
                if (self.msg == ""):
                    self.msg = msg
                else:
                    self.msg = self.msg + "\n" + \
                    msg
        elif datatype == types.ListType:
            if not (pMessage == []):
                for item in pMessage:
                    msg = item
                    if (self.msg == ""):
                        self.msg = msg
                    else:
                        self.msg = self.msg + "\n" + \
                        msg
        else:
            raise TypeError("pMessage with value" + str(pMessage) + \
                            "is of type " + str(datatype) + " not of " + \
                            "type " + str(types.StringType) + \
                            " or type " + str(types.ListType) + \
                            " as expected!")
        return self.msg

    def messageReset(self):
        '''
        reset the message string.
        @author: ekkehard j. koch
        @param self:essential if you override this definition
        @return: boolean - true
        @note: none
        '''
        self.msg = ""
        return self.msg
