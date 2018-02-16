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
@change: 2013/10/16 Original Implementation
@change: 2014/02/12 ekkehard Implemented self.detailedresults flow
@change: 2014/02/12 ekkehard Implemented isapplicable
@change: 2014/04/09 ekkehard Decription Update
@change: 2014/07/21 ekkehard added AllowPreReleaseInstallation
@change: 2014/09/15 ekkehard fixed CatalogURL string
@change: 2015/04/14 dkennel updated for new style isApplicable
@change: 2015/09/21 ekkehard OS X El Capitan 10.11 & Implement New Guidance
@change: 2015/10/07 eball Help text cleanup
@change: 2016/04/28 ekkehard test enhancements
@change: 2016/11/01 ekkehard add disable automatic macOS (OS X) updates
@change: 2017/07/07 ekkehard - make eligible for macOS High Sierra 10.13
@change: 2017/08/28 ekkehard - Added self.sethelptext()
@change: 2017/11/13 ekkehard - make eligible for OS X El Capitan 10.11+
'''
from __future__ import absolute_import
import re
import types
from ..ruleKVEditor import RuleKVEditor
from ..CommandHelper import CommandHelper
from ..localize import APPLESOFTUPDATESERVER


class ConfigureAppleSoftwareUpdate(RuleKVEditor):
    '''
    This Mac Only rule does three thing:
    To fix issue the following commands:

    1. Set the default Apple Software Update Server for the organization server
    defaults -currentHost write /Library/Preferences/com.apple.SoftwareUpdate CatalogURL http://apple.foo.com:8088/
    2. Disables AutomaticDownload:
    defaults -currentHost write /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload -bool no
    3. Disables AutomaticCheckEnabled:
    defaults -currentHost write /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled -bool no
    4. Disables AutomaticCheckEnabled:
    defaults -currentHost write /Library/Preferences/com.apple.SoftwareUpdate ConfigDataInstall -bool no
    5. Disables DisableCriticalUpdateInstall:
    defaults -currentHost write /Library/Preferences/com.apple.SoftwareUpdate DisableCriticalUpdateInstall -bool no
    6. Disables ability to install PreReleases:
    defaults -currentHost write /Library/Preferences/com.apple.SoftwareUpdate AllowPreReleaseInstallation -bool no
    7. Disables ability to install PreReleases:
    defaults -currentHost write /Library/Preferences/com.apple.SoftwareUpdate RecommendedUpdates 
    8. Disables ability to install PreReleases:
    defaults -currentHost write /Library/Preferences/com.apple.SoftwareUpdate SkipLocalCDN -bool no
    9. Disables automatic macOS (OS X) updates
    defaults write /Library/Preferences/com.apple.commerce AutoUpdateRestartRequired -bool no

    1. defaults -currentHost read /Library/Preferences/com.apple.SoftwareUpdate CatalogURL
    2. defaults -currentHost read /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload
    3. defaults -currentHost read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled
    4. defaults -currentHost read /Library/Preferences/com.apple.SoftwareUpdate ConfigDataInstall
    5. defaults -currentHost read /Library/Preferences/com.apple.SoftwareUpdate DisableCriticalUpdateInstall
    6. defaults -currentHost read /Library/Preferences/com.apple.SoftwareUpdate AllowPreReleaseInstallation
    7. defaults -currentHost read /Library/Preferences/com.apple.SoftwareUpdate RecommendedUpdates
    8. defaults -currentHost read /Library/Preferences/com.apple.SoftwareUpdate SkipLocalCDN
    9. defaults -currentHost read /Library/Preferences/com.apple.commerce AutoUpdateRestartRequired

    OS X Yosemite considerations:
    defaults write /Library/Preferences/com.apple.commerce AutoUpdate -bool [TRUE|FALSE]

    @author: ekkehard j. koch
    '''

###############################################################################

    def __init__(self, config, environ, logdispatcher, statechglogger):
        RuleKVEditor.__init__(self, config, environ, logdispatcher,
                              statechglogger)
        self.rulenumber = 262
        self.rulename = 'ConfigureAppleSoftwareUpdate'
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.sethelptext()
        self.rootrequired = True
        self.guidance = ['CCE 14813-0', 'CCE 14914-6', 'CCE 4218-4',
                         'CCE 14440-2']
        self.applicable = {'type': 'white',
                           'os': {'Mac OS X': ['10.11', 'r', '10.13.10']}}

        if self.environ.getostype() == "Mac OS X":
            self.addKVEditor("ConfigureCatalogURL",
                             "defaults",
                             "/Library/Preferences/com.apple.SoftwareUpdate",
                             "",
                             {"CatalogURL": [str(APPLESOFTUPDATESERVER),
                                             str(APPLESOFTUPDATESERVER)]},
                             "present",
                             "",
                             "Set software update server (CatalogURL) to '" +
                             str(APPLESOFTUPDATESERVER) +
                             "'. This should always be enabled. If disabled " + \
                             " it will point to the Apple Software Update " + \
                             "Server. NOTE: your system will report as not " + \
                             "compliant if you disable this option.",
                             None,
                             False,
                             {"CatalogURL":
                              [re.escape("The domain/default pair of (/Library" + \
                                         "/Preferences/com.apple.Software" + \
                                         "Update, CatalogURL) does not exist"),
                               None]})
            osxversion = str(self.environ.getosver())
            if osxversion.startswith("10.9"):
                self.addKVEditor("DisableAutomaticDownload",
                                 "defaults",
                                 "/Library/Preferences/com.apple.SoftwareUpdate",
                                 "",
                                 {"AutomaticDownload": ["0", "-bool no"]},
                                 "present",
                                 "",
                                 "Disable Automatic Software Update Downloads. " +
                                 "This should be enabled.",
                                 None,
                                 False,
                                 {"AutomaticDownload": ["1", "-bool yes"]})
                self.addKVEditor("DisableAutomaticCheckEnabled",
                                 "defaults",
                                 "/Library/Preferences/com.apple.SoftwareUpdate",
                                 "",
                                 {"AutomaticCheckEnabled": ["0", "-bool no"]},
                                 "present",
                                 "",
                                 "Disable Automatic Checking For Downloads. " +
                                 "This should be enabled.",
                                 None,
                                 False,
                                 {"AutomaticCheckEnabled": ["1", "-bool yes"]})
                self.addKVEditor("DisableConfigDataInstall",
                                 "defaults",
                                 "/Library/Preferences/com.apple.SoftwareUpdate",
                                 "",
                                 {"ConfigDataInstall": ["0", "-bool no"]},
                                 "present",
                                 "",
                                 "Disable Installing of system data files.",
                                 None,
                                 False,
                                 {"ConfigDataInstall": ["1", "-bool yes"]})
                self.addKVEditor("DisableCriticalUpdateInstall",
                                 "defaults",
                                 "/Library/Preferences/com.apple.SoftwareUpdate",
                                 "",
                                 {"CriticalUpdateInstall": ["0", "-bool no"]},
                                 "present",
                                 "",
                                 "Disable Installing of security updates.",
                                 None,
                                 False,
                                 {"CriticalUpdateInstall": ["1", "-bool yes"]})
            else:
                self.addKVEditor("EnableAutomaticDownload",
                                 "defaults",
                                 "/Library/Preferences/com.apple.SoftwareUpdate",
                                 "",
                                 {"AutomaticDownload": ["1", "-bool yes"]},
                                 "present",
                                 "",
                                 "Enable Automatic Software Update Downloads. " +
                                 "This should be enabled.",
                                 None,
                                 False,
                                 {"AutomaticDownload": ["0", "-bool no"]})
                self.addKVEditor("EnableAutomaticCheckEnabled",
                                 "defaults",
                                 "/Library/Preferences/com.apple.SoftwareUpdate",
                                 "",
                                 {"AutomaticCheckEnabled": ["1", "-bool yes"]},
                                 "present",
                                 "",
                                 "Enable Automatic Checking For Downloads. " +
                                 "This should be enabled.",
                                 None,
                                 False,
                                 {"AutomaticCheckEnabled": ["0", "-bool no"]})
                self.addKVEditor("EnableConfigDataInstall",
                                 "defaults",
                                 "/Library/Preferences/com.apple.SoftwareUpdate",
                                 "",
                                 {"ConfigDataInstall": ["1", "-bool yes"]},
                                 "present",
                                 "",
                                 "Enable Installing of system data files.",
                                 None,
                                 False,
                                 {"ConfigDataInstall": ["0", "-bool no"]})
                self.addKVEditor("EnableCriticalUpdateInstall",
                                 "defaults",
                                 "/Library/Preferences/com.apple.SoftwareUpdate",
                                 "",
                                 {"CriticalUpdateInstall": ["1", "-bool yes"]},
                                 "present",
                                 "",
                                 "Enable Installing of security updates.",
                                 None,
                                 False,
                                 {"CriticalUpdateInstall": ["0", "-bool no"]})

            self.addKVEditor("DisableAllowPreReleaseInstallation",
                             "defaults",
                             "/Library/Preferences/com.apple.SoftwareUpdate",
                             "",
                             {"AllowPreReleaseInstallation": ["0", "-bool no"]},
                             "present",
                             "",
                             "Disable Installation of Pre Release Software.",
                             None,
                             False,
                             {"AllowPreReleaseInstallation": ["1", "-bool yes"]})
            self.addKVEditor("RecommendedUpdates",
                             "defaults",
                             "/Library/Preferences/com.apple.SoftwareUpdate",
                             "",
                             {"RecommendedUpdates": [re.escape("(\n)\n"), None]},
                             "present",
                             "",
                             "List of recommended updates.",
                             None,
                             True,
                             {})
            self.addKVEditor("SkipLocalCDN",
                             "defaults",
                             "/Library/Preferences/com.apple.SoftwareUpdate",
                             "",
                             {"SkipLocalCDN": ["1", "-bool yes"]},
                             "present",
                             "",
                             "Require the machine to check with the update server rather than caching servers.",
                             None,
                             False,
                             {"SkipLocalCDN": ["0", "-bool no"]})
            self.addKVEditor("DisableAutomaticMacOSUpdates",
                             "defaults",
                             "/Library/Preferences/com.apple.commerce",
                             "",
                             {"AutoUpdateRestartRequired": ["0", "-bool no"]},
                             "present",
                             "",
                             "Disable automatic installation of macOS (OS X) upgrades.",
                             None,
                             False,
                             {"AutoUpdateRestartRequired": ["1", "-bool yes"]})
        self.ch = CommandHelper(self.logdispatch)
        self.softwareupdatehasnotrun = True

    def beforereport(self):
        success = True
        if self.softwareupdatehasnotrun:
# FIXME this is way to slow
            #success = self.ch.executeCommand("softwareupdate --list")
            self.softwareupdatehasnotrun = False
        else:
            success = True
        return success

###############################################################################

    def formatValue(self, pValue):
        outputvalue = pValue
        datatype = type(outputvalue)
        if datatype == types.StringType:
            if not (outputvalue == ""):
                outputvalue = re.sub("\\\\n|\(|\)|\,|\'", "", outputvalue)
                outputvalue = re.sub("\s+", " ", outputvalue)
        elif datatype == types.ListType:
            for i, item in enumerate(outputvalue):
                item = re.sub("\\\\n|\(|\)|\,|\'", "", item)
                item = re.sub("\s+", " ", item)
                outputvalue[i] = item
        else:
            outputvalue = outputvalue
        return outputvalue
