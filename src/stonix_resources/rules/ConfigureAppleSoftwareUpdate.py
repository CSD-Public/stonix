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
@change: 2018/06/08 ekkehard - make eligible for macOS Mojave 10.14
@change: 2018/11/07 Brandon R. Gonzales - Add reporting output/instructions to
            detailed results when the system requires software updates
@change: 2018/11/16 Brandon R. Gonzales - ConfigureCatalogURL is now fixed
            through command helper.
@change: 2019/03/12 ekkehard - make eligible for macOS Sierra 10.12+
'''
from __future__ import absolute_import
import re
import types
import traceback

from ..ruleKVEditor import RuleKVEditor
from ..CommandHelper import CommandHelper
from ..logdispatcher import LogPriority
from ..localize import APPLESOFTUPDATESERVER

class ConfigureAppleSoftwareUpdate(RuleKVEditor):
    '''
    This Mac Only rule does three things:
    To fix issue the following commands:

    1. Set the default Apple Software Update Server for the organization server
    softwareupdate --set-catalog http://apple.foo.com:8088/
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

    1. defaults -currentHost read /Library/Preferences/com.apple.SoftwareUpdate AppleCatalogURL
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
                           'os': {'Mac OS X': ['10.12', 'r', '10.14.10']}}

        if self.environ.getostype() == "Mac OS X":
            self.ccurlci = None
            if self.checkConsts([APPLESOFTUPDATESERVER]):
                # ConfigureCatalogURL ci needs to be set up manually because
                # it is reported with kveditor and fixed with command helper
                datatype = 'bool'
                key = 'CONFIGURECATALOGURL'
                instructions = "Set software update server (AppleCatalogURL) to '" + \
                               str(APPLESOFTUPDATESERVER) + \
                               "'. This should always be enabled. If disabled " + \
                               " it will point to the Apple Software Update " + \
                               "Server. NOTE: your system will report as not " + \
                               "compliant if you disable this option."
                default = True
                self.ccurlci = self.initCi(datatype, key, instructions, default)
                self.addKVEditor("ConfigureCatalogURL",
                                 "defaults",
                                 "/Library/Preferences/com.apple.SoftwareUpdate",
                                 "",
                                 {"AppleCatalogURL": [str(APPLESOFTUPDATESERVER),
                                                      str(APPLESOFTUPDATESERVER)]},
                                 "present",
                                 "",
                                 instructions,
                                 None,
                                 True,
                                 {})
            else:
                self.detailedresults += "\nThe Configure Catalogue URL portion of this rule requires that the constant: APPLESOFTWAREUPDATESERVER be defined and not None. Please ensure this constant is set properly in localize.py"
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

    def report(self):
        '''
        Calls the inherited RuleKVEditor report method.

        Additionally checks that the APPLESOFTWAREUPDATESERVER constant is
        set, the ConfigureCatalogueURL kveditor item is enabled, and gives
        instructions on how to manually fix the RecommendedUpdates kveditor
        item if it is not compliant.
        @author: Brandon R. Gonzales
        @return: bool - true if rule is compliant, false otherwise
        '''

        # Invoke super method
        self.resultReset()
        rulekvecompliant = RuleKVEditor.report(self, True)

        try:
            compliant = True
            detailedresults = ""

            if not self.checkConsts([APPLESOFTUPDATESERVER]):
                compliant = False
                detailedresults += "\nThe Configure Catalogue URL " + \
                    "portion of this rule requires that the constant: " + \
                    "APPLESOFTWAREUPDATESERVER be defined and not None. " + \
                    "Please ensure this constant is set properly in " + \
                    "localize.py"
            elif not self.ccurlci.getcurrvalue():
                compliant = False
                detailedresults += "\nThe Configure Catalogue URL " + \
                                   "portion of this rule requires that " + \
                                   "the ci: CONFIGURECATALOGURL be " + \
                                   "enabled. Please enable this " + \
                                   "configuration item either in the " + \
                                   "STONIX GUI or stonix.conf"

            # The KVEditor object for "RecommendedUpdates" may require a manual
            # fix (running apple software updates). Here is where we instruct the
            # user on how to fix this item if it is non-compliant.
            self.getKVEditor("RecommendedUpdates")
            softwareupdated = self.kveditor.report()
            if not softwareupdated:
                compliant = False
                # OSX 10.14+ has a different way of updating software
                if re.search("10\.12\.*", self.environ.getosver()) or \
                   re.search("10\.13\.*", self.environ.getosver()):
                    detailedresults = "\nThe software on this system is " + \
                                      "not up-to-date. Please update " + \
                                      "your software by opening the App " + \
                                      "Store, navigating to the " + \
                                      "'Updates' tab, and running " + \
                                      "'UPDATE ALL'.\n\n" + \
                                      detailedresults
                else:
                    detailedresults = "\nThe software on this system is " + \
                                      "not up-to-date. Please update " + \
                                      "your software by opening System " + \
                                      "Preferences, navigating to the " + \
                                      "'Software Update' menu, and " + \
                                      "running the necessary updates.\n\n" + \
                                      detailedresults

            compliant = compliant and rulekvecompliant
            self.resultAppend(detailedresults)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception, err:
            compliant = False
            self.detailedresults = self.detailedresults + \
            str(traceback.format_exc())
            self.rulesuccess = False
            self.logdispatch.log(LogPriority.ERROR,
                                 [self.prefix(),
                                  "exception - " + str(err) + \
                                  " - " + self.detailedresults])
        self.compliant = compliant
        self.formatDetailedResults("report", self.compliant,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return compliant

    def fix(self):
        '''
        Calls the inherited RuleKVEditor fix method.

        Additionally fixes the ConfigureCatalogURL kveditor item though
        command helper(instead of using RuleKVEditor).

        @author: Brandon R. Gonzales
        @return: bool - True if fix was successful, False otherwise
        '''
        rulekvesuccess = RuleKVEditor.fix(self, True)

        try:
            success = True
            detailedresults = ""

            if self.checkConsts([APPLESOFTUPDATESERVER]) and self.ccurlci != None:
                if self.ccurlci.getcurrvalue():
                    cmd1 = ["softwareupdate", "--set-catalog",
                            str(APPLESOFTUPDATESERVER)]
                    self.ch.executeCommand(cmd1)
                else:
                    cmd2 = ["softwareupdate", "--clear-catalog"]
                    self.ch.executeCommand(cmd2)
            else:
                success = False
                detailedresults += "\nThe Configure Catalogue URL " + \
                    "portion of this rule requires that the constant: " + \
                    "APPLESOFTWAREUPDATESERVER be defined and not None. " + \
                    "Please ensure this constant is set properly in " + \
                    "localize.py"

            success = success and rulekvesuccess
            self.resultAppend(detailedresults)
        except (KeyboardInterrupt, SystemExit):
            success = False
            raise
        except Exception, err:
            success = False
            self.detailedresults = self.detailedresults + \
            str(traceback.format_exc())
            self.rulesuccess = False
            self.logdispatch.log(LogPriority.ERROR,
                                 [self.prefix(),
                                  "exception - " + str(err) + \
                                  " - " + self.detailedresults])
        self.formatDetailedResults("fix", success,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return success

    def undo(self):
        '''
        Calls the inherited RuleKVEditor undo method.

        Additionally reverts the ConfigureCatalogURL kveditor item though
        command helper(instead of using RuleKVEditor).

        @author: Brandon R. Gonzales
        @return: bool - True if fix was successful, False otherwise
        '''
        rulekvesuccess = RuleKVEditor.undo(self)

        try:
            success = True
            detailedresults = ""

            cmd = ["softwareupdate", "--clear-catalog"]
            self.ch.executeCommand(cmd)

            success = success and rulekvesuccess
            self.resultAppend(detailedresults)
        except (KeyboardInterrupt, SystemExit):
            success = False
            raise
        except Exception, err:
            success = False
            self.detailedresults = self.detailedresults + \
            str(traceback.format_exc())
            self.rulesuccess = False
            self.logdispatch.log(LogPriority.ERROR,
                                 [self.prefix(),
                                  "exception - " + str(err) + \
                                  " - " + self.detailedresults])
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
