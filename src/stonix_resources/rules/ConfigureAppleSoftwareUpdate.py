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
This method runs all the report methods for RuleKVEditors in defined in the
dictionary

@author: Ekkehard J. Koch
@change: 2013/10/16 Original Implementation
@change: 2014/02/12 Ekkehard Implemented self.detailedresults flow
@change: 2014/02/12 Ekkehard Implemented isapplicable
@change: 2014/04/09 Ekkehard Decription Update
@change: 2014/07/21 Ekkehard added AllowPreReleaseInstallation
@change: 2014/09/15 Ekkehard fixed CatalogURL string
@change: 2015/04/14 Dave Kennel updated for new style isApplicable
@change: 2015/09/21 Ekkehard OS X El Capitan 10.11 & Implement New Guidance
@change: 2015/10/07 Eric Ball Help text cleanup
@change: 2016/04/28 Ekkehard test enhancements
@change: 2016/11/01 Ekkehard add disable automatic macOS (OS X) updates
@change: 2017/07/07 Ekkehard - make eligible for macOS High Sierra 10.13
@change: 2017/08/28 Ekkehard - Added self.sethelptext()
@change: 2017/11/13 Ekkehard - make eligible for OS X El Capitan 10.11+
@change: 2018/06/08 Ekkehard - make eligible for macOS Mojave 10.14
@change: 2018/11/07 Brandon R. Gonzales - Add reporting output/instructions to
            detailed results when the system requires software updates
@change: 2018/11/16 Brandon R. Gonzales - ConfigureCatalogURL is now fixed
            through command helper.
@change: 2019/03/12 Ekkehard - make eligible for macOS Sierra 10.12+
@change: 2019/06/26 Brandon R. Gonzales - Stop user from reporting on
            ConfigureCatalogueURL as it can only be fixed by root
@change: 2019/08/07 ekkehard - enable for macOS Catalina 10.15 only
"""



import re
import types
import traceback

from ruleKVEditor import RuleKVEditor
from CommandHelper import CommandHelper
from logdispatcher import LogPriority
from localize import APPLESOFTUPDATESERVER


class ConfigureAppleSoftwareUpdate(RuleKVEditor):
    """This Mac Only rule does three things:
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

    """

    def __init__(self, config, environ, logdispatcher, statechglogger):
        """
        private method to initialize the module

        :param config: configuration object instance
        :param environ: environment object instance
        :param logdispatcher: logdispatcher object instance
        :param statechglogger: statechglogger object instance
        """

        RuleKVEditor.__init__(self, config, environ, logdispatcher,
                              statechglogger)
        self.rulenumber = 262
        self.rulename = 'ConfigureAppleSoftwareUpdate'
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.sethelptext()
        self.rootrequired = False
        self.guidance = ['CCE 14813-0', 'CCE 14914-6', 'CCE 4218-4',
                         'CCE 14440-2']
        self.applicable = {'type': 'white',
                           'os': {'Mac OS X': ['10.15', 'r', '10.15.10']}}

        if self.environ.getostype() == "Mac OS X":
            if self.environ.geteuid() == 0:
                softwareupdate_path = "/Library/Preferences/com.apple.SoftwareUpdate.plist"
                commerce_path = "/Library/Preferences/com.apple.commerce.plist"
            else:
                softwareupdate_path = "com.apple.SoftwareUpdate"
                commerce_path = "com.apple.commerce"

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

                if self.environ.geteuid() == 0:
                    self.addKVEditor("ConfigureCatalogURL",
                                     "defaults",
                                     softwareupdate_path,
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
                                 softwareupdate_path,
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
                                 softwareupdate_path,
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
                                 softwareupdate_path,
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
                                 softwareupdate_path,
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
                                 softwareupdate_path,
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
                                 softwareupdate_path,
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
                                 softwareupdate_path,
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
                                 softwareupdate_path,
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
                             softwareupdate_path,
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
                             softwareupdate_path,
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
                             softwareupdate_path,
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
                             commerce_path,
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
        """set a flag to indicate whether report has run yet or not

        :return: success
        :rtype: bool
        """

        success = True
        if self.softwareupdatehasnotrun:
# FIXME this is way to slow
            #success = self.ch.executeCommand("softwareupdate --list")
            self.softwareupdatehasnotrun = False
        else:
            success = True
        return success

    def report(self):
        """Calls the inherited RuleKVEditor report method.
        
        Additionally checks that the APPLESOFTWAREUPDATESERVER constant is
        set, the ConfigureCatalogueURL kveditor item is enabled, and gives
        instructions on how to manually fix the RecommendedUpdates kveditor
        item if it is not compliant.

        :return: compliant - true if rule is compliant, false otherwise
        :rtype: bool

        """

        # Invoke super method
        self.resultReset()
        self.compliant = True
        detailedresults = ""
        if not RuleKVEditor.report(self, True):
            self.compliant = False

        try:

            if not self.checkConsts([APPLESOFTUPDATESERVER]):
                self.compliant = False
                detailedresults += "\nThe Configure Catalogue URL " + \
                    "portion of this rule requires that the constant: " + \
                    "APPLESOFTWAREUPDATESERVER be defined and not None. " + \
                    "Please ensure this constant is set properly in " + \
                    "localize.py"
            elif not self.ccurlci.getcurrvalue():
                self.compliant = False
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
                self.compliant = False
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

            self.resultAppend(detailedresults)

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.compliant = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)

        return self.compliant

    def fix(self):
        """Calls the inherited RuleKVEditor fix method.
        
        Additionally fixes the ConfigureCatalogURL kveditor item though
        command helper(instead of using RuleKVEditor).

        :return: self.rulesuccess - True if fix was successful, False otherwise
        :rtype: bool
        """

        self.rulesuccess = True
        detailedresults = ""

        if not RuleKVEditor.fix(self, True):
            self.rulesuccess = False

        try:

            if self.environ.geteuid() == 0:

                if self.checkConsts([APPLESOFTUPDATESERVER]) and self.ccurlci != None:
                    if self.ccurlci.getcurrvalue():
                        cmd1 = ["softwareupdate", "--set-catalog",
                                str(APPLESOFTUPDATESERVER)]
                        self.ch.executeCommand(cmd1)
                    else:
                        cmd2 = ["softwareupdate", "--clear-catalog"]
                        self.ch.executeCommand(cmd2)
                else:
                    self.rulesuccess = False
                    detailedresults += "\nThe Configure Catalogue URL " + \
                        "portion of this rule requires that the constant: " + \
                        "APPLESOFTWAREUPDATESERVER be defined and not None. " + \
                        "Please ensure this constant is set properly in " + \
                        "localize.py"

            self.resultAppend(detailedresults)

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)

        return self.rulesuccess

    def undo(self):
        """Calls the inherited RuleKVEditor undo method.
        
        Additionally reverts the ConfigureCatalogURL kveditor item though
        command helper(instead of using RuleKVEditor).

        :return: success - True if fix was successful, False otherwise
        :rtype: bool

        """

        rulekvesuccess = RuleKVEditor.undo(self)

        try:
            success = True
            detailedresults = ""

            if self.environ.geteuid() == 0:
                cmd = ["softwareupdate", "--clear-catalog"]
                self.ch.executeCommand(cmd)

                success = success and rulekvesuccess
            self.resultAppend(detailedresults)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as err:
            success = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.rulesuccess = False
            self.logdispatch.log(LogPriority.ERROR,
                                 [self.prefix(),
                                  "exception - " + str(err) + \
                                  " - " + self.detailedresults])
        return success

    def formatValue(self, pValue):
        """format a given argument as a clean string

        :param pValue: argument to format
        :return: outputvalue
        :rtype: str
        """

        outputvalue = pValue
        datatype = type(outputvalue)
        if datatype == bytes:
            if not (outputvalue == ""):
                outputvalue = re.sub("\\\\n|\(|\)|\,|\'", "", outputvalue)
                outputvalue = re.sub("\s+", " ", outputvalue)
        elif datatype == list:
            for i, item in enumerate(outputvalue):
                item = re.sub("\\\\n|\(|\)|\,|\'", "", item)
                item = re.sub("\s+", " ", item)
                outputvalue[i] = item
        else:
            outputvalue = outputvalue

        return outputvalue
