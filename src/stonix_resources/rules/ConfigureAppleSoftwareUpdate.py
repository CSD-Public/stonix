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
@change 2019/10/08 dwalker - updated rule to use softwareupdate command
            when setting catalogurl.  Implemented proper event recording
            for undo. Removed unecessary 10.9 code as no longer supported
"""

import re
import traceback
import os

from ..ruleKVEditor import RuleKVEditor
from ..CommandHelper import CommandHelper
from ..logdispatcher import LogPriority


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

        self.euid = os.geteuid()
        self.os_minor_vers = self.environ.getosminorver()
        self.set_catalog_key_name()

        if self.euid == 0:
            softwareupdate_path = "/Library/Preferences/com.apple.SoftwareUpdate.plist"
            commerce_path = "/Library/Preferences/com.apple.commerce.plist"
        else:
            softwareupdate_path = "com.apple.SoftwareUpdate"
            commerce_path = "com.apple.commerce"

        datatype = "string"
        key = "UPDATESERVERURL"
        instructions = "Set the software update source for the system to the specified server/URL. Changing this to a blank value will prevent the system from updating"

        # this URL may change in the future
        default = "http://swscan.apple.com"

        self.update_serverCI = self.initCi(datatype, key, instructions, default)

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

    def set_catalog_key_name(self):
        """
        set the catalog url key name based on os version

        :return: void
        """

        self.catalog_key = ""

        if int(self.os_minor_vers) <= 14:
            self.catalog_key = "AppleCatalogURL"
        # changed in macOS X 10.15 Catalina
        elif int(self.os_minor_vers) >= 15:
            self.catalog_key = "CatalogURL"

    def report(self):
        """Calls the inherited RuleKVEditor report method.

        Additionally checks that the APPLESOFTWAREUPDATESERVER constant is
        set, the ConfigureCatalogueURL kveditor item is enabled, and gives
        instructions on how to manually fix the RecommendedUpdates kveditor
        item if it is not compliant.

        :return: compliant - true if rule is compliant, false otherwise
        :rtype: bool

        """

        self.update_server = self.update_serverCI.getcurrvalue()
        self.detailedresults = ""
        self.compliant = True

        try:
            # reset rulekveditor.detailedresults to blank
            self.resultReset()

            # report on many update server config's
            if not RuleKVEditor.report(self, True):
                self.compliant = False

            # report whether an update server is configured
            if not self.report_update_server():
                self.compliant = False

            # report whether the system is up-to-date on system updates
            if not self.report_updated():
                self.compliant = False

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.compliant = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)

        return self.compliant

    def report_updated(self):
        """
        check if the system is up to date on all recommended software updates

        :return: up2date
        :rtype: bool
        """

        up2date = True

        list_updates_cmd = "/usr/sbin/softwareupdate --list"
        self.ch.executeCommand(list_updates_cmd)
        output = self.ch.getOutputString()
        if re.search("\[recommended\]", output, re.I):
            up2date = False
            self.detailedresults += "\nYour system is not fully updated"

        return up2date

    def report_update_server(self):
        """

        :return: update_server_configured
        :rtype: bool
        """

        update_server_configured = True

        if not self.update_server:
            update_server_configured = False
            return update_server_configured

        try:
            get_update_server_cmd = "/usr/bin/defaults read /Library/Preferences/com.apple.SoftwareUpdate " + str(self.catalog_key)
            self.ch.executeCommand(get_update_server_cmd)
            output = self.ch.getOutputString()
            if not re.search(self.update_server, output, re.I):
                update_server_configured = False
                self.detailedresults += "\nAn automatic updates server is not configured"
        except Exception as err:
            update_server_configured = False
            self.detailedresults += "\nAn automatic updates server is not configured"
            self.logdispatch.log(LogPriority.DEBUG, str(err))

        return update_server_configured

    def fix_catalog_url(self):
        """
        set the update catalog url (update server url)

        :return: success
        :rtype: bool
        """

        success = True
        set_url_cmd = "/usr/sbin/softwareupdate --set-catalog " + self.update_server

        try:
            if self.update_server:
                if self.euid == 0:
                    self.ch.executeCommand(set_url_cmd)
                else:
                    success = False
        except:
            success = False

        return success

    def fix_update(self):
        """

        :return: success
        """

        success = True
        update_cmd = "/usr/sbin/softwareupdate -i -r"

        try:
            if self.update_server:
                if self.euid == 0:
                    self.ch.executeCommand(update_cmd)
                else:
                    success = False
        except:
            success = False

        return success

    def fix(self):
        """Calls the inherited RuleKVEditor fix method.

        Additionally fixes the ConfigureCatalogURL kveditor item though
        command helper(instead of using RuleKVEditor).

        :return: self.rulesuccess - True if fix was successful, False otherwise
        :rtype: bool
        """

        self.rulesuccess = True
        self.detailedresults = ""

        try:

            if not self.fix_catalog_url():
                self.rulesuccess = False

            if not RuleKVEditor.fix(self, True):
                self.rulesuccess = False

            if not self.fix_update():
                self.rulesuccess = False

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)

        return self.rulesuccess
