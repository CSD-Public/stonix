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
Created on Feb 10, 2015

@author: Derek Walker
@change: 2015/04/14 dkennel updated for new isApplicable
@change: 2016/04/06 eball Changed rule name to ConfigureProfileManagement
@change: 2017/03/30 dkennel Setting this to FISMA high until Apple fixes bugs
@change: 2017/08/28 ekkehard - Added self.sethelptext()
@change: 2019/07/17 Brandon R. Gonzales - Make applicable to MacOS 10.13-10.14
'''

from __future__ import absolute_import
import traceback
import os

from ..rule import Rule
from ..logdispatcher import LogPriority
from ..stonixutilityfunctions import iterate
from ..KVEditorStonix import KVEditorStonix
from ..localize import FISMACAT


class ConfigurePasswordPolicy(Rule):
    '''Deploy Passcode Policy configuration profiles for OS X Mavericks 10.9
    & OS Yosemite 10.10. Profile files are installed using the following
    OS X command.


    '''
    def __init__(self, config, environ, logdispatch, statechglogger):
        '''
        Constructor
        '''

        Rule.__init__(self, config, environ, logdispatch, statechglogger)

        self.logger = logdispatch
        self.rulenumber = 106
        self.rulename = "ConfigurePasswordPolicy"
        self.formatDetailedResults("initialize")
        self.sethelptext()
        self.rootrequired = True
        self.applicable = {'type': 'white',
                           'os': {'Mac OS X': ['10.10.0', 'r', '10.14.10']}}
        self.fismacat = FISMACAT
        datatype = "bool"
        key = "PWPOLICY"
        instructions = "To disable the installation of the password " + \
            "profile set the value of PWPOLICY to False"
        default = False
        self.pwci = self.initCi(datatype, key, instructions, default)
        
        datatype = "bool"
        key = "SECPOLICY"
        instructions = "To disable the installation of the security " + \
            "profile set the value of SECPOLICY to False"
        default = True
        self.sci = self.initCi(datatype, key, instructions, default)
        self.iditerator = 0
        self.setvars()

    def setvars(self):
        '''set class variables based on os version'''

        self.passprofile = ""
        self.secprofile = ""
        baseconfigpath = "/Applications/stonix4mac.app/Contents/Resources/stonix.app/Contents/MacOS/stonix_resources/files/"
        if self.fismacat == "high":
            self.passprofile = baseconfigpath + "stonix4macPasscodeConfigurationProfile-high.mobileconfig"
            self.secprofile = baseconfigpath + "stonix4macSecurity&PrivacyConfigurationProfile.mobileconfig"
        else:
            self.passprofile = baseconfigpath + "stonix4macPasscodeConfigurationProfile.mobileconfig"
            self.secprofile = baseconfigpath + "stonix4macSecuritySecurity&PrivacyConfigurationProfile.mobileconfig"

        # the following path and dictionaries are for testing on local vm's
        # without installing stonix package each time.  DO NOT DELETE
        # basetestpath = "/Users/username/stonix/src/stonix_resources/files/"
        # if self.fismacat == "high":
        #     self.passprofiledict = basetestpath + "stonix4macPasscodeConfigurationProfile-high.mobileconfig"
        #     self.secprofiledict = basetestpath + "stonix4macSecuritySecurity&PrivacyConfigurationProfile.mobileconfig"
        # else:
        #     self.passprofiledict = basetestpath + "stonix4macPasscodeConfigurationProfile.mobileconfig"
        #     self.secprofiledict = basetestpath + "stonix4macSecuritySecurity&PrivacyConfigurationProfile.mobileconfig"
        if not os.path.exists(self.passprofile):
            self.logger.log(LogPriority.DEBUG,
                            "Could not locate appropriate password policy profile for macOS X version: " + str(
                                self.os_major_ver) + "." + str(self.os_minor_ver))
            self.passprofile = ""
        if not os.path.exists(self.secprofile):
            self.logger.log(LogPriority.DEBUG,
                "Could not locate appropriate privacy and security policy profile for macOS X version: " + str(
                 self.os_major_ver) + "." + str(self.os_minor_ver))
            self.secprofile = ""
################################################################################################

    def report(self):
        '''first item in dictionary - identifier (multiple can exist)
        first item in second nested dictionary - key identifier within
            opening braces in output
        first item in nested list is the expected value after the = in
            output (usually a number, in quotes "1"
        second item in nested list is accepted datatype of value after
            the = ("bool", "int")
        third item in nested list (if int) is whether the allowable value
            is allowed to be more or less and still be ok
            "more", "less"
        
        @author: Derek Walker


        '''
        try:
            self.compliant = True
            self.pwcompliant = False
            self.secompliant = False
            self.detailedresults = ""
            if not self.pwprofile:
                self.detailedresults += "Could not determine the appropriate password policy profile for your system.\n"
                self.compliant = False
                self.formatDetailedResults("report", self.compliant, self.detailedresults)
                self.logdispatch.log(LogPriority.INFO, self.detailedresults)
                return self.compliant
            if not self.secprofile:
                self.detailedresults += "Could not determine the appropriate privacy and security policy profile for your system.\n"
                self.compliant = False
                self.formatDetailedResults("report", self.compliant, self.detailedresults)
                self.logdispatch.log(LogPriority.INFO, self.detailedresults)
                return self.compliant
            if self.fismacat == "high":
                self.pwprofiledict = {"com.apple.mobiledevice.passwordpolicy":
                                      {"allowSimple": ["0", "bool"],
                                       "forcePIN": ["1", "bool"],
                                       "maxFailedAttempts": ["3", "int", "less"],
                                       "maxGracePeriod":["0", "string"],
                                       "maxPINAgeInDays": ["60", "int", "less"],
                                       "minComplexChars": ["1", "int", "more"],
                                       "minLength": ["15", "int", "more"],
                                       "minutesUntilFailedLoginReset":
                                       ["15", "int", "more"],
                                       "pinHistory": ["25", "int", "more"],
                                       "requireAlphanumeric": ["1", "bool"]}}
            else:
                self.pwprofiledict = {"com.apple.mobiledevice.passwordpolicy":
                                      {"allowSimple": ["1", "bool"],
                                       "forcePIN": ["1", "bool"],
                                       "maxFailedAttempts": ["5", "int", "less"],
                                       "maxGracePeriod":["15", "string"],
                                       "maxPINAgeInDays": ["180", "int", "less"],
                                       "minComplexChars": ["1", "int", "more"],
                                       "minLength": ["8", "int", "more"],
                                       "minutesUntilFailedLoginReset":
                                       ["15", "int", "more"],
                                       "pinHistory": ["5", "int", "more"],
                                       "requireAlphanumeric": ["1", "bool"]}}
            self.secdict = {"com.apple.applicationaccess": {"allowAutoUnlock": ["0", "bool"]},
                            "com.apple.security.firewall": {"Applications": (),
                                                            "BlockAllIncoming": ["0", "bool"],
                                                            "EnableFirewall": ["0", "bool"],
                                                            "EnableStealthMode": ["0", "bool"]},
                            "com.apple.systempolicy.control":{"AllowIdentifiedDevelopers": ["1", "bool"],
                                                              "EnableAssessment": ["0", "bool"]},
                            "com.apple.screensaver": {"askForPassword": ["1", "bool"],
                                                      "askForPasswordDelay": ["5", "int", "less"]},
                            "com.apple.preference.security": {"dontAllowLockMessageUI": ["1", "bool"]},
                            "com.apple.SubmitDiagInfo": {"AutoSubmit": ["0", "bool"]},
                            "com.apple.MCX": {"DestroyFVKeyOnStandby": ["0", "bool"],
                                              "dontAllowFDEDisable":["0", "bool"]}}
            self.pweditor = KVEditorStonix(self.statechglogger, self.logger,
                                               "profiles", self.passprofile, "",
                                               self.pwprofiledict, "", "")
            '''Run the system_proflier command'''
            if not self.pweditor.report():
                self.detailedresults += "Password profile not installed\n"
                self.compliant = False
            else:
                self.detailedresults += "All password profile configuration items are correct and profile is installed."


            self.seceditor = KVEditorStonix(self.statechglogger, self.logger,
                                           "profiles", self.secprofile, "",
                                           self.secdict, "", "", self.environ)
            '''Run the system_proflier command'''
            if not self.seceditor.report():
                self.compliant = False
                self.detailedresults += "Security and privacy profile not installed\n"
            else:
                self.detailedresults += "All security and privacy profile configuration items are correct and profile is installed."

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

###############################################################################

    def fix(self):
        '''Configure and install the password policy profile for Mac OS X
        
        @author: Derek Walker
        @change: 04/19/2018 - Breen Malmberg - added doc string; cleaned up redundant code;
                added more logging; added in-line comments; removed dead-end logic paths which
                blocked correct code from running at all (ever); corrected the return variable;
                added detailedresults formatting if exiting method early due to CI not being set


        '''


        try:

            self.detailedresults = ""
            self.rulesuccess = True

            if self.pwci.getcurrvalue():  # and self.sci.getcurrvalue():
                self.iditerator = 0
                eventlist = self.statechglogger.findrulechanges(self.rulenumber)
                for event in eventlist:
                    self.statechglogger.deleteentry(event)

            # if the primary rule CI is enabled, then run the fix actions for this rule
            if self.pwci.getcurrvalue():
                if not self.pweditor.report():
                    if self.pweditor.fix():
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        self.pweditor.setEventID(myid)
                        if not self.pweditor.commit():
                            self.rulesuccess = False
                            self.logdispatch.log(LogPriority.DEBUG, "Kveditor commit failed")
                    else:
                        self.rulesuccess = False
                        self.logdispatch.log(LogPriority.DEBUG, "Kveditor fix failed")
                else:
                    self.detailedresults += "Password policy profile was already installed. Nothing to do.\n"
            else:
                self.rulesuccess = False
                self.detailedresults += "Password CI was not enabled.\n"
            # if the primary rule CI is enabled, then run the fix actions for this rule
            if self.sci.getcurrvalue():
                if not self.seceditor.report():
                    if self.seceditor.fix():
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        self.seceditor.setEventID(myid)
                        if not self.seceditor.commit():
                            self.rulesuccess = False
                            self.logdispatch.log(LogPriority.DEBUG, "Kveditor commit failed")
                    else:
                        self.rulesuccess = False
                        self.logdispatch.log(LogPriority.DEBUG, "Kveditor fix failed")
                else:
                    self.detailedresults += "Security and privacy profile was already installed. Nothing to do."
            else:
                self.rulesuccess = False
                self.detailedresults += "Security and privacy CI was not enabled.\n"


        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.rulesuccess
