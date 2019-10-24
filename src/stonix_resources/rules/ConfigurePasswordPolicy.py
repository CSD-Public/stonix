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
Created on Aug 23, 2016

@author: Derek Walker
@change: 2017/03/30 Dave Kennel Marked as FISMA High
@change: 2017/07/17 ekkehard - make eligible for macOS High Sierra 10.13
@change: 2018/06/08 ekkehard - make eligible for macOS Mojave 10.14
@change: 2018/10/25 Breen Malmberg - added support for high sierra and mojave;
        refactored rule
@change: Derek Walker - 2/7/2019 - updated method to search for a
            different identifier for security profile on 10.13. Added
            testing paths in setvars method which are commented out. DO
            NOT DELETE THIS SECTION OF COMMENTED CODE.
@change: 2019/08/07 ekkehard - enable for macOS Catalina 10.15 only
@change: 2019/10/23 dwalker - updated for Catalina profile, removed other unecessary code
    for older os versions that don't have python3
'''

import traceback
import os
from rule import Rule
from logdispatcher import LogPriority
from stonixutilityfunctions import iterate
from localize import FISMACAT
from KVEditorStonix import KVEditorStonix


class ConfigurePasswordPolicy(Rule):
    '''Deploy Passcode Policy configuration profiles for macOS X'''

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
                           'os': {'Mac OS X': ['10.15', 'r', '10.15.10']},
                           'fisma': 'med'}
        self.fismacat = FISMACAT
        datatype = "bool"
        key = "PWPOLICY"
        instructions = "To disable the installation of the password " + \
                       "profile set the value of PWPOLICY to False"
        default = False
        self.pwci = self.initCi(datatype, key, instructions, default)

        # uncomment if/when there is a security and privacy proflie available for catalina
        # datatype = "bool"
        # key = "SECPOLICY"
        # instructions = "To disable the installation of the security " + \
        #                "profile set the value of SECPOLICY to False"
        # default = True
        # self.sci = self.initCi(datatype, key, instructions, default)
        self.iditerator = 0
        self.setvars()

    def setvars(self):
        '''set class variables based on os version'''

        self.pwprofile = ""
        self.secprofile = ""
        self.os_major_ver = self.environ.getosmajorver()
        self.os_minor_ver = self.environ.getosminorver()
        baseconfigpath = "/Applications/stonix4mac.app/Contents/Resources/stonix.app/Contents/MacOS/stonix_resources/files/"
        if self.fismacat == "high":
            self.passprofiledict = {"10.15": baseconfigpath + "stonix4macPasscodeConfigurationProfile-high.mobileconfig"}
            #uncomment line below when catalina has a security profile
            #self.secprofiledict = {"10.15": baseconfigpath + "stonix4macSecurity"}
        else:
            self.passprofiledict = {"10.15": baseconfigpath + "stonix4macPasscodeConfigurationProfile.mobileconfig"}
            #uncomment line below when catalina has a security profile
            self.secprofiledict = {"10.15": baseconfigpath + "stonix4macSecurity"}

        # the following path and dictionaries are for testing on local vm's
        # without installing stonix package each time.  DO NOT DELETE
        # basetestpath = "/Users/username/stonix/src/stonix_resources/files/"
        # if self.fismacat == "high":
        #     self.passprofiledict = {
        #         "10.15": basetestpath + "stonix4macPasscodeConfigurationProfile-high.mobileconfig"}
        #     self.secprofiledict = {
        #         "10.15": basetestpath + "nameOfSecurityProfileWhenAvailable"}
        # else:
        #     self.passprofiledict = {
        #         "10.15": basetestpath + "stonix4macPasscodeConfigurationProfile.mobileconfig"}
        #     self.secprofiledict = {
        #         "10.15": basetestpath + "nameOfSecurityProfileWhenAvailable"}
        try:
            self.pwprofile = self.passprofiledict[str(self.os_major_ver) + "." + str(self.os_minor_ver)]
        except KeyError:
            self.logger.log(LogPriority.DEBUG,
                            "Could not locate appropriate password policy profile for macOS X version: " + str(
                                self.os_major_ver) + "." + str(self.os_minor_ver))
            self.pwprofile = ""
        # uncomment if/when we have a security and privacy profile for catalina
        # try:
        #     self.secprofile = self.secprofiledict[str(self.os_major_ver) + "." + str(self.os_minor_ver)]
        # except KeyError:
        #     self.logger.log(LogPriority.DEBUG,
        #         "Could not locate appropriate privacy and security policy profile for macOS X version: " + str(
        #          self.os_major_ver) + "." + str(self.os_minor_ver))
        #     self.secprofile = ""

    def report(self):
        '''report compliance to password policy and
        security and privacy policy
        :returns: self.compliant
        :rtype: bool
        @author: Derek Walker
        @change: Breen Malmberg - 10/25/2018 - added doc string; refactor
        @change: Derek Walker - 2/7/2019 - updated method to search for a
            different identifier for security profile on 10.13
        '''
        try:
            self.compliant = True
            self.pwcompliant = False
            self.secompliant = False
            self.detailedresults = ""
            if not self.pwprofile:
                self.detailedresults += "\nCould not determine the appropriate password policy profile for your system."
                self.compliant = False
                self.formatDetailedResults("report", self.compliant, self.detailedresults)
                self.logdispatch.log(LogPriority.INFO, self.detailedresults)
                return self.compliant
            # uncomment if/when we have a security and privacy profile for catalina
            # if not self.secprofile:
            #     self.detailedresults += "\nCould not determine the appropriate privacy and security policy profile for your system."
            #     self.compliant = False
            #     self.formatDetailedResults("report", self.compliant, self.detailedresults)
            #     self.logdispatch.log(LogPriority.INFO, self.detailedresults)
            #     return self.compliant
            if self.fismacat == "high":
                self.pwprofiledict = {"com.apple.mobiledevice.passwordpolicy":
                                          {"allowSimple": ["0", "bool"],
                                           "forcePIN": ["1", "bool"],
                                           "maxFailedAttempts": ["3", "int", "less"],
                                           "maxGracePeriod": ["0", "string"],
                                           "maxPINAgeInDays": ["60", "int", "less"],
                                           "minComplexChars": ["1", "int", "more"],
                                           "minLength": ["14", "int", "more"],
                                           "minutesUntilFailedLoginReset":
                                               ["15", "int", "more"],
                                           "pinHistory": ["25", "int", "more"],
                                           "requireAlphanumeric": ["1", "bool"]}}
            else:
                self.pwprofiledict = {"com.apple.mobiledevice.passwordpolicy":
                                          {"allowSimple": ["1", "bool"],
                                           "forcePIN": ["1", "bool"],
                                           "maxFailedAttempts": ["5", "int", "less"],
                                           "maxGracePeriod": ["15", "string"],
                                           "maxPINAgeInDays": ["180", "int", "less"],
                                           "minComplexChars": ["1", "int", "more"],
                                           "minLength": ["8", "int", "more"],
                                           "minutesUntilFailedLoginReset":
                                               ["15", "int", "more"],
                                           "pinHistory": ["5", "int", "more"],
                                           "requireAlphanumeric": ["1", "bool"]}}
            self.pweditor = KVEditorStonix(self.statechglogger, self.logger,
                                           "profiles", self.pwprofile, "",
                                           self.pwprofiledict, "", "", self.environ)
            '''Run the system_proflier command'''
            if not self.pweditor.report():
                self.compliant = False
                if self.pweditor.fixables:
                    self.detailedresults += "The following configuration items need fixing:\n" + "\n".join(
                        self.pweditor.fixables)
                else:
                    self.detailedresults += "Password profile not installed\n"
            else:
                self.detailedresults += "All password profile configuration items are correct and profile is installed."

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

    def fix(self):
        '''install the password policy and privacy and security policy profiles
        :returns: self.rulesuccess
        :rtype: bool
        @author: Derek Walker
        @change: Breen Malmberg - 10/25/2018 - added doc string; refactor
        '''

        try:
            self.detailedresults = ""
            if not self.pwci.getcurrvalue(): #and not self.sci.getcurrvalue():
                self.detailedresults += "Neither configuration item was enabled\n" + \
                    "Rule fix will not run\n"
                return
            self.rulesuccess = True
            if self.pwci.getcurrvalue() and self.sci.getcurrvalue():
                self.iditerator = 0
                eventlist = self.statechglogger.findrulechanges(self.rulenumber)
                for event in eventlist:
                    self.statechglogger.deleteentry(event)
            # if password policy ci enabled
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
                    self.detailedresults += "\nPassword policy profile was already installed. Nothing to do."
            # uncomment if/when catlina we have a security and privacy profile for catalina
            # # if privacy and sec policy ci enabled
            # if self.sci.getcurrvalue():
            #     # install privacy and security profile
            #     if not self.secompliant:
            #         installsecp = pinstall + self.secprofile
            #         self.ch.executeCommand(installsecp)
            #         retcode = self.ch.getReturnCode()
            #         # if successfull
            #         if retcode == 0:
            #             # configure undo action
            #             self.iditerator += 1
            #             myid = iterate(self.iditerator, self.rulenumber)
            #             undosecp = premove + self.secprofile
            #             event = {"eventtype": "comm",
            #                      "command": undosecp}
            #             self.statechglogger.recordchgevent(myid, event)
            #             self.detailedresults += "\nSuccessfully installed Privacy and Security policy profile in:\n" + str(
            #                 self.secprofile)
            #         # if not successful
            #         else:
            #             self.rulesuccess = False
            #             self.detailedresults += "\nFailed to install Privacy and Security policy profile!"
            #             errmsg = self.ch.getErrorString()
            #             self.logger.log(LogPriority.DEBUG, errmsg)
            #     else:
            #         self.detailedresults += "\nPrivacy and Security policy profile was already installed. Nothing to do."

                # sync new profiles with users
                #self.ch.executeCommand(profiles + " sync")

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.rulesuccess
