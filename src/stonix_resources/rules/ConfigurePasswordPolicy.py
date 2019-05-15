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
                           'os': {'Mac OS X': ['10.12.4', '+']}}
        self.fismacat = FISMACAT
        datatype = "bool"
        key = "PWPOLICY"
        instructions = "To disable the installation of the password " + \
            "profile set the value of PWPOLICY to False"
        default = True
        self.pwci = self.initCi(datatype, key, instructions, default)
        
        datatype = "bool"
        key = "SECPOLICY"
        instructions = "To disable the installation of the security " + \
            "profile set the value of SECPOLICY to False"
        default = True
        self.sci = self.initCi(datatype, key, instructions, default)
        self.iditerator = 0
        
        if self.fismacat == "high":
            self.passidentifier = "gov.lanl.stonix4mac.macOS.Sierra.10.12.fisma.high"
#             self.pwprofile = "/Users/username/stonix/src/" + \
#                              "stonix_resources/files/" + \
#                              "stonix4macPasscodeProfileFormacOSSierra10.12FISMAHigh.mobileconfig"
            self.pwprofile = "/Applications/stonix4mac.app/Contents/" + \
                             "Resources/stonix.app/Contents/MacOS/" + \
                             "stonix_resources/files/" + \
                             "stonix4macPasscodeProfileFormacOSSierra10.12FISMAHigh.mobileconfig"
        else:
            self.passidentifier = "gov.lanl.stonix4mac.macOS.Sierra.10.12.fisma.low"
#             self.pwprofile = "/Users/username/stonix/src/" + \
#                              "stonix_resources/files/" + \
#                              "stonix4macPasscodeProfileFormacOSSierra10.12FISMALow.mobileconfig"
            self.pwprofile = "/Applications/stonix4mac.app/Contents/" + \
                             "Resources/stonix.app/Contents/MacOS/" + \
                             "stonix_resources/files/" + \
                             "stonix4macPasscodeProfileFormacOSSierra10.12FISMALow.mobileconfig"
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

        self.compliant = True
        self.detailedresults = ""
        self.pweditor, self.seceditor = "", ""
        self.pwreport = True

        try:

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
            self.pweditor = KVEditorStonix(self.statechglogger, self.logger,
                                               "profiles", self.pwprofile, "",
                                               self.pwprofiledict, "", "")
            '''Run the system_proflier command'''
            self.pweditor.report()
            if self.pweditor.fixables:
                self.pwreport = False
                self.detailedresults += "The following configuration items need fixing:\n" + "\n".join(self.pweditor.fixables)
                self.compliant = False
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

###############################################################################

    def fix(self):
        '''Configure and install the password policy profile for Mac OS X
        
        @author: Derek Walker
        @change: 04/19/2018 - Breen Malmberg - added doc string; cleaned up redundant code;
                added more logging; added in-line comments; removed dead-end logic paths which
                blocked correct code from running at all (ever); corrected the return variable;
                added detailedresults formatting if exiting method early due to CI not being set


        '''

        self.rulesuccess = True
        self.detailedresults = ""
        self.iditerator = 0

        try:

            if not self.pwci.getcurrvalue():
                self.formatDetailedResults("fix", self.rulesuccess, self.detailedresults)
                self.detailedresults += "\nFix was not enabled for this rule. Nothing will be done."
                self.logdispatch.log(LogPriority.INFO, self.detailedresults)
                return self.rulesuccess

            # clear previous undo events
            eventlist = self.statechglogger.findrulechanges(self.rulenumber)
            self.logdispatch.log(LogPriority.DEBUG, "Removing previous stored undo events (if any)...")
            for event in eventlist:
                self.statechglogger.deleteentry(event)

            # if the primary rule CI is enabled, then run the fix actions for this rule
            if self.pwci.getcurrvalue():
                self.logdispatch.log(LogPriority.DEBUG, "Fix enabled. Running fix...")
                if not self.pwreport:
                    if os.path.exists(self.pwprofile):
                        self.logdispatch.log(LogPriority.DEBUG, "Found required password profile. Installing...")

                        if not self.pweditor.fix():
                            self.rulesuccess = False
                            self.logdispatch.log(LogPriority.DEBUG, "Kveditor fix failed")
                        elif not self.pweditor.commit():
                            self.rulesuccess = False
                            self.logdispatch.log(LogPriority.DEBUG, "Kveditor commit failed")
                        else:

                            self.iditerator += 1
                            myid = iterate(self.iditerator, self.rulenumber)
                            undocmd = ["/usr/bin/profiles", "-R", "-p", self.passidentifier]
                            event = {"eventtype": "comm",
                                     "command": undocmd}
                            self.statechglogger.recordchgevent(myid, event) 
                    else:
                        self.detailedresults += "\nCould not locate required password profile: " + str(self.pwprofile)
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
