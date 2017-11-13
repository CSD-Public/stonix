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
Created on Feb 10, 2015

@author: dwalker
@change: 2015/04/14 dkennel updated for new isApplicable
@change: 2016/04/06 eball Changed rule name to ConfigureProfileManagement
@change: 2017/03/30 dkennel Setting this to FISMA high until Apple fixes bugs
@change: 2017/08/28 ekkehard - Added self.sethelptext()
'''
from __future__ import absolute_import
import traceback
import os
from ..rule import Rule
from re import search
from ..logdispatcher import LogPriority
from ..stonixutilityfunctions import iterate
from ..KVEditorStonix import KVEditorStonix
from ..CommandHelper import CommandHelper
from ..localize import FISMACAT


class ConfigurePasswordPolicy(Rule):
    '''
    Deploy Passcode Policy configuration profiles for OS X Mavericks 10.9
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
        self.pwreport = True
        
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
        '''
        @since: 3/9/2016
        @author: dwalker
        first item in dictionary - identifier (multiple can exist)
            first item in second nested dictionary - key identifier within
                opening braces in output
            first item in nested list is the expected value after the = in
                output (usually a number, in quotes "1"
            second item in nested list is accepted datatype of value after
                the = ("bool", "int")
            third item in nested list (if int) is whether the allowable value
                is allowed to be more or less and still be ok
                "more", "less"
                '''
        try:
            compliant = True
            self.detailedresults = ""
            self.pweditor, self.seceditor = "", ""
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
            if not self.pweditor.report():
                self.pwreport = False
                self.detailedresults += "password profile is either uninstalled or weak\n"
                compliant = False
#             if not self.seceditor.report():
#                 self.secreport = False
#                 self.detailedresults += "security profile is either uninstalled or weak\n"
#                 compliant = False
            self.compliant = compliant
        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

###############################################################################

    def fix(self):
        try:
            if not self.pwci.getcurrvalue():# and not self.sci.getcurrvalue():
                return
            #if self.pwci.getcurrvalue() or self.sci.getcurrvalue():
            success = True
            self.detailedresults = ""
            self.iditerator = 0
            eventlist = self.statechglogger.findrulechanges(self.rulenumber)
            for event in eventlist:
                self.statechglogger.deleteentry(event)
            if self.pwci.getcurrvalue() and not os.path.exists(self.pwprofile):
                print "profile doesn't exist\n\n"
                return False
#             if self.sci.getcurrvalue() and not os.path.exists(self.secprofile):
#                 return False
            print "inside fix\n\n"
            if self.pwci.getcurrvalue():
                if not self.pwreport:
                    print "self.pwreport is False\n\n"
                    if os.path.exists(self.pwprofile):
                        print "pwprofile exists\n\n"
                        if not self.pweditor.fix():
                            print "kveditor fix failed\n\n"
                            success = False
                        elif not self.pweditor.commit():
                            print "kveditor commit failed\n\n"
                            success = False
                        else:
                            print "installation of profile a success\n\n"
                            self.iditerator += 1
                            myid = iterate(self.iditerator, self.rulenumber)
                            cmd = ["/usr/bin/profiles", "-R", "-p",
                                   self.passidentifier]
                            event = {"eventtype": "comm",
                                     "command": cmd}
                            self.statechglogger.recordchgevent(myid, event) 
                    else:
                        self.detailedresults += "You don't have password " + \
                            "profile needed to be installed\n"
                        success = False
#             if self.sci.getcurrvalue():
#                 if not self.secreport:
#                     if os.path.exists(self.secprofile):
#                         self.iditerator += 1
#                         myid = iterate(self.iditerator, self.rulenumber)
#                         self.pweditor.setEventID(myid)
#                         if not self.pweditor.fix():
#                             success = False
#                         elif not self.pweditor.commit():
#                             success = False
#                     else:
#                         self.detailedresults += "You don't have security " + \
#                             "profile needed to be installed\n"
#                         success = False
            self.rulesuccess = success
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.rulesuccess
