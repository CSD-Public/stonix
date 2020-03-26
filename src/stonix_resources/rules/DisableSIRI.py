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
Created on Apr 20, 2017

@author: dwalker
@change 2017/08/28 rsn Fixing to use new help text methods
@change: 2019/07/17 Brandon R. Gonzales - Make applicable to MacOS 10.13-10.14
@change: 2019/08/07 ekkehard - enable for macOS Catalina 10.15 only
'''

import traceback
import os
from rule import Rule
from logdispatcher import LogPriority
from KVEditorStonix import KVEditorStonix
from stonixutilityfunctions import iterate
from CommandHelper import CommandHelper


class DisableSIRI(Rule):
    def __init__(self, config, environ, logdispatch, statechglogger):
        '''Constructor'''
        Rule.__init__(self, config, environ, logdispatch, statechglogger)

        self.logger = logdispatch
        self.rulenumber = 310
        self.rulename = "DisableSIRI"
        self.formatDetailedResults("initialize")
        self.rootrequired = True
        self.applicable = {'type': 'white',
                           'os': {'Mac OS X': ['10.15', 'r', '10.15.10']},
                           'fisma': 'low'}
        self.sethelptext()
        datatype = "bool"
        key = "DISABLESIRI"
        instructions = "To disable this rule set the value of " + \
            "DISABLESIRI to False"
        default = True
        self.ci = self.initCi(datatype, key, instructions, default)

    def setvars(self):
        self.siriprofile = ""
        baseconfigpath = "/Applications/stonix4mac.app/Contents/" + \
                             "Resources/stonix.app/Contents/MacOS/" + \
                             "stonix_resources/files/"
        self.siriprofile = baseconfigpath + "stonix4macDisableSIRI.mobileconfig"
        '''Directory location for testing only'''
        #basetestpath = "/Users/username/stonix/src/" + \
        #               "stonix_resources/files/"
        #self.siriprofile = basetestpath + "stonix4macDisableSIRI.mobileconfig"
        if not os.path.exists(self.siriprofile):
            message = "Could not locate the appropriate siri disablement profile"
            self.logger.log(LogPriority.DEBUG, message)
            self.siriprofile = ""
                    
    def report(self):
        try:
            self.detailedresults = ""
            self.compliant = True
            self.setvars()
            if not self.siriprofile:
                self.detailedresults += "Could not locate the appropriate SIRI disablement profile.\n"
                self.compliant = False
                self.formatDetailedResults("report", self.compliant, self.detailedresults)
                self.logdispatch.log(LogPriority.INFO, self.detailedresults)
                return self.compliant
            if os.path.exists(self.siriprofile):
                siridict = {"com.apple.ironwood.support": {"Ironwood Allowed": {"val": "0",
                                                                                "type": "bool",
                                                                                "accept": "",
                                                                                "result": False}}}
                self.sirieditor = KVEditorStonix(self.statechglogger, self.logger,
                                                "profiles", self.siriprofile, "",
                                                siridict, "", "")
                if not self.sirieditor.report():
                    self.detailedresults += "Siri not disabled\n"
                    self.compliant = False
            else:
                self.detailedresults += self.siriprofile + " doesn't exist\n"
                self.compliant = False

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

    def fix(self):
        try:
            success = True
            self.detailedresults = ""
            # only run the fix actions if the CI has been enabled
            if not self.ci.getcurrvalue():
                self.detailedresults += "Configuration item was not enabled\n"
                self.rulesuccess = False
                self.formatDetailedResults("fix", self.rulesuccess, self.detailedresults)
                self.logdispatch.log(LogPriority.INFO, self.detailedresults)
                return self.rulesuccess
            # for systems that may have had the other profile installed
            # we check for previous profile and remove it
            if not self.removePreviousProfile():
                self.detailedresults += "Unable to remove previously installed profile " + \
                    "before installing current one\n"
                success = False
            self.iditerator = 0
            eventlist = self.statechglogger.findrulechanges(self.rulenumber)
            for event in eventlist:
                self.statechglogger.deleteentry(event)
            if not self.sirieditor.report():
                if self.sirieditor.fix():
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    self.sirieditor.setEventID(myid)
                    if not self.sirieditor.commit():
                        success = False
                        self.detailedresults += "Unable to install profile\n"
                        self.logdispatch.log(LogPriority.DEBUG, "Kveditor commit failed")
                else:
                    success = False
                    self.detailedresults += "Unable to install profile\n"
                    self.logdispatch.log(LogPriority.DEBUG, "Kveditor fix failed")
            else:
                self.detailedresults += "SIRI disablement profile was already installed.\n"
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

    def removePreviousProfile(self):
        '''This method removes any previous profiles that we may have renamed
        that the user may still have installed.'''
        success = True
        identifier = "097AD858-A863-4130-989F-D87CCE7E393A"
        cmd = "/usr/bin/profiles remove -identifier " + identifier
        ch = CommandHelper(self.logger)
        if not ch.executeCommand(cmd):
            success = False
            debug = "Unable to remove profiles with identifier: " + identifier + "\n"
            self.logger.log(LogPriority.DEBUG, debug)
        return success