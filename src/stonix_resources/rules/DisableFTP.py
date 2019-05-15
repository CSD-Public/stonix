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
Created on Mar 4, 2015

@author: dwalker
@change: 2015/04/15 dkennel updated for new isApplicable
@change: 2015/10/07 eball PEP8 cleanup
@change: 2017/8/9 dwalker updated rule to use unload option vs disable option
@change: 2017/8/30 dwalker updated rule to properly disable ftp according to
        apple suport
@change: 10/09/2018 - Breen Malmberg - made applicable to mojave 10.14
@change: 2019/03/12 ekkehard - make eligible for macOS Sierra 10.12+
'''
from __future__ import absolute_import
from ..rule import Rule
from ..CommandHelper import CommandHelper
from ..logdispatcher import LogPriority
from ..stonixutilityfunctions import iterate
import traceback
import re


class DisableFTP(Rule):

    def __init__(self, config, environ, logdispatcher, statechglogger):
        Rule.__init__(self, config, environ, logdispatcher,
                              statechglogger)
        self.rulenumber = 266
        self.rulename = 'DisableFTP'
        self.logger = logdispatcher
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.helptext = "This rule disables FTP services for the Mac"
        self.applicable = {'type': 'white',
                           'os': {'Mac OS X': ['10.12', 'r', '10.14.10']}}

        # init CIs
        datatype = 'bool'
        key = 'DISABLEFTP'
        instructions = "To prevent DisableFTP from being disabled, set " + \
            "the value of DISABLEFTP to False."
        default = True
        self.ci = self.initCi(datatype, key, instructions, default)
    
    def report(self):
        try:
            self.detailedresults = ""
            compliant = True
            cmd = ["/bin/launchctl", "list"]
            self.ch = CommandHelper(self.logger)
            if self.ch.executeCommand(cmd):
                output = self.ch.getOutput()
                for line in output:
                    if re.search("com\.apple\.ftpd", line):
                        self.detailedresults += "FTP is running and it shouldn't\n"
                        compliant = False
                        break
            else:
                self.detailedresults += "Unable to list running services\n"
                compliant = False
            self.compliant = compliant
        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception:
            self.rulesuccess = False
            self.compliant = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant
    
    def fix(self):
        try:
            if not self.ci.getcurrvalue():
                return
            success = True
            self.detailedresults = ""
    
            #clear out event history so only the latest fix is recorded
            self.iditerator = 0
            eventlist = self.statechglogger.findrulechanges(self.rulenumber)
            for event in eventlist:
                self.statechglogger.deleteentry(event)
            cmd = ["/bin/launchctl", "disable", "system/com.apple.ftpd"]
            self.ch.executeCommand(cmd)
            cmd = ["/bin/launchctl", "unload",
                   "/System/Library/LaunchDaemons/ftp.plist"]
            if not self.ch.executeCommand(cmd):
                success = False
            else:
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                cmd = ["/bin/launchctl", "enable", "system/com.apple.ftpd"]
                event = {"eventtype": "comm",
                         "command": cmd}
                self.statechglogger.recordchgevent(myid, event)
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                cmd = ["/bin/launchctl", "load", "-w",
                       "/System/Library/LaunchDaemons/ftp.plist"]
                event = {"eventtype": "comm",
                         "command": cmd}
                self.statechglogger.recordchgevent(myid, event)
            self.rulesuccess = success
                
        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", success,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.rulesuccess
