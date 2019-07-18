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
'''
from __future__ import absolute_import
import traceback
import os
from ..rule import Rule
from re import search, escape
from ..logdispatcher import LogPriority
from ..stonixutilityfunctions import iterate
from ..CommandHelper import CommandHelper


class DisableSIRIandContinuityFeatures(Rule):
    def __init__(self, config, environ, logdispatch, statechglogger):
        '''Constructor'''
        Rule.__init__(self, config, environ, logdispatch, statechglogger)

        self.logger = logdispatch
        self.rulenumber = 310
        self.rulename = "DisableSIRIandContinuityFeatures"
        self.formatDetailedResults("initialize")
        self.rootrequired = True
        self.applicable = {'type': 'white',
                           'os': {'Mac OS X': ['10.10.0', 'r', '10.14.10']},
                           'fisma': 'low'}
        datatype = "bool"
        key = "SIRICONTINUITY"
        instructions = "To disable this rule set the value of " + \
            "SIRICONTINUITY to False"
        default = True
        self.ci = self.initCi(datatype, key, instructions, default)
        
        datatype = "string"
        key = "MACHOMEDIR"
        instructions = "Enter the current user's home directory here " + \
            " which is usually in the location of: /Users/username\n" + \
            "If left blank, we will try to retrieve the home directory " + \
            "inside the rule\n"
        default = ""
        self.homeci = self.initCi(datatype, key, instructions, default)
        '''Directory location for testing only'''
#         self.profile = "/Users/username/stonix/src/" + \
#                        "stonix_resources/files/" + \
#                        "stonix4macRestrictionsiCloudDictationSpeech.mobileconfig"
        self.profile = "/Applications/stonix4mac.app/Contents/" + \
                       "Resources/stonix.app/Contents/MacOS/" + \
                       "stonix_resources/files/" + \
                       "stonix4macRestrictionsiCloudDictationSpeech.mobileconfig"
        self.identifier = "097AD858-A863-4130-989F-D87CCE7E393A"
        self.home = ""
        self.ch = CommandHelper(self.logger)
        self.siripath1 = "/Library/Containers/com.apple.SiriNCService" + \
            "/Data/Library/Preferences/com.apple.Siri.plist" 
        self.siriparams1 = "StatusMenuVisible"
        self.siripath2 = "/Library/Preferences/com.apple.assistant.support" + \
            ".plist"
        self.siriparams2 = "Assistant\ Enabled"
        self.sethelptext()

    def setupHomeDir(self):
        home = ""
        cmd = "/bin/echo $HOME"
        if self.ch.executeCommand(cmd):
            output = self.ch.getOutputString()
            if output:
                home = output.strip()
        return home
                    
    def report(self):
        try:
            self.detailedresults = ""
            self.defaults1 = True
            self.defaults2 = True
            self.profilecomp = True
            compliant = True
            if not self.homeci.getcurrvalue():
                self.home = self.setupHomeDir()
            if self.home:
                if os.path.exists(self.home):
                    if os.path.exists(self.home + self.siripath1):
                        cmd = "/usr/bin/defaults read " + \
                               self.home + self.siripath1 + " " + \
                               self.siriparams1
                        if self.ch.executeCommand(cmd):
                            output = self.ch.getOutputString().strip()
                            if output != "1":
                                self.undo1 = output
                                self.detailedresults += "Didn't get the " + \
                                    "desired results for StatusMenuVisible\n"
                                self.defaults1 = False
                        else:
                            self.detailedresults += "Unable to run defaults " + \
                                "read command on " + self.siripath1 + "\n"
                            self.defaults1 = False
                    if os.path.exists(self.home + self.siripath2):
                        cmd = "/usr/bin/defaults read " + \
                               self.home + self.siripath2 + " " + \
                               self.siriparams2
                        if self.ch.executeCommand(cmd):
                            output = self.ch.getOutputString().strip()
                            if output != "0":
                                self.undo2 = output
                                self.detailedresults += "Didn't get the " + \
                                    "desired results for " + \
                                    "Assistant Enabled\n"
                                self.defaults2 = False
                        else:
                            self.detailedresults += "Unable to run defaults " + \
                                "read command on " + self.siripath2 + "\n"
                            self.defaults2 = False
                else:
                    self.detailedresults += "Home directory entered does not exist\n"
                    compliant = False
            else:
                self.detailedresults += "Unable to retrieve your home directory\n"
                compliant = False

            found = False
            cmd = ["/usr/bin/profiles", "-P"]
            if not self.ch.executeCommand(cmd):
                self.detailedresults += "Unable to run profiles command\n"
            else:
                output = self.ch.getOutput()
                if output:
                    for line in output:
                        if search("^There are no configuration profiles installed", line.strip()):
                            self.detailedresults += "There are no configuration profiles installed\n"
                            break
                        elif search(escape(self.identifier) + "$", line.strip()):
                            found = True
                            break
            if not found:
                self.detailedresults += "All desired profiles aren't isntalled\n"
                self.profilecomp = False
            self.compliant = self.defaults1 & self.defaults2 & \
            self.profilecomp & compliant
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
            if not self.ci.getcurrvalue():
                return
            success = True
            self.detailedresults = ""
            self.iditerator = 0
            eventlist = self.statechglogger.findrulechanges(self.rulenumber)
            for event in eventlist:
                self.statechglogger.deleteentry(event)
            if not self.defaults1:
                cmd = ["/usr/bin/defaults", "write", self.home + self.siripath1,
                       self.siriparams1, "-bool", "yes"]
                if self.ch.executeCommand(cmd):
                    if self.ch.getReturnCode() != 0:
                        success = False
                    else:
                        undocmd = ["/usr/bin/defaults", "write", self.home + \
                                   self.siripath1, self.siriparams1, self.undo1]
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        event = {"eventtype": "comm",
                                 "command": undocmd}
                        self.statechglogger.recordchgevent(myid, event)
            if not self.defaults2:
                cmd = "/usr/bin/defaults write " + self.home + \
                self.siripath2 + " " + self.siriparams2 + " -bool no"
                if self.ch.executeCommand(cmd):
                    if self.ch.getReturnCode() != 0:
                        success = False
                    else:
                        undocmd = "/usr/bin/defaults write " + self.home + \
                            self.siripath2 + " " + self.siriparams2 + \
                            " " + self.undo2
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        event = {"eventtype": "commandstring",
                                 "command": undocmd}
                        self.statechglogger.recordchgevent(myid, event)
            if not self.profilecomp:
                if os.path.exists(self.profile):
                    cmd = ["/usr/bin/profiles", "-I", "-F", self.profile]
                    if not self.ch.executeCommand(cmd):
                        success = False
                    else:
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        cmd = ["/usr/bin/profiles", "-R", "-p", self.identifier]
                        event = {"eventtype": "comm",
                                 "command": cmd}
                        self.statechglogger.recordchgevent(myid, event)
                else:
                    success = False
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
