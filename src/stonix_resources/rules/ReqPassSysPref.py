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
Created on Feb 11, 2015

By requiring a password to unlock System Preferences, a casual user is less
likely to compromise the security of the Mac.

@author: bemalmbe
@change: 2015/04/17 dkennel updated for new isApplicable
@change: 2015/09/16 eball Refactored rule to update active authorization
                          settings rather than the typically-unused plist
@change: 2017/07/17 ekkehard - make eligible for macOS High Sierra 10.13
@change: 2017/11/13 ekkehard - make eligible for OS X El Capitan 10.11+
@change: 2018/06/08 ekkehard - make eligible for macOS Mojave 10.14
@change: 2019/03/12 ekkehard - make eligible for macOS Sierra 10.12+
'''



from ..rule import Rule
from ..stonixutilityfunctions import iterate
from ..logdispatcher import LogPriority
from ..CommandHelper import CommandHelper
from subprocess import Popen, PIPE, STDOUT
import re
import traceback


class ReqPassSysPref(Rule):
    '''By requiring a password to unlock System Preferences, a casual user is less
    likely to compromise the security of the Mac.


    '''

    def __init__(self, config, environ, logger, statechglogger):
        Rule.__init__(self, config, environ, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 200
        self.rulename = 'ReqPassSysPref'
        self.compliant = True
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.sethelptext()
        self.rootrequired = True
        self.guidance = ['CIS 1.4.13.3']

        datatype = 'bool'
        key = 'REQPASSYSPREF'
        instructions = 'To disable this rule, set the value of ' + \
            'ReqPassSysPref to False.'
        default = True
        self.ci = self.initCi(datatype, key, instructions, default)

        self.applicable = {'type': 'white',
                           'os': {'Mac OS X': ['10.12', 'r', '10.14.10']}}

        self.prefslist = ["system.preferences",
                          "system.preferences.accessibility",
                          "system.preferences.accounts",
                          "system.preferences.datetime",
                          "system.preferences.energysaver",
                          "system.preferences.network",
                          "system.preferences.parental-controls",
                          "system.preferences.printing",
                          "system.preferences.security",
                          "system.preferences.security.remotepair",
                          "system.preferences.sharing",
                          "system.preferences.softwareupdate",
                          "system.preferences.startupdisk",
                          "system.preferences.timemachine"]
        self.ch = CommandHelper(self.logger)
        self.plists = {}
        self.undovals = {}

    def report(self):
        self.detailedresults = ""
        self.compliant = True
        plists = {}

        try:
            for pref in self.prefslist:
                plist = []
                if not self.ch.executeCommand(["security", "authorizationdb",
                                               "read", pref]):
                    self.compliant = False
                    error = "Report could not execute security command"
                    self.logdispatch.log(LogPriority.ERROR, error)
                else:
                    plist = self.ch.getOutput()

                if not plist:
                    self.compliant = False
                    error = "Security command returned no output for " + pref
                    self.logdispatch.log(LogPriority.ERROR, error)
                else:
                    # First line of output is a success/failure code from the
                    # security command, which must be deleted to get a valid
                    # plist
                    del plist[0]
                    plist = "".join(plist)
                    debug = "Checking for <key>shared</key>, <false/>"
                    self.logger.log(LogPriority.DEBUG, debug)
                    if not re.search(r"<key>shared</key>\s+<false/>", plist):
                        self.compliant = False
                        self.detailedresults += pref + " is not set " + \
                            "to require a password\n"
                        plists[pref] = plist
                        debug = "Correct value not found in " + pref + ". " + \
                            "Adding to plists dictionary."
                        self.logger.log(LogPriority.DEBUG, debug)
            self.plists = plists

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.detailedresults = traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

    def fix(self):
        if not self.ci.getcurrvalue():
            info = "ReqPassSysPref CI not enabled. Fix not run."
            self.logger.log(LogPriority.INFO, info)
            return

        results = ""
        success = True
        self.iditerator = 0

        # Delete past state change records from previous fix
        eventlist = self.statechglogger.findrulechanges(self.rulenumber)
        for event in eventlist:
            self.statechglogger.deleteentry(event)

        # The output from the "security" command needs to be written to a
        # plist. "defaults" made unwanted changes to the list, so regex sub
        # is used instead. This is then piped back into the security command.
        try:
            for pref in self.plists:
                contents = self.plists[pref]
                contents = re.sub(r"(<key>shared</key>\s+<)\w+/>",
                                  r"\1false/>", contents)
                p = Popen(["security", "authorizationdb", "write", pref],
                          stdout=PIPE, stdin=PIPE, stderr=STDOUT)
                secOut = p.communicate(contents)[0]
                debug = "Popen result for " + pref + ": " + secOut
                self.logger.log(LogPriority.DEBUG, debug)
                if not re.search("YES", secOut):
                    success = False
                    results += "'security authorizationdb write' command " + \
                        "was not successful\n"
                else:
                    # Write was successful; make state change event
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    event = {"eventtype": "applesec", "pref": pref}
                    self.statechglogger.recordchgevent(myid, event)
            self.rulesuccess = success
            self.detailedresults = results
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.detailedresults = traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", success,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return success

    def undo(self):
        '''Due to the complicated (yet single-purpose) nature of this rule, a
        custom undo function has been implemented.
        @author: Eric Ball


        '''
        try:
            self.detailedresults = ""
            results = ""
            success = True
            eventlist = self.statechglogger.findrulechanges(self.rulenumber)
            if not eventlist:
                self.formatDetailedResults("undo", None, self.detailedresults)
                self.logdispatch.log(LogPriority.INFO, self.detailedresults)
                return success
            for entry in eventlist:
                try:
                    event = self.statechglogger.getchgevent(entry)
                    # The entire process must be done in reverse. Get the info
                    # from "security", write to a plist, manipulate with
                    # re.sub, then pipe back into "security".
                    if event["eventtype"] == "applesec":
                        pref = event["pref"]
                        if not self.ch.executeCommand(["security",
                                                       "authorizationdb",
                                                       "read", pref]):
                            success = False
                            error = "Undo could not execute security command"
                            self.logger.log(LogPriority.ERROR, error)
                        plist = self.ch.getOutput()
                        del plist[0]
                        plist = "".join(plist)
                        plist = re.sub(r"(<key>shared</key>\s+<)\w+/>",
                                       r"\1true/>", plist)
                        p = Popen(["security", "authorizationdb",
                                   "write", pref],
                                  stdout=PIPE, stdin=PIPE, stderr=STDOUT)
                        secOut = p.communicate(plist)[0]
                        debug = "Popen result for " + pref + ": " + secOut
                        self.logger.log(LogPriority.DEBUG, debug)
                        if not re.search("YES", secOut):
                            success = False
                            results += "'security authorizationdb write' " + \
                                "command was not successful\n"
                except(IndexError, KeyError):
                    self.detailedresults = "EventID " + entry + " not found"
                    self.logdispatch.log(LogPriority.DEBUG,
                                         self.detailedresults)
            self.detailedresults = results
        except(KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            success = False
            self.detailedresults = traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, [self.rulename + ".undo",
                                 self.detailedresults])
        self.formatDetailedResults("undo", success, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return success
