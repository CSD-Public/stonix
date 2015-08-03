'''
Created on Jun 25, 2015

@author: dwalker
'''
from __future__ import absolute_import
import traceback
from ..rule import Rule
from ..CommandHelper import CommandHelper
from ..stonixutilityfunctions import iterate
from ..logdispatcher import LogPriority
import re


class NoCachedFDEKeys(Rule):

    def __init__(self, config, environ, logdispatch, statechglogger):
        '''
        Constructor
        '''
        Rule.__init__(self, config, environ, logdispatch, statechglogger)

        self.logger = logdispatch
        self.rulenumber = 271
        self.rulename = "NoCachedFDEKeys"
        self.formatDetailedResults("initialize")
        self.helptext = "This rule prevents the mac from saving filevault " + \
            "encryption keys on the system."
        self.rootrequired = True
        datatype = "bool"
        key = "NOCACHEDFDEKEYS"
        instructions = "To disable this rule set the value of " + \
            "NOCACHEDFDEKEYS to False"
        default = True
        self.applicable = {'type': 'white',
                           'os': {'Mac OS X': ['10.9', 'r', '10.10.10']}}
        self.ci = self.initCi(datatype, key, instructions, default)

    def report(self):
        try:
            compliant = True
            self.ch = CommandHelper(self.logger)
            cmd = "/usr/bin/pmset -g"
            if self.ch.executeCommand(cmd):
                output = self.ch.getOutput()
                error = self.ch.getError()
                if output:
                    for line in output:
                        if re.search("DestroyFVKeyOnStandby", line):
                            line = line.strip()
                            temp = line.split()
                            if temp[1] != "1":
                                self.detailedresults += "Incorrect value " + \
                                    "for DestroyFVKeyOnStandy key\n"
                                debug = "Incorrect value for " + \
                                    "DestroyFVKeyOnStandby key\n"
                                self.logger.log(LogPriority.DEBUG, debug)
                                compliant = False
                elif error:
                    debug = "Error in running pmset command\n"
                    self.logger.log(LogPriority.DEBUG, debug)
                    compliant = False
            self.compliant = compliant
        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception, err:
            self.rulesuccess = False
            self.detailedresults = self.detailedresults + "\n" + str(err) + \
                " - " + str(traceback.format_exc())
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

    def fix(self):
        try:
            if not self.ci.getcurrvalue():
                return
            self.detailedresults = ""
            self.iditerator = 0
            eventlist = self.statechglogger.findrulechanges(self.rulenumber)
            for event in eventlist:
                self.statechglogger.deleteentry(event)
            success = True
            if not self.compliant:
                cmd = "/usr/bin/pmset -a destroyfvkeyonstandby 1"
                if self.ch.executeCommand(cmd):
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    undocmd = "/usr/bin/pmset -a destroyfvkeyonstandby 0"
                    event = {"eventtype": "commandstring",
                             "command": undocmd}
                    self.statechglogger.recordchgevent(myid, event)
                else:
                    success = False
            self.rulesuccess = success
        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception, err:
            self.rulesuccess = False
            self.detailedresults = self.detailedresults + "\n" + str(err) + \
                " - " + str(traceback.format_exc())
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.rulesuccess
