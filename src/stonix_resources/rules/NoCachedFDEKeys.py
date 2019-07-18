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
Created on Jun 25, 2015

@author: dwalker
@change: 2015/10/07 eball Help text cleanup, added copyright notice
@change: 2017/07/17 ekkehard - make eligible for macOS High Sierra 10.13
@change: 2017/11/13 ekkehard - make eligible for OS X El Capitan 10.11+
@change: 2018/06/08 ekkehard - make eligible for macOS Mojave 10.14
@change: 2019/03/12 ekkehard - make eligible for macOS Sierra 10.12+
'''

import traceback
from ..rule import Rule
from ..CommandHelper import CommandHelper
from ..stonixutilityfunctions import iterate
from ..logdispatcher import LogPriority
import re


class NoCachedFDEKeys(Rule):

    def __init__(self, config, environ, logdispatch, statechglogger):
        '''Constructor'''
        Rule.__init__(self, config, environ, logdispatch, statechglogger)

        self.logger = logdispatch
        self.rulenumber = 271
        self.rulename = "NoCachedFDEKeys"
        self.formatDetailedResults("initialize")
        self.sethelptext()
        self.rootrequired = True
        datatype = "bool"
        key = "NOCACHEDFDEKEYS"
        instructions = "To disable this rule set the value of " + \
            "NOCACHEDFDEKEYS to False"
        default = True
        self.applicable = {'type': 'white',
                           'os': {'Mac OS X': ['10.12', 'r', '10.14.10']}}
        self.ci = self.initCi(datatype, key, instructions, default)

    def report(self):
        '''

        :return:
        '''
        try:
            self.detailedresults = ""
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
        except Exception as err:
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
            self.detailedresults = ""
            success = True
            if self.ci.getcurrvalue():
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
        except Exception as err:
            self.rulesuccess = False
            self.detailedresults = self.detailedresults + "\n" + str(err) + \
                " - " + str(traceback.format_exc())
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.rulesuccess
