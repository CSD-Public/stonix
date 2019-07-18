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
This rule disables support for several uncommon network protocols.

@author: Eric Ball
@change: 2015/09/10 eball - Original implementation
@change 2017/08/28 rsn Fixing to use new help text methods
'''

import os
import re
import traceback
from ..CommandHelper import CommandHelper
from ..stonixutilityfunctions import iterate, createFile
from ..rule import Rule
from ..logdispatcher import LogPriority


class DisableUncommonProtocols(Rule):

    def __init__(self, config, enviro, logger, statechglogger):
        Rule.__init__(self, config, enviro, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 132
        self.rulename = "DisableUncommonProtocols"
        self.formatDetailedResults("initialize")
        self.mandatory = False
        self.applicable = {'type': 'white',
                           "family": ["linux"]}

        # Configuration item instantiation
        datatype = "bool"
        key = "DISABLEUNCOMMONPROTOCOLS"
        instructions = "To disable this rule, set the value of " + \
                       "DISABLEUNCOMMONPROTOCOLS to false."
        default = True
        self.ci = self.initCi(datatype, key, instructions, default)

        datatype = "list"
        key = "PROTOCOLS"
        instructions = "List all network protocols to disable"
        default = ["dccp", "sctp", "rds", "tipc"]
        self.ci2 = self.initCi(datatype, key, instructions, default)

        self.guidance = ["NSA 2.5.7", "CIS 4.6", "CCE-26448-1", "CCE-26410-1",
                         "CCE-26239-4", "CCE-26696-5", "CCE-26828-4",
                         "CCE-27106-4"]
        self.iditerator = 0
        self.ch = CommandHelper(self.logger)
        self.sethelptext()

    def report(self):
        try:
            protocols = self.ci2.getcurrvalue()
            self.compliant = True
            self.detailedresults = ""
            mpdir = "/etc/modprobe.d/"

            for proto in protocols:
                cmd = ["grep", "-R", proto, mpdir]
                self.ch.executeCommand(cmd)
                if not re.search(":install " + proto + " /bin/true",
                                 self.ch.getOutputString()):
                    self.compliant = False
                    self.detailedresults += proto + " is not disabled\n"
        except (KeyboardInterrupt, SystemExit):
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
            protocols = self.ci2.getcurrvalue()
            mpdir = "/etc/modprobe.d/"
            protoconf = mpdir + "stonix-protocols.conf"

            self.iditerator = 0
            eventlist = self.statechglogger.findrulechanges(self.rulenumber)
            for event in eventlist:
                self.statechglogger.deleteentry(event)

            if not os.path.exists(protoconf):
                createFile(protoconf, self.logger)
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                event = {"eventtype": "creation", "filepath": protoconf}
                self.statechglogger.recordchgevent(myid, event)

            for proto in protocols:
                cmd = ["grep", "-R", proto, mpdir]
                self.ch.executeCommand(cmd)
                if not re.search(":install " + proto + " /bin/true",
                                 self.ch.getOutputString()):
                    open(protoconf, "a").write("install " + proto +
                                               " /bin/true\n")

            self.rulesuccess = success
        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.rulesuccess
