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
This rule disables the ability of admins to log into another user's
locked session.

@author: Eric Ball
@change: 2015-08-03 eball Original implementation
@change: 2015/11/09 ekkehard - make eligible of OS X El Capitan
@change: 2016/02/10 eball Update for El Capitan
@change: 2017/07/07 ekkehard - make eligible for macOS High Sierra 10.13
@change 2017/08/28 rsn Fixing to use new help text methods
@change: 2017/11/13 ekkehard - make eligible for OS X El Capitan 10.11+
@change: 2018/06/08 ekkehard - make eligible for macOS Mojave 10.14
@change: 2019/03/12 ekkehard - make eligible for macOS Sierra 10.12+
@change: 2019/08/07 ekkehard - enable for macOS Catalina 10.15 only
'''

import os
import re
import traceback
from ..stonixutilityfunctions import writeFile, readFile, iterate, resetsecon
from ..rule import Rule
from ..logdispatcher import LogPriority


class DisableAdminLoginOverride(Rule):

    def __init__(self, config, enviro, logger, statechglogger):
        Rule.__init__(self, config, enviro, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 177
        self.rulename = "DisableAdminLoginOverride"
        self.formatDetailedResults("initialize")
        self.mandatory = False
        self.applicable = {'type': 'white',
                           'os': {'Mac OS X': ['10.15', 'r', '10.15.10']}}

        # Configuration item instantiation
        datatype = "bool"
        key = "DISABLEADMINLOGINOVERRIDE"
        instructions = "To disable this rule, set the value of " + \
                       "DISABLEADMINLOGINOVERRIDE to false."
        default = True
        self.ci = self.initCi(datatype, key, instructions, default)

        self.guidance = ["CIS 5.10"]
        self.iditerator = 0
        self.sethelptext()

    def report(self):
        try:
            self.path = "/etc/pam.d/screensaver"
            adminAllowed = "group=admin,wheel fail_safe"
            self.compliant = True
            self.detailedresults = ""

            if os.path.exists(self.path):
                ssText = readFile(self.path, self.logger)
                for line in ssText:
                    if re.search(adminAllowed, line):
                        self.compliant = False
                        self.detailedresults += self.path + ' contains "' + \
                            adminAllowed + '"'
                        break
            else:
                self.compliant = False
                self.detailedresults += self.path + " does not exist."

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
            self.iditerator = 0
            eventlist = self.statechglogger.findrulechanges(self.rulenumber)
            for event in eventlist:
                self.statechglogger.deleteentry(event)

            if os.path.exists(self.path):
                adminAllowed = "group=admin,wheel fail_safe"
                adminDisabled = "group=wheel fail_safe"
                ssText = "".join(readFile(self.path, self.logger))
                if re.search(adminAllowed, ssText):
                    ssText = re.sub(adminAllowed, adminDisabled, ssText)
                    tmpfile = self.path + ".tmp"
                    if writeFile(tmpfile, ssText, self.logger):
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        event = {"eventtype": "conf", "filepath": self.path}
                        self.statechglogger.recordchgevent(myid, event)
                        self.statechglogger.recordfilechange(self.path,
                                                             tmpfile, myid)
                        os.rename(tmpfile, self.path)
                        resetsecon(self.path)
                    else:
                        success = False
                        self.detailedresults += "Problem writing new " + \
                                                "contents to temporary file"
            else:
                success = False
                self.detailedresults += self.path + ''' does not exist. STONIX \
will not attempt to create this file. If you are using OS X 10.9 or later, \
this is most likely a bug, and should be reported. Earlier versions of OS X \
are not currently supported by STONIX.'''

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
