###############################################################################
#                                                                             #
# Copyright 2015.  Los Alamos National Security, LLC. This material was       #
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
Created on Mar 3, 2015

@author: dwalker
@change: 2015/04/14 dkennel updated for new isApplicable
'''
from __future__ import absolute_import
import traceback
import re
import os
from ..rule import Rule
from ..CommandHelper import CommandHelper
from ..logdispatcher import LogPriority
from ..localize import GATEKEEPER


class ConfigureGatekeeper(Rule):
    '''
    '''
    def __init__(self, config, environ, logdispatch, statechglogger):
        '''
        Constructor
        '''
        Rule.__init__(self, config, environ, logdispatch, statechglogger)

        self.logger = logdispatch
        self.rulenumber = 256
        self.rulename = "ConfigureGatekeeper"
        self.formatDetailedResults("initialize")
        self.helptext = ""
        self.rootrequired = True
        datatype = "bool"
        key = "GATEKEEPER"
        instructions = "To disable this rule set the value of " + \
            "GATEKEEPER to False"
        default = True
        self.applicable = {'type': 'white',
                           'os': {'Mac OS X': ['10.9', 'r', '10.11.10']}}
        self.ci = self.initCi(datatype, key, instructions, default)
        self.profPath = os.path.join(os.path.dirname(__file__), "..", "files",
                                     "LANL Security & Privacy.mobileconfig")

    def report(self):
        try:
            compliant = True
            cmd = ["/usr/bin/profiles", "-L"]
            notinst = "There are no configuration profiles installed"
            inst = GATEKEEPER
            self.ch = CommandHelper(self.logger)
            if self.ch.executeCommand(cmd):
                output = self.ch.getOutput()
                if output:
                    for line in output:
                        if re.search(notinst, line):
                            self.detailedresults += "There is no " + \
                                "gatekeeper profile installed\n"
                            compliant = False
                            break
                        elif re.search(inst, line):
                            self.detailedresults += "Gatekeeper profile " + \
                                "installed\n"
                            break
            else:
                self.detailedresults += "Unable to run the profiles " + \
                    "list command\n"
                compliant = False
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
            success = True
            cmd = ["/usr/bin/profiles", "-L"]
            notinst = "There are no configuration profiles installed"
            inst = GATEKEEPER
            found = False
            if self.ch.executeCommand(cmd):
                output = self.ch.getOutput()
                if output:
                    for line in output:
                        if re.search(notinst, line):
                            self.detailedresults += "There is no " + \
                                "gatekeeper configuration profile installed\n"
                            cmd = ["/usr/bin/profiles", "-I", "-F",
                                   self.profPath]
                            if self.ch.executeCommand(cmd):
                                found = True
                                break
                        elif re.search(inst, line):
                            self.detailedresults += "Password profile " + \
                                "installed\n"
                            found = True
                            break
            else:
                self.detailedresults += "Unable to run the profiles " + \
                    "list command\n"
                success = False
            if not found:
                cmd = ["/usr/bin/profiles", "-I", "-F", self.profPath]
                if not self.ch.executeCommand(cmd) or \
                        self.ch.getReturnCode() != 0:
                    success = False
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

    def undo(self):
        pass
