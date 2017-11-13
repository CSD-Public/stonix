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
Created on Dec 2, 2013

@author: dwalker
@change: 02/16/2014 ekkehard Implemented self.detailedresults flow
@change: 02/16/2014 ekkehard Implemented isapplicable
@change: 04/18/2014 dkennel Replaced old style CI with new
@change: 2014/10/17 ekkehard OS X Yosemite 10.10 Update
@change: 2015/04/15 dkennel updated for new isApplicable
@change: 2015/10/07 eball Help text/PEP8 cleanup
@change: 2017/07/07 ekkehard - make eligible for macOS High Sierra 10.13
@change 2017/08/28 rsn Fixing to use new help text methods
'''

from __future__ import absolute_import
from ..rule import Rule
from ..logdispatcher import LogPriority
from ..CommandHelper import CommandHelper
from re import search
import traceback


class DisableRoot(Rule):

    def __init__(self, config, environ, logger, statechglogger):
        '''Constructor'''
        Rule.__init__(self, config, environ, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 160
        self.rulename = "DisableRoot"
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.applicable = {'type': 'white',
                           'os': {'Mac OS X': ['10.9', 'r', '10.13.10']}}

        # configuration item instantiation
        datatype = 'bool'
        key = 'DISABLEROOT'
        instructions = "To disable this rule set the value of DISABLEROOT " + \
            "to False."
        default = True
        self.ci = self.initCi(datatype, key, instructions, default)

        self.cmdhelper = CommandHelper(self.logger)
        self.guidance = ["NSA 1.3.14"]
        self.sethelptext()

    def report(self):
        '''
        DisableRoot.report() method to report whether root is disabled or not
        @author: dwalker
        @param self:essential if you override this definition
        @return: boolean - True if system is compliant, False if not
        '''
        try:
            self.detailedresults = ""
            compliant = False
            cmd = ["/usr/bin/dscl", ".", "-read", "/Users/root",
                   "AuthenticationAuthority"]
            if not self.cmdhelper.executeCommand(cmd):
                self.detailedresults += "Unable to run the /usr/bin/dscl " + \
                    "command."
                compliant = False
            else:
                output = self.cmdhelper.getOutput()
                error = self.cmdhelper.getError()
                if output:
                    for line in output:
                        if search("No such key", line):
                            compliant = True
                            break
                elif error:
                    for line in error:
                        if search("No such key", line):
                            compliant = True
                            break
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
        '''
        DisableRoot.fix() method to run the command necessary to disable root
        on the mac.
        @author: dwalker
        @param self:essential if you override this definition
        @return: boolean - True if able to fix successfully, False if not
        '''
        try:
            if not self.ci.getcurrvalue():
                return
            self.detailedresults = ""

            delete = ["/usr/bin/dscl", ".", "-delete", "/Users/root",
                      "AuthenticationAuthority"]
            create = ["/usr/bin/dscl", ".", "-create", "/Users/root",
                      "passwd", "*"]
            if not self.cmdhelper.executeCommand(delete):
                self.detailedresults += "wasn't able to run the command " + \
                    str(delete) + "\n"
            elif not self.cmdhelper.executeCommand(create):
                self.detailedresults += "wasn't able to run the command " + \
                    str(create) + "\n"
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
