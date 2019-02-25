###############################################################################
#                                                                             #
# Copyright 2015-2019.  Los Alamos National Security, LLC. This material was  #
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
Created on Oct 26, 2016

@author: dwalker
@change: 2017/03/30 dkennel Marked as FISMA high
'''
from __future__ import absolute_import
import traceback
import os
from re import search
from ..rule import Rule
from ..logdispatcher import LogPriority
from ..stonixutilityfunctions import iterate
from ..CommandHelper import CommandHelper


class STIGConfigureApplicationRestrictionsPolicy(Rule):

    def __init__(self, config, environ, logdispatch, statechglogger):
        '''
        Constructor
        '''
        Rule.__init__(self, config, environ, logdispatch, statechglogger)

        self.logger = logdispatch
        self.rulenumber = 364
        self.rulename = "STIGConfigureApplicationRestrictionsPolicy"
        self.formatDetailedResults("initialize")
        self.sethelptext()
        self.rootrequired = True
        self.applicable = {'type': 'white',
                           'os': {'Mac OS X': ['10.11.0', 'r', '10.11.6']},
                           'fisma': 'high'}
        datatype = "bool"
        key = "APPRESTRICTIONS"
        instructions = "To disable the installation of the application " + \
            "restrictions profile set the value of APPRESTRICTIONS to False"
        default = True
        self.ci = self.initCi(datatype, key, instructions, default)
        self.iditerator = 0
        self.identifier = "mil.disa.STIG.Application_Restrictions.alacarte"
        self.profile = "/Applications/stonix4mac.app/Contents/" + \
                     "Resources/stonix.app/Contents/MacOS/" + \
                     "stonix_resources/files/" + \
                     "U_Apple_OS_X_10-11_V1R1_STIG_Application_Restrictions_Policy.mobileconfig"
        '''These directories for testing purposes only'''
#             self.profile = "/Users/username/stonix/src/" + \
#                          "stonix_resources/files/" + \
#                          "U_Apple_OS_X_10-11_V1R1_STIG_Application_Restrictions_Policy.mobileconfig"
    
    def report(self):
        try:
            compliant = False
            self.detailedresults = ""
            self.ch = CommandHelper(self.logger)
            cmd = ["/usr/bin/profiles", "-P"]
            if not self.ch.executeCommand(cmd):
                compliant = False
                self.detailedresults += "Unable to run profiles command\n"
            else:
                output = self.ch.getOutput()
                if output:
                    for line in output:
                        if search("^There are no configuration profiles installed", line.strip()):
                            compliant = False
                            self.detailedresults += "There are no configuration profiles installed\n"
                            break
                        elif search("mil\.disa\.STIG\.Application_Restrictions\.alacarte$", line.strip()):
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
    
    def fix(self):
        try:
            if not self.ci.getcurrvalue():
                return
            if os.path.exists(self.profile):
                success = True
                self.detailedresults = ""
                self.iditerator = 0
                eventlist = self.statechglogger.findrulechanges(self.rulenumber)
                for event in eventlist:
                    self.statechglogger.deleteentry(event)
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