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
Created on Jan 13, 2015

Remote management should only be enabled on trusted networks with strong user
controls present in a Directory system, mobile devices without strict controls
are vulnerable to exploit and monitoring.

@author: bemalmbe
@change: 2015/04/14 dkennel updated for new isApplicable
'''

from __future__ import absolute_import

from ..rule import Rule
from ..stonixutilityfunctions import iterate
from ..CommandHelper import CommandHelper
from ..logdispatcher import LogPriority

import traceback
import re


class ConfigureRemoteManagement(Rule):
    '''
    classdocs
    '''

    def __init__(self, config, environ, logger, statechglogger):
        '''
        Constructor
        '''
        Rule.__init__(self, config, environ, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 261
        self.rulename = 'ConfigureRemoteManagement'
        self.compliant = True
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.helptext = 'Remote management should only be enabled on ' + \
        'trusted networks with strong user controls present in a Directory' + \
        ' system, mobile devices without strict controls are vulnerable to' + \
        ' exploit and monitoring.'
        self.rootrequired = True
        self.guidance = ['CIS 2.4.9', 'Apple HT201710']

        self.applicable = {'type': 'white',
                           'os': {'Mac OS X': ['10.9', 'r', '10.11.10']}}
        self.iditerator = 0

    def report(self):
        '''
        '''

        self.detailedresults = ''
        self.cmdhelper = CommandHelper(self.logger)
        self.compliant = True

        reportdict = {"ARD_AllLocalUsers": "0",
                     "ScreenSharingReqPermEnabled": "1",
                     "VNCLegacyConnectionsEnabled": "0",
                     "LoadRemoteManagementMenuExtra": "1"}
        self.origstate = {}

        try:

            for key in reportdict:
                self.cmdhelper.executeCommand("defaults read /Library/Preferences/com.apple.RemoteManagement " + key)
                output = self.cmdhelper.getOutputString()
                if not reportdict[key] == output.strip():
                    self.detailedresults += '\n' + key + ' not set to ' + reportdict[key]
                    self.compliant = False
                if output.strip() == "0":
                    self.origstate[key] = "False"
                elif output.strip() == "1":
                    self.origstate[key] = "True"

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.detailedresults += traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)

        return self.compliant

    def fix(self):
        '''
        '''

        self.detailedresults = ''
        success = True
        self.iditerator = 0

        fixdict = {"ARD_AllLocalUsers": "False",
                   "ScreenSharingReqPermEnabled": "True",
                   "VNCLegacyConnectionsEnabled": "False",
                   "LoadRemoteManagementMenuExtra": "True"}

        try:

            for key in fixdict:
                self.cmdhelper.executeCommand("defaults write /Library/Preferences/com.apple.RemoteManagement " + key + " -bool " + fixdict[key])
                errout = self.cmdhelper.getError()
                if errout:
                    success = False
                if self.compliant:
                    if len(self.origstate) > 0 and key in self.origstate:
                        event = {"eventtype": "commandstring",
                                 "command": "defaults write /Library/Preferences/com.apple.RemoteManagement " + key + " -bool " + self.origstate[key]}
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        self.statechglogger.recordchgevent(myid, event)
                    elif len(self.origstate) == 0:
                        event = {"eventtype": "commandstring",
                                 "command": "defaults delete /Library/Preferences/com.apple.RemoteManagement " + key}
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        self.statechglogger.recordchgevent(myid, event)

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.detailedresults += traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", success,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return success
