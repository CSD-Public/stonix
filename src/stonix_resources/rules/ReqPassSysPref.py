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
Created on Feb 11, 2015

By requiring a password to unlock System Preferences, a casual user is less
likely to compromise the security of the Mac.

@author: bemalmbe
@change: 2015/04/17 dkennel updated for new isApplicable
'''

from __future__ import absolute_import

from ..rule import Rule
from ..stonixutilityfunctions import iterate
from ..logdispatcher import LogPriority
from ..CommandHelper import CommandHelper

import traceback
import re


class ReqPassSysPref(Rule):
    '''
    By requiring a password to unlock System Preferences, a casual user is less
    likely to compromise the security of the Mac.
    '''

    def __init__(self, config, environ, logger, statechglogger):
        '''
        Constructor
        '''
        Rule.__init__(self, config, environ, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 200
        self.rulename = 'ReqPassSysPref'
        self.compliant = True
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.helptext = 'By requiring a password to unlock System ' + \
        'Preferences, a casual user is less likely to compromise the ' + \
        'security of the Mac.'
        self.rootrequired = True
        self.guidance = ['CIS 1.4.13.3']

        datatype = 'bool'
        key = 'ReqPassSysPref'
        instructions = 'To disable this rule, set the value of ' + \
        'ReqPassSysPref to False.'
        default = True
        self.ci = self.initCi(datatype, key, instructions, default)

        self.applicable = {'type': 'white',
                           'os': {'Mac OS X': ['10.9', 'r', '10.11.10']}}

        self.prefslist = ["system.preferences", "system.preferences.accessibility",
                     "system.preferences.accounts", "system.preferences.datetime",
                     "system.preferences.energysaver", "system.preferences.location",
                     "system.preferences.network", "system.preferences.nvram",
                     "system.preferences.parental-controls", "system.preferences.printing",
                     "system.preferences.security", "system.preferences.security.remotepair",
                     "system.preferences.sharing", "system.preferences.softwareupdate",
                     "system.preferences.startupdisk", "system.preferences.timemachine",
                     "system.preferences.version-cue"]
        self.authplist = '/System/Library/Security/authorization.plist'
        self.plbuddy = '/usr/libexec/PlistBuddy'

    def report(self):
        '''
        determine whether the system is compliant with the ReqPassSysPref rule
        @author: bemalmbe
        '''

        self.detailedresults = ''
        self.compliant = True
        self.cmdhelper = CommandHelper(self.logger)
        self.origstates = {}

        try:

            for pref in self.prefslist:
                self.cmdhelper.executeCommand(self.plbuddy + " -c 'Print rights:" + str(pref) + ":shared' " + self.authplist)
                output = self.cmdhelper.getOutputString()
                self.origstates[pref] = output.strip()
                if output.strip() != "false":
                    self.compliant = False
                    self.detailedresults += '\n' + str(pref) + ' is currently not configured to require a password'

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
        make necessary adjustments to bring the system into compliance with the
        ReqPassSysPref rule
        '''

        self.detailedresults = ''
        success = True
        self.iditerator = 0

        try:

            for pref in self.prefslist:
                self.cmdhelper.executeCommand(self.plbuddy + " -c 'Set rights:" + str(pref) + ":shared 0' " + self.authplist)
                seterrout = self.cmdhelper.getErrorString()
                output = self.cmdhelper.getOutputString()
                if seterrout:
                    self.detailedresults += '\n' + str(seterrout)
                if re.search("Does Not Exist", output.strip()):
                    self.cmdhelper.executeCommand(self.plbuddy + " -c 'Add rights:" + str(pref) + ":shared bool false' " + self.authplist)
                    adderrout = self.cmdhelper.getErrorString()
                    if adderrout:
                        success = False
                        self.detailedresults += '\n' + str(adderrout)

                try:
                    event = {"eventtype": "commandstring",
                             "command": self.plbuddy + " -c 'Set rights:" + str(pref) + ":shared bool " + str(self.origstates[pref]) + " " + self.authplist}
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    self.statechglogger.recordchgevent(myid, event)
                except KeyError:
                    pass

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.detailedresults += traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", success,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return success
