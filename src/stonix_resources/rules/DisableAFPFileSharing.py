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
This method disables AFP file sharing on mac os x systems

@author: Breen Malmberg
@change: 2015/04/14 dkennel updated for new isApplicable
'''

from __future__ import absolute_import

import traceback

from ..rule import Rule
from ..CommandHelper import CommandHelper
from ..logdispatcher import LogPriority


class DisableAFPFileSharing(Rule):
    '''
    This method disables AFP file sharing on mac os x systems

    @author: Breen Malmberg
    '''

###############################################################################

    def __init__(self, config, environ, logger, statechglogger):

        Rule.__init__(self, config, environ, logger, statechglogger)
        self.rulenumber = 164
        self.rulename = 'DisableAFPFileSharing'
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.helptext = "This method disables AFP file sharing on mac os x systems"
        self.rootrequired = True
        self.logger = logger
        self.guidance = ['CIS 1.4.14.3']

        self.applicable = {'type': 'white',
                           'os': {'Mac OS X': ['10.9', 'r', '10.11.10']}}

        # set up configuration items for this rule
        datatype = 'bool'
        key = 'DisableAFPFileSharing'
        instructions = 'To disable this rule, set the value of ' + \
        'DisableAFPFileSharing to False'
        default = True
        self.ci = self.initCi(datatype, key, instructions, default)

    def report(self):
        '''
        report compliance status of the system with this rule

        @return: self.compliant
        @rtype: boolean
        @author: Breen Malmberg
        '''

        self.compliant = True
        self.detailedresults = ""

        try:

            self.cmdhelper = CommandHelper(self.logger)
            self.afpfile = '/System/Library/LaunchDaemons/com.apple.AppleFileServer.plist'
            cmd = 'defaults read ' + self.afpfile + ' Disabled'

            self.cmdhelper.executeCommand(cmd)
            output = self.cmdhelper.getOutputString()
            if output.strip() != '1':
                self.compliant = False
                self.detailedresults += '\nAFP file server is not disabled'

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.detailedresults += traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

###############################################################################

    def fix(self):
        '''
        run command to disable afp file sharing

        @return: success
        @rtype: boolean
        @author: Breen Malmberg
        '''

        self.detailedresults = ""
        success = True

        try:

            cmd = 'defaults write ' + self.afpfile + ' Disabled -bool True'
            self.cmdhelper.executeCommand(cmd)
            errout = self.cmdhelper.getErrorString()

            if errout:
                success = False
            else:
                event = {'eventtype': 'commandstring',
                         'command': 'defaults remove ' + self.afpfile + ' Disabled'}
                myid = '0164001'
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
