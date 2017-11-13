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
Created on Mar 4, 2015

@author: dwalker
@change: 2015/04/15 dkennel updated for new isApplicable
@change: 2015/10/07 eball PEP8 cleanup
'''
from __future__ import absolute_import
from ..ruleKVEditor import RuleKVEditor
from ..ServiceHelper import ServiceHelper
from ..logdispatcher import LogPriority


class DisableFTP(RuleKVEditor):

    def __init__(self, config, environ, logdispatcher, statechglogger):
        RuleKVEditor.__init__(self, config, environ, logdispatcher,
                              statechglogger)
        self.rulenumber = 266
        self.rulename = 'DisableFTP'
        self.logger = logdispatcher
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.helptext = "This rule disables FTP services for the Mac"
        self.applicable = {'type': 'white',
                           'os': {'Mac OS X': ['10.9', 'r', '10.12.10']}}

        # init CIs
        datatype = 'bool'
        key = 'DISABLEFTP'
        instructions = "To prevent DisableFTP from being disabled, set " + \
            "the value of DISABLEFTP to False."
        default = True
        self.ci = self.initCi(datatype, key, instructions, default)
        self.addKVEditor("DisableFTP",
                         "defaults",
                         "/System/Library/LaunchDaemons/ftp.plist",
                         "",
                         {"Disabled": ["1", "-bool yes"]},
                         "present",
                         "",
                         "Disable FTP service")
        self.sh = ServiceHelper(self.environ, self.logger)
        self.setkvdefaultscurrenthost()  # default value is False

    def afterfix(self):
        '''
        @author: dwalker
        @return: boolean - True if definition is successful in unloading
            ftp, False if unsuccessful
        '''
        if self.sh.auditservice("ftpd", "ftpd"):
            if self.sh.disableservice("ftpd", "ftpd"):
                return True
            else:
                self.detailedresults += "Wasn't able to unload ftpd\n"
                self.logger.log(LogPriority.DEBUG, self.detailedresults)
                return False

###############################################################################

    def afterreport(self):
        '''
        @author: dwalker
        @return: boolean
        '''
        if self.sh.auditservice("ftpd", "ftpd"):
            self.detailedresults += "FTP is set to be disabled but " + \
                "hasn't been unloaded"
            self.logger.log(LogPriority.DEBUG, self.detailedresults)
            return False
        else:
            return True
