###############################################################################
#                                                                             #
# Copyright 2015-2018.  Los Alamos National Security, LLC. This material was  #
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
@author: dwalker 1/13/2015
@change: 2015/04/15 updated for new isApplicable
@change: 2017/07/07 ekkehard - make eligible for macOS High Sierra 10.13
@change: 2017/08/28 rsn Fixing to use new help text methods
@change: 2017/11/13 ekkehard - make eligible for OS X El Capitan 10.11+
'''
from __future__ import absolute_import
from ..ruleKVEditor import RuleKVEditor
import traceback
from ..logdispatcher import LogPriority


class DisableOpenSafeSafari(RuleKVEditor):
    def __init__(self, config, environ, logdispatcher, statechglogger):
        RuleKVEditor.__init__(self, config, environ, logdispatcher,
                              statechglogger)

        self.rulenumber = 270
        self.rulename = 'DisableOpenSafeSafari'
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.rootrequired = False
        # for compatibility with logging in rule.py's undo() method...
        self.logger = self.logdispatch
        self.guidance = []
        self.applicable = {'type': 'white',
                           'os': {'Mac OS X': ['10.11', 'r', '10.13.10']}}
        # init CIs
        datatype = 'bool'
        key = 'SAFESAFARI'
        instructions = "To prevent the open safe file after downloading " + \
        "feature being disabled, set the value of SAFESAFARI to False."
        default = True
        self.ci = self.initCi(datatype, key, instructions,
                                                default)
        self.addKVEditor("DisableOpenSafeSafari",
                         "defaults",
                         "~/Library/Preferences/com.apple.Safari.plist",
                         "",
                         {"AutoOpenSafeDownloads": ["0", "-bool no"]},
                         "present",
                         "",
                         "Disable open safe files after download in safari")
        self.sethelptext()

    def undo(self):
        '''
        Overriding parent undo method because there is no undo method for this
        rule due to the fact that this is a user context only rule and non
        administrators can't undo rule actions.
        '''
        try:
            self.detailedresults = "no undo available\n"
            self.logger.log(LogPriority.INFO, self.detailedresults)
        except(KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.INFO, self.detailedresults)
