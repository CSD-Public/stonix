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
@change: 2015/10/07 eball Help text cleanup
@change: 2016/07/07 ekkehard converted to RuleKVEditor
'''

from __future__ import absolute_import
from ..ruleKVEditor import RuleKVEditor


class DisableAFPFileSharing(RuleKVEditor):
    '''
    This method disables AFP file sharing on mac os x systems

    @author: Breen Malmberg
    '''

###############################################################################

    def __init__(self, config, environ, logdispatcher, statechglogger):
        RuleKVEditor.__init__(self, config, environ, logdispatcher,
                              statechglogger)
        self.rulenumber = 164
        self.rulename = 'DisableAFPFileSharing'
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.helptext = "This rule disables AFP file sharing."
        self.rootrequired = True
        self.guidance = ['CIS 1.4.14.3']

        self.applicable = {'type': 'white',
                           'os': {'Mac OS X': ['10.9', 'r', '10.12.10']}}
        if self.environ.getostype() == "Mac OS X":
            self.addKVEditor("DisableAFPFileSharing",
                             "defaults",
                             "/System/Library/LaunchDaemons/com.apple.AppleFileServer",
                             "",
                             {"Disabled": ["1", "-bool True"]},
                             "present",
                             "",
                             "Disable AFP File Sharing",
                             None,
                             False,
                             {})
