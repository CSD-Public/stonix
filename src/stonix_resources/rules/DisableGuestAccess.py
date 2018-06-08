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
Created on 09/30/2013

@author: ekoch
@change: 2014-02-12 ekkehard Implemented self.detailedresults flow
@change: 2014-02-12 ekkehard Implemented isapplicable
@change: 2014-10-17 ekkehard OS X Yosemite 10.10 Update
@change: 2015-02-26 ekkehard Artifact artf35702 : DisableGuestAccess
@change: 2015/04/15 dkennel updated for new isApplicable
@change: 2017/07/07 ekkehard - make eligible for macOS High Sierra 10.13
@change: 2017/08/28 rsn Fixing to use new help text methods
@change: 2017/11/13 ekkehard - make eligible for OS X El Capitan 10.11+
@change: 2018/06/08 ekkehard - make eligible for macOS Mojave 10.14
'''
from __future__ import absolute_import
from ..ruleKVEditor import RuleKVEditor


class DisableGuestAccess(RuleKVEditor):
    '''
    This Mac Only rule makes sure that the NAT Dictionary is not enabled.:
    1. guestAccess is disabled with the following commands:
    defaults -currentHost read /Library/Preferences/com.apple.AppleFileServer guestAccess
    defaults -currentHost write /Library/Preferences/com.apple.AppleFileServer guestAccess -bool yes
    2. AllowGuestAccess is disabled with the following commands:
    defaults -currentHost read /Library/Preferences/com.apple.AppleFileServer AllowGuestAccess
    defaults -currentHost write /Library/Preferences/com.apple.AppleFileServer AllowGuestAccess -bool yes
    @author: ekkehard j. koch
    '''

###############################################################################

    def __init__(self, config, environ, logger, statechglogger):
        RuleKVEditor.__init__(self, config, environ, logger, statechglogger)
        self.rulenumber = 174
        self.rulename = 'DisableGuestAccess'
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.helptext = "Configures the Apple File Server (AFS) and " + \
        "the Samba (SMB) server to prohibit anonymous guest access."
        self.applicable = {'type': 'white',
                           'os': {'Mac OS X': ['10.11', 'r', '10.14.10']}}

        self.rootrequired = True
        self.guidance = []
        self.addKVEditor("disableGuestSharingAFP",
                         "defaults",
                         "/Library/Preferences/com.apple.AppleFileServer",
                         "",
                         {"guestAccess": ["0", "-bool no"]},
                         "present",
                         "",
                         "Do not allow guests to access AppleShare volumes.",
                         None,
                         False,
                         {})
        self.addKVEditor("disableGuestSharingSMB",
                         "defaults",
                         "/Library/Preferences/SystemConfiguration/com.apple.smb.server", 
                         "",
                         {"AllowGuestAccess": ["0", "-bool no"]},
                         "present",
                         "",
                         "Do not allow guest to access SMB Shares.",
                         None,
                         False,
                         {})
