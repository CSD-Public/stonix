###############################################################################
#                                                                             #
# Copyright 2019. Triad National Security, LLC. All rights reserved.          #
# This program was produced under U.S. Government contract 89233218CNA000001  #
# for Los Alamos National Laboratory (LANL), which is operated by Triad       #
# National Security, LLC for the U.S. Department of Energy/National Nuclear   #
# Security Administration.                                                    #
#                                                                             #
# All rights in the program are reserved by Triad National Security, LLC, and #
# the U.S. Department of Energy/National Nuclear Security Administration. The #
# Government is granted for itself and others acting on its behalf a          #
# nonexclusive, paid-up, irrevocable worldwide license in this material to    #
# reproduce, prepare derivative works, distribute copies to the public,       #
# perform publicly and display publicly, and to permit others to do so.       #
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
@change: 2019/03/12 ekkehard - make eligible for macOS Sierra 10.12+
@change: 2019/08/07 ekkehard - enable for macOS Catalina 10.15 only
'''

from ..ruleKVEditor import RuleKVEditor


class DisableGuestAccess(RuleKVEditor):
    '''This Mac Only rule makes sure that the NAT Dictionary is not enabled.:
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
                           'os': {'Mac OS X': ['10.15', 'r', '10.15.10']}}

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
