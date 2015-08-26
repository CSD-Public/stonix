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
This method runs all the report methods for RuleKVEditors in defined in the
dictionary

@author: ekkehard j. koch
@change: 09/17/2013 Original Implementation
@change: 02/05/2014 New Is Applicable and pep 8 updates.
@change: 02/13/2014 ekkehard Implemented self.detailedresults flow
@change: 2014/10/17 ekkehard OS X Yosemite 10.10 Update
@change: 2015/04/15 dkennel updated for new isApplicable
'''
from __future__ import absolute_import
from ..ruleKVEditor import RuleKVEditor


class DisableMediaAutomaticActions(RuleKVEditor):
    '''
    defaults write /Library/Preferences/com.apple.digihub NAT -dict Enabled -int 0
    defaults read /Library/Preferences/SystemConfiguration/com.apple.nat NAT
    {
        Enabled = 0;
    }
    @author: ekkehard j. koch
    '''

    def __init__(self, config, environ, logger, statechglogger):
        RuleKVEditor.__init__(self, config, environ, logger, statechglogger)
        self.rulenumber = 257
        self.rulename = 'DisableMediaAutomaticActions'
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.helptext = "Internet Sharing uses the open source natd " + \
        "process to share an internet connection with other computers and " +\
        "devices on a local network. Unless specifically required, " +\
        "Internet Sharing should be turned off. If used, it should only " + \
        "be turned on when actual sharing is needed. A much better " + \
        "solution is a dedicated router. Apple makes a number of " + \
        "certified compatible routers."
        self.rootrequired = True
        self.guidance = []
        self.applicable = {'type': 'white',
                           'os': {'Mac OS X': ['10.9', 'r', '10.11.10']}}
        self.addKVEditor("DisableAutoCDAction", "defaults",
                         "/Library/Preferences/com.apple.digihub",
                         "",
                         {"com.apple.digihub.blank.cd.appeared":
                          ["Enabled = 0;", "-dict Enabled -int 0"]},
                         "present",
                         "",
                         "Disable Automatic mounting of CDs.",
                         None,
                         False,
                         {})
        self.addKVEditor("DisableAutoMusicCDAction", "defaults",
                         "/Library/Preferences/com.apple.digihub",
                         "",
                         {"com.apple.digihub.blank.dvd.appeared":
                          ["Enabled = 0;", "-dict Enabled -int 0"]},
                         "present",
                         "",
                         "Disable Automatic mounting of Music CDs.",
                         None,
                         False,
                         {})
        self.addKVEditor("DisableAutoPictureCDAction", "defaults",
                         "/Library/Preferences/com.apple.digihub",
                         "",
                         {"com.apple.digihub.cd.picture.appeared":
                          ["Enabled = 0;", "-dict Enabled -int 0"]},
                         "present",
                         "",
                         "Disable Automatic mounting of Picture CDs.",
                         None,
                         False,
                         {})
        self.addKVEditor("DisableAutoVideoDVDAction", "defaults",
                         "/Library/Preferences/com.apple.digihub",
                         "",
                         {"com.apple.digihub.dvd.video.appeared":
                          ["Enabled = 0;", "-dict Enabled -int 0"]},
                         "present",
                         "",
                         "Disable Automatic mounting of DVDs.",
                         None,
                         False,
                         {})
