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
@change: 2015/10/07 eball Help text/PEP8 cleanup
@change: 2016/07/07 eball Converted to RuleKVEditor
'''

from __future__ import absolute_import
from ..ruleKVEditor import RuleKVEditor


class ConfigureRemoteManagement(RuleKVEditor):
    '''
    classdocs
    '''

    def __init__(self, config, environ, logger, statechglogger):
        '''
        Constructor
        '''
        RuleKVEditor.__init__(self, config, environ, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 261
        self.rulename = 'ConfigureRemoteManagement'
        self.compliant = True
        self.formatDetailedResults("initialize")
        self.helptext = 'Remote management should only be enabled on ' + \
            'trusted networks with strong user controls present in a ' + \
            'Directory system. Mobile devices without strict controls are ' + \
            'vulnerable to exploit and monitoring.'
        self.rootrequired = True
        self.guidance = ['CIS 2.4.9', 'Apple HT201710']

        self.applicable = {'type': 'white',
                           'os': {'Mac OS X': ['10.9', 'r', '10.12.10']}}

        if self.environ.getostype() == "Mac OS X":
            self.addKVEditor("ARD_AllLocalUsers",
                             "defaults",
                             "/Library/Preferences/com.apple.RemoteManagement",
                             "",
                             {"ARD_AllLocalUsers": ["0", "-bool no"]},
                             "present",
                             "",
                             "Do not allow local users remote management rights.",
                             None,
                             False,
                             {"ARD_AllLocalUsers": ["1", "-bool yes"]})
            self.addKVEditor("ScreenSharingReqPermEnabled",
                             "defaults",
                             "/Library/Preferences/com.apple.RemoteManagement",
                             "",
                             {"ScreenSharingReqPermEnabled":
                              ["1", "-bool yes"]},
                             "present",
                             "",
                             "Enable remote users to request permissions for screen sharing.",
                             None,
                             False,
                             {"ScreenSharingReqPermEnabled":
                              ["0", "-bool no"]})
            self.addKVEditor("VNCLegacyConnectionsEnabled",
                             "defaults",
                             "/Library/Preferences/com.apple.RemoteManagement",
                             "",
                             {"VNCLegacyConnectionsEnabled":
                              ["0", "-bool no"]},
                             "present",
                             "",
                             "Disable Legacy VNC Connections.",
                             None,
                             False,
                             {"VNCLegacyConnectionsEnabled":
                              ["1", "-bool yes"]})
            self.addKVEditor("LoadRemoteManagementMenuExtra",
                             "defaults",
                             "/Library/Preferences/com.apple.RemoteManagement",
                             "",
                             {"LoadRemoteManagementMenuExtra":
                              ["1", "-bool yes"]},
                             "present",
                             "",
                             "Load the remote management menu item.",
                             None,
                             False,
                             {"LoadRemoteManagementMenuExtra":
                              ["0", "-bool no"]})
