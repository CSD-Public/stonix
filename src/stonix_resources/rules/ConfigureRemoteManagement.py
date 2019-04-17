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
Created on Jan 13, 2015

Remote management should only be enabled on trusted networks with strong user
controls present in a Directory system, mobile devices without strict controls
are vulnerable to exploit and monitoring.

@author: Breen Malmberg
@change: 2015/04/14 dkennel updated for new isApplicable
@change: 2015/10/07 eball Help text/PEP8 cleanup
@change: 2016/07/07 eball Converted to RuleKVEditor
@change: 2017/06/16 Breen Malmberg Added ARD_AllLocalUsersPrivs kveditor
@change: 2017/07/07 ekkehard - make eligible for macOS High Sierra 10.13
@change: 2017/08/28 Breen Malmberg - Added self.sethelptext()
@change: 2017/11/13 ekkehard - make eligible for OS X El Capitan 10.11+
@change: 2018/06/08 ekkehard - make eligible for macOS Mojave 10.14
@change: 2019/03/12 ekkehard - make eligible for macOS Sierra 10.12+
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
        self.sethelptext()
        self.rootrequired = True
        self.guidance = ['CIS 2.4.9', 'Apple HT201710']

        self.applicable = {'type': 'white',
                           'os': {'Mac OS X': ['10.12', 'r', '10.14.10']}}

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

            self.addKVEditor("ARD_AllLocalUsersPrivs",
                             "defaults",
                             "/Library/Preferences/com.apple.RemoteManagement",
                             "",
                             {"ARD_AllLocalUsersPrivs": ["1073742058", "-int 1073742058"]},
                             "present",
                             "",
                             "Set which privleges local users have access to",
                             None,
                             False,
                             {"ARD_AllLocalUsersPrivs": ["0", "-int 0"]})

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
