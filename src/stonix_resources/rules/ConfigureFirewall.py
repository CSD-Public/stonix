###############################################################################
#                                                                             #
# Copyright 2015-2017.  Los Alamos National Security, LLC. This material was  #
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
@change: 03/25/2014 Original Implementation
@change: 2014/10/17 ekkehard OS X Yosemite 10.10 Update
@change: 2015/04/14 dkennel updated for new isApplicable
@change: 2015/10/07 eball Help text cleanup
@change: 2016/05/31 ekkehard fix help text
@change: 2016/06/22 eball Added &= to afterfix checks so that all checks before
    the last one are not discarded. Also cleaned up help text (again!)
@change: 2017/07/07 ekkehard - make eligible for macOS High Sierra 10.13
@change: 2017/08/28 ekkehard - Added self.sethelptext()
@change: 2017/10/23 rsn - change to new service helper interface
'''
from __future__ import absolute_import
from ..ruleKVEditor import RuleKVEditor
from ..CommandHelper import CommandHelper
from ..ServiceHelper import ServiceHelper


class ConfigureFirewall(RuleKVEditor):
    '''

    @author: ekkehard j. koch
    '''

###############################################################################

    def __init__(self, config, environ, logdispatcher, statechglogger):
        RuleKVEditor.__init__(self, config, environ, logdispatcher,
                              statechglogger)
        self.rulenumber = 14
        self.rulename = 'ConfigureFirewall'
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.sethelptext()
        self.rootrequired = True
        self.guidance = []
        self.applicable = {'type': 'white',
                           'os': {'Mac OS X': ['10.9', 'r', '10.13.10']}}
        self.ch = CommandHelper(self.logdispatch)
        self.sh = ServiceHelper(self.environ, self.logdispatch)
        self.addKVEditor("FirewallOn",
                         "defaults",
                         "/Library/Preferences/com.apple.alf",
                         "",
                         {"globalstate": ["1", "-int 1"]},
                         "present",
                         "",
                         "Turn On Firewall. When enabled.",
                         None,
                         False,
                         {"globalstate": ["0", "-int 0"]})
        self.addKVEditor("FirewallLoginEnabled",
                         "defaults",
                         "/Library/Preferences/com.apple.alf",
                         "",
                         {"loggingenabled": ["1", "-int 1"]},
                         "present",
                         "",
                         "Login Enabled. When enabled.",
                         None,
                         False,
                         {"loggingenabled": ["0", "-int 0"]})
        self.addKVEditor("FirewallStealthDisabled",
                         "defaults",
                         "/Library/Preferences/com.apple.alf",
                         "",
                         {"stealthenabled": ["0", "-int 0"]},
                         "present",
                         "",
                         "Stealth Disabled. When enabled.",
                         None,
                         False,
                         {"stealthenabled": ["1", "-int 1"]})

    def afterfix(self):
        afterfixsuccessful = True
        service = "/System/Library/LaunchDaemons/com.apple.alf.plist"
        servicename = "com.apple.alf"
        afterfixsuccessful &= self.sh.auditservice(service, servicename=servicename)
        afterfixsuccessful &= self.sh.disableservice(service, servicename=servicename)
        afterfixsuccessful &= self.sh.enableservice(service, servicename=servicename)
        return afterfixsuccessful
