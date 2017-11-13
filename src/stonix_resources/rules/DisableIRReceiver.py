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
Created on Sep 5, 2013

@author: dwalker
@change: 2014/03/18 ekkehard re-factored to be ruleKVEditor Rule
@change: 2014/10/17 ekkehard OS X Yosemite 10.10 Update
@change: 2015/04/15 dkennel updated for new isApplicable
@change: 2017/07/07 ekkehard - make eligible for macOS High Sierra 10.13
@change: 2017/08/28 rsn Fixing to use new help text methods
'''

from __future__ import absolute_import
from ..ruleKVEditor import RuleKVEditor


class DisableIRReceiver(RuleKVEditor):

    def __init__(self, config, environ, logger, statechglogger):
        RuleKVEditor.__init__(self, config, environ, logger, statechglogger)
        self.rulenumber = 202
        self.rulename = "DisableIRReceiver"
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.rootrequired = True
        self.guidance = ['CIS 2.4.13.7']
        self.applicable = {'type': 'white',
                           'os': {'Mac OS X': ['10.9', 'r', '10.13.10']}}
        self.addKVEditor("DisableIRReceiver",
                         "defaults",
                         "/Library/Preferences/com.apple.driver.AppleIRController.plist",
                         "",
                         {"DeviceEnabled": ["0", "-bool no"]},
                         "present",
                         "",
                         "Disable Infrared receiver. " +
                         "This should be enabled.",
                         None,
                         False,
                         {})
        self.sethelptext()
