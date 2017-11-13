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
Created on May 24, 2013
This is a rule to disable password hints, specifically started for the Mac.

@operating system: generic
@author: Roy Nielsen
@change: 02/13/2014 ekkehard Implemented self.detailedresults flow
@change: 02/13/2014 ekkehard Implemented isapplicable
@change: 2014/10/17 ekkehard OS X Yosemite 10.10 Update
@change: 2015/04/15 dkennel updated for new isApplicable
'''
from __future__ import absolute_import
from ..ruleKVEditor import RuleKVEditor


class DisablePasswordHints(RuleKVEditor):
    """
    This class disables Auto Login on the system.
    """
    def __init__(self, config, environ, logdispatcher, statechglogger):
        '''
        Constructor
        '''
        RuleKVEditor.__init__(self, config, environ, logdispatcher,
                              statechglogger)
        self.rulenumber = 171
        self.rulename = 'DisablePasswordHints'
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.rootrequired = True
        self.helptext = "This rule determines how may login attempts " + \
                        "until password hints will be displayed.  Default " + \
                        "is 0, indicating password hints will never be " + \
                        "displayed."
        self.applicable = {'type': 'white',
                           'os': {'Mac OS X': ['10.9', 'r', '10.12.10']}}
        self.addKVEditor("DisablePasswordHints",
                         "defaults",
                         "/Library/Preferences/com.apple.loginwindow",
                         "",
                         {"RetriesUntilHint": ["0", "-int 0"]},
                         "present",
                         "",
                         "This variable is to determine number of " + \
                         "tries until password hints are displayed at " + \
                         "the login window. Zero indicates no password " + \
                         "hints will be given.",
                         None,
                         False,
                         {})
