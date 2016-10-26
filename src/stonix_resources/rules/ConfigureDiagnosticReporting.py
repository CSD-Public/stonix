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
Created on Jan 22, 2016
This rule will configure the diagnostic reporting in OS X.

@operating system: Mac
@author: Eric Ball
@change: 2016/01/22 eball Original implementation
'''

from __future__ import absolute_import
from ..ruleKVEditor import RuleKVEditor


class ConfigureDiagnosticReporting(RuleKVEditor):
    def __init__(self, config, environ, logdispatcher, statechglogger):
        RuleKVEditor.__init__(self, config, environ, logdispatcher,
                              statechglogger)
        self.rulenumber = 3
        self.rulename = 'ConfigureDiagnosticReporting'
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.helptext = "This rule disables the automatic reporting of " + \
            "diagnostic information to Apple and third party app developers."
        self.rootrequired = True
        self.guidance = []
        self.applicable = {'type': 'white',
                           'os': {'Mac OS X': ['10.9', 'r', '10.12.10']}}
        self.addKVEditor("AutoSubmit",
                         "defaults",
                         "/Library/Application Support/CrashReporter/" +
                         "DiagnosticMessagesHistory.plist",
                         "",
                         {"AutoSubmit": ["0", "-bool no"]},
                         "present",
                         "",
                         "Automatically submits diagnostic information to " +
                         "Apple",
                         None,
                         False,
                         {"AutoSubmit": ["1", "-bool yes"]})
        version = self.environ.getosver()
        versionsplit = version.split(".")
        if len(versionsplit) >= 2:
            minorversion = int(versionsplit[1])
        else:
            minorversion = 0
        if minorversion >= 10:
            self.addKVEditor("ThirdPartyDataSubmit",
                             "defaults",
                             "/Library/Application Support/CrashReporter/" +
                             "DiagnosticMessagesHistory.plist",
                             "",
                             {"ThirdPartyDataSubmit": ["0", "-bool no"]},
                             "present",
                             "",
                             "Automatically submits diagnostic information " +
                             "to third-party developers",
                             None,
                             False,
                             {"ThirdPartyDataSubmit": ["1", "-bool yes"]})
