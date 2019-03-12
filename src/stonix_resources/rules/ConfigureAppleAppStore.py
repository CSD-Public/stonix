###############################################################################
#                                                                             #
# Copyright 2018-2019.  Los Alamos National Security, LLC. This material was  #
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
@change: 2018/08/08 Original Implementation
@change: 2019/03/12 Updated
'''
from __future__ import absolute_import
import re
import types
from ..ruleKVEditor import RuleKVEditor
from ..CommandHelper import CommandHelper
from ..localize import APPLESOFTUPDATESERVER


class ConfigureAppleAppStore(RuleKVEditor):
    '''
    defaults write /Library/Preferences/com.apple.commerce AutoUpdate -bool [TRUE|FALSE]

    @author: ekkehard j. koch
    '''

###############################################################################

    def __init__(self, config, environ, logdispatcher, statechglogger):
        RuleKVEditor.__init__(self, config, environ, logdispatcher,
                              statechglogger)
        self.rulenumber = 263
        self.rulename = 'ConfigureAppleAppStore'
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.sethelptext()
        self.rootrequired = True
        self.guidance = ['CCE 14813-0', 'CCE 14914-6', 'CCE 4218-4',
                         'CCE 14440-2']
        self.applicable = {'type': 'white',
                           'os': {'Mac OS X': ['10.14', 'r', '10.14.10']}}

        if self.environ.getostype() == "Mac OS X":
        	self.addKVEditor("EnableAutomaticAppUpdate",
                            "defaults",
                            "/Library/Preferences/com.apple.commerce",
                            "",
                            {"AutoUpdate": ["1", "-bool yes"]},
                            "present",
                            "",
                            "Enable Automatic Application Update. " +
                            "This should be enabled.",
                            None,
                            False,
                            {"AutoUpdate": ["0", "-bool no"]})
               
        self.ch = CommandHelper(self.logdispatch)
        self.appstorehasnotrun = True

    def beforereport(self):
        success = True
        if self.appstorehasnotrun:
            self.appstorehasnotrun = False
        else:
            success = True
        return success

###############################################################################

    def formatValue(self, pValue):
        outputvalue = pValue
        datatype = type(outputvalue)
        if datatype == types.StringType:
            if not (outputvalue == ""):
                outputvalue = re.sub("\\\\n|\(|\)|\,|\'", "", outputvalue)
                outputvalue = re.sub("\s+", " ", outputvalue)
        elif datatype == types.ListType:
            for i, item in enumerate(outputvalue):
                item = re.sub("\\\\n|\(|\)|\,|\'", "", item)
                item = re.sub("\s+", " ", item)
                outputvalue[i] = item
        else:
            outputvalue = outputvalue
        return outputvalue
