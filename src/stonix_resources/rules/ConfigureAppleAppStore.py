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
    '''defaults write /Library/Preferences/com.apple.commerce AutoUpdate -bool [TRUE|FALSE]
    
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
