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
Created on Jan 22, 2016
This rule will configure the diagnostic reporting in macOS (OS X).

@operating system: Mac
@author: Eric Ball
@change: 2016/01/22 eball Original implementation
@change: 2017/07/07 ekkehard - make eligible for macOS High Sierra 10.13
@change: 2017/08/28 ekkehard - Added self.sethelptext()
@change: 2017/11/13 ekkehard - make eligible for OS X El Capitan 10.11+
@change: 2018/06/08 ekkehard - make eligible for macOS Mojave 10.14
@change: 2019/03/12 ekkehard - make eligible for macOS Sierra 10.12+
@change: 2019/08/07 ekkehard - enable for macOS Catalina 10.15 only
'''


from ruleKVEditor import RuleKVEditor


class ConfigureDiagnosticReporting(RuleKVEditor):
    def __init__(self, config, environ, logdispatcher, statechglogger):
        RuleKVEditor.__init__(self, config, environ, logdispatcher,
                              statechglogger)
        self.rulenumber = 3
        self.rulename = 'ConfigureDiagnosticReporting'
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.sethelptext()
        self.rootrequired = True
        self.guidance = []
        self.applicable = {'type': 'white',
                           'os': {'Mac OS X': ['10.15', 'r', '10.15.10']}}
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
