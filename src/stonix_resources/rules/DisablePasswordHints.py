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
Created on May 24, 2013
This is a rule to disable password hints, specifically started for the Mac.

@operating system: generic
@author: Roy Nielsen
@change: 02/13/2014 ekkehard Implemented self.detailedresults flow
@change: 02/13/2014 ekkehard Implemented isapplicable
@change: 2014/10/17 ekkehard OS X Yosemite 10.10 Update
@change: 2015/04/15 dkennel updated for new isApplicable
@change: 2017/07/07 ekkehard - make eligible for macOS High Sierra 10.13
@change: 2017/08/28 rsn Fixing to use new help text methods
@change: 2017/11/13 ekkehard - make eligible for OS X El Capitan 10.11+
@change: 2018/06/08 ekkehard - make eligible for macOS Mojave 10.14
@change: 2019/03/12 ekkehard - make eligible for macOS Sierra 10.12+
@change: 2019/08/07 ekkehard - enable for macOS Catalina 10.15 only
'''

from ..ruleKVEditor import RuleKVEditor


class DisablePasswordHints(RuleKVEditor):
    '''This class disables Auto Login on the system.'''
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
        self.applicable = {'type': 'white',
                           'os': {'Mac OS X': ['10.15', 'r', '10.15.10']}}
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
        self.sethelptext()

