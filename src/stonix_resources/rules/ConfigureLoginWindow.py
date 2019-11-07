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
Created on Nov 1, 2012
This is a rule for Verifying and/or setting the state of the LoginWindow.

@operating system: Mac
@author: Roy Nielsen
@change: 02/13/2014 ekkehard Implemented self.detailedresults flow
@change: 02/13/2014 ekkehard Implemented isapplicable
@change: 2015/04/14 dkennel updated for new stype isApplicable
@change: 2015/10/07 eball Help text cleanup
@change: 2017/07/07 ekkehard - make eligible for macOS High Sierra 10.13
@change: 2017/08/28 ekkehard - Added self.sethelptext()
@change: 2017/11/13 ekkehard - make eligible for OS X El Capitan 10.11+
@change: 2018/06/08 ekkehard - make eligible for macOS Mojave 10.14
@change: 2019/03/12 ekkehard - make eligible for macOS Sierra 10.12+
@change: 2019/08/07 ekkehard - enable for macOS Catalina 10.15 only
'''


# The period was making python complain. Adding the correct paths to PyDev
# made this the working scenario.
from ruleKVEditor import RuleKVEditor


class ConfigureLoginWindow(RuleKVEditor):
    '''defaults read /Library/Preferences/com.apple.loginwindow SHOWFULLNAME'''
    def __init__(self, config, environ, logdispatcher, statechglogger):
        '''
        Constructor
        '''
        RuleKVEditor.__init__(self, config, environ, logdispatcher,
                              statechglogger)
        self.rulenumber = 170
        self.rulename = 'ConfigureLoginWindow'
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.sethelptext()
        self.rootrequired = True
        self.guidance = ['CCE-28310-1']
        self.applicable = {'type': 'white',
                           'os': {'Mac OS X': ['10.15', 'r', '10.15.10']}}
        self.addKVEditor("LoginNamePassword",
                         "defaults",
                         "/Library/Preferences/com.apple.loginwindow",
                         "",
                         {"SHOWFULLNAME": ["1", "-bool yes"]},
                         "present",
                         "",
                         "Forces the user to enter a username and " +
                         "password at the login window when enabled.",
                         None,
                         False,
                         {"SHOWFULLNAME": ["0", "-bool no"]})
        self.addKVEditor("DisableConsoleAccess",
                         "defaults",
                         "/Library/Preferences/com.apple.loginwindow",
                         "",
                         {"DisableConsoleAccess": ["1", "-bool yes"]},
                         "present",
                         "",
                         'If console login is enabled, the user can type ' +
                         '">console" for the user name to get a console ' +
                         'login.',
                         None,
                         False,
                         {"DisableConsoleAccess": ["0", "-bool no"]})
