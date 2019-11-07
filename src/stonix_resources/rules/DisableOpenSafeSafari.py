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
@author: dwalker 1/13/2015
@change: 2015/04/15 updated for new isApplicable
@change: 2017/07/07 ekkehard - make eligible for macOS High Sierra 10.13
@change: 2017/08/28 rsn Fixing to use new help text methods
@change: 2017/11/13 ekkehard - make eligible for OS X El Capitan 10.11+
@change: 2018/06/08 ekkehard - make eligible for macOS Mojave 10.14
@change: 2019/03/12 ekkehard - make eligible for macOS Sierra 10.12+
@change: 2019/08/07 ekkehard - enable for macOS Catalina 10.15 only
'''

from ruleKVEditor import RuleKVEditor
import traceback
from logdispatcher import LogPriority


class DisableOpenSafeSafari(RuleKVEditor):
    def __init__(self, config, environ, logdispatcher, statechglogger):
        RuleKVEditor.__init__(self, config, environ, logdispatcher,
                              statechglogger)

        self.rulenumber = 270
        self.rulename = 'DisableOpenSafeSafari'
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.rootrequired = False
        # for compatibility with logging in rule.py's undo() method...
        self.logger = self.logdispatch
        self.guidance = []
        self.applicable = {'type': 'white',
                           'os': {'Mac OS X': ['10.15', 'r', '10.15.10']}}
        # init CIs
        datatype = 'bool'
        key = 'SAFESAFARI'
        instructions = "To prevent the open safe file after downloading " + \
        "feature being disabled, set the value of SAFESAFARI to False."
        default = True
        self.ci = self.initCi(datatype, key, instructions,
                                                default)
        self.addKVEditor("DisableOpenSafeSafari",
                         "defaults",
                         "~/Library/Preferences/com.apple.Safari.plist",
                         "",
                         {"AutoOpenSafeDownloads": ["0", "-bool no"]},
                         "present",
                         "",
                         "Disable open safe files after download in safari")
        self.sethelptext()

    def undo(self):
        '''Overriding parent undo method because there is no undo method for this
        rule due to the fact that this is a user context only rule and non
        administrators can't undo rule actions.


        '''
        try:
            self.detailedresults = "no undo available\n"
            self.logger.log(LogPriority.INFO, self.detailedresults)
        except(KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.INFO, self.detailedresults)
