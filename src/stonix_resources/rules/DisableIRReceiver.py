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
Created on Sep 5, 2013

@author: dwalker
@change: 2014/03/18 ekkehard re-factored to be ruleKVEditor Rule
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
                           'os': {'Mac OS X': ['10.15', 'r', '10.15.10']}}
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
