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
Created on Mar 2, 2015

@author: dwalker
@change: 2015/04/15 dkennel updated for new isApplicable
@change: 2017/07/07 ekkehard - make eligible for macOS High Sierra 10.13
@change: 2017/08/28 rsn Fixing to use new help text methods
@change: 2017/11/13 ekkehard - make eligible for OS X El Capitan 10.11+
@change: 2018/06/08 ekkehard - make eligible for macOS Mojave 10.14
@change: 2019/03/12 ekkehard - make eligible for macOS Sierra 10.12+
'''
from __future__ import absolute_import
from ..ruleKVEditor import RuleKVEditor


class EncryptSwap(RuleKVEditor):
    '''
    This rule is a user-context only rule meaning, if stonix is run as root
    this rule should not show up in the GUI or be able to be run through the
    CLI.  In addition, when this rule is being run in user context, there
    is no undo.
    '''
    def __init__(self, config, environ, logger, statechglogger):
        RuleKVEditor.__init__(self, config, environ, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 101
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.rulename = "EncryptSwap"
        self.applicable = {'type': 'white',
                           'os': {'Mac OS X': ['10.12', 'r', '10.14.10']}}
        self.addKVEditor("swapEncrypt",
                         "defaults",
                         "/Library/Preferences/com.apple.virtualMemory",
                         "",
                         {"UseEncryptedSwap": ["1", "-bool yes"]},
                          "present",
                          "",
                          "Secure Virtual memory.",
                          None,
                          False,
                          {})
        self.sethelptext()
