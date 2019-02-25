###############################################################################
#                                                                             #
# Copyright 2015-2019.  Los Alamos National Security, LLC. This material was  #
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
Created on Mar 2, 2015

@author: dwalker
@change: 2015/04/15 dkennel updated for new isApplicable
@change: 2017/07/07 ekkehard - make eligible for macOS High Sierra 10.13
@change: 2017/08/28 rsn Fixing to use new help text methods
@change: 2017/11/13 ekkehard - make eligible for OS X El Capitan 10.11+
@change: 2018/06/08 ekkehard - make eligible for macOS Mojave 10.14
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
                           'os': {'Mac OS X': ['10.11', 'r', '10.14.10']}}
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
