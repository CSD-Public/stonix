###############################################################################
#                                                                             #
# Copyright 2015-2018.  Los Alamos National Security, LLC. This material was       #
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
Created on May 9, 2018
Rule that secures the BIND DNS server if installed

@author: dwalker
'''
from __future__ import absolute_import
import os
import re
import traceback
import glob
from ..CommandHelper import CommandHelper
from ..rule import Rule
from ..stonixutilityfunctions import readFile, setPerms, createFile
from ..stonixutilityfunctions import checkPerms, iterate, writeFile, resetsecon
from ..logdispatcher import LogPriority
from ..pkghelper import Pkghelper
import sys


class SecureBIND(Rule):
    '''
    classdocs
    '''

    def __init__(self, config, environ, logger, statechglogger):
        Rule.__init__(self, config, environ, logger, statechglogger)

        self.logger = logger
        self.rulenumber = 93
        self.rulename = 'SecureBIND'
        self.mandatory = False
        self.formatDetailedResults("initialize")
        self.guidance = ['NSA 3.13.2.2, CIS, NSA(2.2.2.2), cce-4006-3,4173-1']
        self.applicable = {'type': 'white',
                           'family': ['linux', 'solaris', 'freebsd'],
                           'os': {'Mac OS X': ['10.11', 'r', '10.13.10']},
                           'fisma': 'high'}

        # configuration item instantiation
        datatype = "bool"
        key = "SECUREBIND"
        instructions = "To disable removeable storage devices on this " + \
            "system, set the value of DISABLESTORAGE to True"
        default = True
        self.storageci = self.initCi(datatype, key, instructions, default)
        self.pcmcialist = ['pcmcia-cs', 'kernel-pcmcia-cs', 'pcmciautils']
        self.pkgremovedlist = []
        self.iditerator = 0
        self.created = False
        self.daemonpath = os.path.abspath(os.path.join(os.path.dirname(sys.argv[0]))) + "/stonix_resources/disablestorage"
        self.sethelptext()