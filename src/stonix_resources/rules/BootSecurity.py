###############################################################################
#                                                                             #
# Copyright 2015.  Los Alamos National Security, LLC. This material was       #
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
Created on Sep 17, 2015
The Boot Security rule configures the system to run a job at system boot time
that handles turning off potential vulnerability points such as: wifi,
bluetooth, microphones, and cameras.

@author: dkennel
'''

from __future__ import absolute_import
import traceback
import os
import re
import subprocess
import time

from ..rule import Rule
from ..logdispatcher import LogPriority


class BootSecurity(object):
    '''
    The Boot Security rule configures the system to run a job at system boot time
    that handles turning off potential vulnerability points such as: wifi,
    bluetooth, microphones, and cameras.
    '''

    def __init__(self, config, environ, logger, statechglogger):
        '''
        Constructor
        '''
        Rule.__init__(self, config, environ, logger, statechglogger)
        self.rulenumber = 18
        self.rulename = 'BootSecurity'
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.helptext = '''The BootSecurity rule configures the system to run a job at
system boot time that ensures that wifi, bluetooth, and cameras are turned off
and that microphone inputs are muted. This helps ensure that the system is in a
secure state at initial startup.'''
        self.rootrequired = False
        self.mutemicrophone = self.__initializeMuteMicrophone()
        self.guidance = []
        self.applicable = {'type': 'white',
                           'family': ['linux', 'solaris', 'freebsd'],
                           'os': {'Mac OS X': ['10.9', 'r', '10.11.10']}}
        self.type = 'rclocal'
        if os.path.exists('/bin/systemctl'):
            self.type = 'systemd'
        elif os.path.exists('/sbin/launchd'):
            self.type = 'mac'

    def auditsystemd(self):
        pass

    def auditrclocal(self):
        pass

    def auditmac(self):
        pass

    def setsystemd(self):
        pass

    def setrclocal(self):
        pass

    def setmac(self):
        pass

    def report(self):
        pass

    def fix(self):
        pass

    def undo(self):
        pass
