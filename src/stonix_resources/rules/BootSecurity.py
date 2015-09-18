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
    The Boot Security rule configures the system to run a job at system boot
    time that handles turning off potential vulnerability points such as: wifi,
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
                           'family': ['linux'],
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
        fmode = 436  # Integer representation of 664
        unitFileContents = """[Unit]
Description=Stonix Boot Security
After=network.target

[Service]
ExecStart=/usr/bin/stonix_resources/stonixBootSecurity-Linux.py

[Install]
WantedBy=multi-user.target
"""
        unitFilePath = '/etc/systemd/system/stonixBootSecurity.service'
        whandle = open(unitFilePath, 'w')
        whandle.write(unitFileContents)
        whandle.close()
        os.chown(unitFilePath, 0, 0)
        os.chmod(unitFilePath, fmode)
        reloadcmd = '/bin/systemctl daemon-reload'
        try:
            proc = subprocess.Popen(reloadcmd, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, shell=True)
        except Exception:
            pass

    def setrclocal(self):
        rclocal = '/etc/rc.local'
        if os.path.islink(rclocal):
            paths = ['/etc/rc.d/rc.local', '/etc/init.d/rc.local']
            for rcpath in paths:
                if os.path.isfile(rcpath):
                    rclocal = rcpath
        tempfile = rclocal + '.stonixtmp'
        command = '/usr/bin/stonix_resources/stonixBootSecurity-Linux.py'
        fhandle = open(rclocal, 'r')
        rcdata = fhandle.readlines()
        fhandle.close()
        newdata = []
        inserted = False
        for line in rcdata:
            if re.search('^#', line):
                newdata.append(line)
            elif re.search('^\n', line) and not inserted:
                newdata.append(command)
                newdata.append(line)
                inserted = True
            elif re.search('exit 0', line) and not inserted:
                newdata.append(command)
                newdata.append(line)
                inserted = True
            else:
                newdata.append(line)
        if not inserted:
            newdata.append(command)
        whandle = open(tempfile, 'w')
        for line in newdata:
            whandle.write(line)
        whandle.close()
        mytype1 = 'conf'
        mystart1 = 'not configured'
        myend1 = 'configured'
        myid1 = '0018001'
        self.statechglogger.recordfilechange(rclocal, tempfile, myid1)
        event1 = {'eventtype': mytype1,
                  'startstate': mystart1,
                  'endstate': myend1,
                  'myfile': rclocal}
        self.statechglogger.recordchgevent(myid1, event1)
        os.rename(tempfile, rclocal)
        os.chown(rclocal, 0, 0)
        os.chmod(rclocal, 493)  # Integer of 0777
        self.rulesuccess = True
        self.currstate = 'configured'

    def setmac(self):
        pass

    def report(self):
        pass

    def fix(self):
        pass

    def undo(self):
        pass
