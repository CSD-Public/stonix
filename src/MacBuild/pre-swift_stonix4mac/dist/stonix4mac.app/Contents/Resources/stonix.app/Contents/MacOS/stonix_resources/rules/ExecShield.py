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
Created on Sep 5, 2014
This class is responsible for auditing and correcting the setting of the
ExecShield overflow prevention and the randomize_va_space ASLR mechanism.
@author: dkennel
@change: 2015/04/15 dkennel updated for new isApplicable
@change: 2015/10/07 eball Help text/PEP8 cleanup
@change: 2016/04/26 ekkehard Results Formatting
'''
from __future__ import absolute_import
import os
import re
import traceback
import subprocess

from ..rule import Rule
from ..stonixutilityfunctions import resetsecon
from ..logdispatcher import LogPriority
from ..KVEditorStonix import KVEditorStonix


class ExecShield(Rule):
    '''
    This class is responsible for auditing and correcting the setting of the
    ExecShield overflow prevention and the virtual address space randomizer.
    On most modern Linux distributions these are correct by default.

    @author: dkennel
    '''

    def __init__(self, config, environ, logger, statechglogger):
        '''
        Constructor
        '''
        Rule.__init__(self, config, environ, logger, statechglogger)
        self.rulenumber = 63
        self.rulename = 'ExecShield'
        self.formatDetailedResults("initialize")
        self.mandatory = False
        self.helptext = '''The ExecShield rule will audit, and if needed \
correct the settings of the kernel functions that provide protection against \
memory corruption attacks such as buffer overflows. These features include \
ExecShield, which prevents execution of memory locations that should only \
hold data, and va_randomize, which randomizes the locations of various memory \
regions.'''
        self.rootrequired = True
        self.comment = re.compile('^#|^;')
        self.sysctlconf = '/etc/sysctl.conf'
        self.tmpPath = '/etc/sysctl.conf.tmp'
        self.comment = re.compile('^#|^;')
        self.guidance = ['CCE-27007-4', 'CCE-26999-3']
        self.applicable = {'type': 'white',
                           'family': ['linux']}
        self.varandomcompliant = False
        self.shieldprocpath = '/proc/sys/kernel/exec-shield'
        if os.path.exists(self.shieldprocpath):
            self.execshieldapplies = True
            self.directives = {'kernel.exec-shield': '1',
                               'kernel.randomize_va_space': '2'}
        else:
            self.execshieldapplies = False
            self.directives = {'kernel.randomize_va_space': '2'}
        self.execshieldcompliant = False
        self.ExecCI = self.__initializeExecShield()

    def __initializeExecShield(self):
        '''
        Private method to initialize the configurationitem object for the
        EXECSHIELD bool.
        @return: configuration object instance
        @author: dkennel
        '''
        datatype = 'bool'
        key = 'execshield'
        instructions = 'If set to yes or true the EXECSHIELD action will, ' + \
            'if needed correct the kernel settings for the ExecShield and ' + \
            'virtual address randomization functions. This should be safe ' + \
            'for all systems.'
        default = True
        myci = self.initCi(datatype, key, instructions, default)
        return myci

    def checkproc(self, procpath):
        '''
        Check for the value of a specific key in proc. Return that value.
        This method is designed for proc keys that only return a single value.

        @param procpath string: fully qualified path to the element to be
        checked.
        @return: string version of the value at that proc location.
        @author: dkennel
        '''
        myval = ''
        try:
            rhandle = open(procpath, 'r')
            myval = rhandle.read()
            rhandle.close()
            myval = myval.strip()
            return myval
        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception:
            self.detailedresults = 'ExecShield.checkproc: '
            self.detailedresults += traceback.format_exc()
            self.rulesuccess = False
            self.logdispatch.log(LogPriority.ERROR,
                                 ['ExecShield.checkproc',
                                  self.detailedresults])

    def report(self):
        '''
        Main report method. We rely on the active values in proc to make our
        compliant/not-compliant decision.

        @author dkennel
        '''
        self.detailedresults = ''
        try:
            if self.execshieldapplies:
                execval = int(self.checkproc(self.shieldprocpath))
                if execval == 1:
                    self.execshieldcompliant = True
                    self.detailedresults += 'Exec-Shield present and ' + \
                        'compliant\n'
                else:
                    self.detailedresults += 'Exec-Shield present but not ' + \
                        'compliant. Current value: ' + str(execval) + '\n'
            va_path = '/proc/sys/kernel/randomize_va_space'
            vaval = int(self.checkproc(va_path))
            if vaval == 2:
                self.varandomcompliant = True
                self.detailedresults += 'Randomize_va_space compliant\n'
            else:
                self.detailedresults += 'Randomize_va_space not compliant. ' + \
                    'Current value: ' + str(vaval) + '\n'
            if self.execshieldapplies:
                if self.execshieldcompliant and self.varandomcompliant:
                    self.compliant = True
            else:
                if self.varandomcompliant:
                    self.compliant = True
        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception:
            self.detailedresults = 'ExecShield.report: '
            self.detailedresults += traceback.format_exc()
            self.rulesuccess = False
            self.logdispatch.log(LogPriority.ERROR,
                                 self.detailedresults)
        self.formatDetailedResults("report", self.compliant,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

    def fix(self):
        '''
        Main fix method. We update the current vaules in proc via shell
        commands and set the correct settings in /etc/sysctl.conf since our
        assumption is that if it didn't pass it's because it's been overridden
        in sysctl.conf.

        @author: dkennel
        '''
        self.detailedresults = ""
        self.rulesuccess = False
        if self.ExecCI.getcurrvalue():
            try:
                kvtype = "conf"
                intent = "present"
                self.editor = KVEditorStonix(self.statechglogger, self.logdispatch,
                                             kvtype, self.sysctlconf, self.tmpPath,
                                             self.directives, intent, "openeq")
                if self.execshieldapplies:
                    cmdshield = '/sbin/sysctl -w kernel.exec-shield=1'
                    subprocess.call(cmdshield, shell=True)
                cmdvarand = '/sbin/sysctl -w kernel.randomize_va_space=2'
                subprocess.call(cmdvarand, shell=True)
    
                if not self.editor.report():
                    if self.editor.fixables:
                        myid = '0063001'
                        self.editor.setEventID(myid)
                        if not self.editor.fix():
                            return False
                        elif not self.editor.commit():
                            return False
                        os.chown(self.sysctlconf, 0, 0)
                        os.chmod(self.sysctlconf, 420)
                        resetsecon(self.sysctlconf)
    
            except (KeyboardInterrupt, SystemExit):
                # User initiated exit
                raise
            except Exception:
                self.detailedresults = 'ExecShield.fix: '
                self.detailedresults += traceback.format_exc()
                self.rulesuccess = False
                self.logdispatch.log(LogPriority.ERROR,
                                     self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
