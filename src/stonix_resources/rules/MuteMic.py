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
Created on Jul 7, 2014

This class handles muting the microphone input levels.

@author: dkennel
@change: 2014/10/17 ekkehard OS X Yosemite 10.10 Update
@change: 2014/12/15 dkennel Fix for Macs with no microphones (and ergo no input)
@change: 2015/04/15 dkennel updated for new isApplicable

'''
from __future__ import absolute_import
import traceback
import os
import re
import subprocess
import time

from ..rule import Rule
from ..logdispatcher import LogPriority
from ..CommandHelper import CommandHelper


class MuteMic(Rule):
    '''
    This class is responsible for muting the microphone input levels to
    help prevent attacks that would attempt to use the system as a listening
    device.

    @author: dkennel
    '''

    def __init__(self, config, environ, logger, statechglogger):
        '''
        Constructor
        '''
        Rule.__init__(self, config, environ, logger, statechglogger)
        self.rulenumber = 201
        self.rulename = 'MuteMic'
        self.formatDetailedResults("initialize")
        self.mandatory = False
        self.helptext = '''The MuteMic rule will mute or set the microphone input levels to
zero. This can help prevent a compromised computer from being used as a
listening device. On most platforms input volume changes require no privileges
so this setting can be easily undone.'''
        self.rootrequired = False
        self.mutemicrophone = self.__initializeMuteMicrophone()
        self.guidance = ['CIS']
        self.applicable = {'type': 'white',
                           'family': ['linux', 'solaris', 'freebsd'],
                           'os': {'Mac OS X': ['10.9', 'r', '10.10.10']}}

    def __initializeMuteMicrophone(self):
        '''
        Private method to initialize the configurationitem object for the
        MUTEMICROPHONE bool.
        @return: configuration object instance
        @author: dkennel
        '''
        datatype = 'bool'
        key = 'mutemicrophone'
        instructions = '''If set to yes or true the MUTEMICROPHONE action will mute the
microphone. This rule should always be set to TRUE with few valid exceptions.'''
        default = True
        myci = self.initCi(datatype, key, instructions, default)
        return myci

    def report(self):
        '''
        Report method for MuteMic. Uses the platform native method to read
        the input levels. Levels must be zero to pass. Note for Linux the use
        of amixer presumes pulseaudio.

        @author: dkennel
        '''
        darwin = False
        chklevels = None
        if self.environ.getosfamily() == 'darwin':
            darwin = True
            chklevels = "/usr/bin/osascript -e 'get the input volume of (get volume settings)'"
        elif os.path.exists('/usr/bin/amixer'):
            chklevels = '/usr/bin/amixer sget Capture Volume'

        if chklevels != None:
            level = 99
            try:
                if darwin:
                    self.logdispatch.log(LogPriority.DEBUG,
                                         ['MuteMic.report',
                                          'Doing Mac level check'])
                    proc = subprocess.Popen(chklevels, stdout=subprocess.PIPE,
                                            stderr=subprocess.PIPE, shell=True)
                    level = proc.stdout.readline()
                    level = level.strip()
                    if level == 'missing value':
                        level = 0
                    else:
                        int(level)
                else:
                    self.logdispatch.log(LogPriority.DEBUG,
                                         ['MuteMic.report',
                                          'Doing amixer level check'])
                    proc = subprocess.Popen(chklevels, stdout=subprocess.PIPE,
                                            stderr=subprocess.PIPE,
                                            shell=True)
                    results = proc.stdout.readlines()
                    zeroed = True
                    level = 0
                    self.logdispatch.log(LogPriority.DEBUG,
                                         ['MuteMic.report',
                                          'results = ' + str(results)])
                    for line in results:
                        if re.search('Capture [0-9]', line) and not \
                        re.search('Limits:', line):
                            match = re.search('Capture [0-9]+', line)
                            capturevol = match.group(0).split()[1]
                            try:
                                vol = int(capturevol)
                            except(ValueError):
                                zeroed = False
                                self.logdispatch.log(LogPriority.DEBUG,
                                                     ['MuteMic.report',
                                                      'zeroed set to False VE'])
                            if vol != 0:
                                zeroed = False
                                self.logdispatch.log(LogPriority.DEBUG,
                                                     ['MuteMic.report',
                                                      'zeroed set to False'])
                    if not zeroed:
                        level = 100

            except (KeyboardInterrupt, SystemExit):
                # User initiated exit
                raise
            except Exception, err:
                self.rulesuccess = False
                self.detailedresults = self.detailedresults + "\n" + str(err) + \
                " - " + str(traceback.format_exc())
                self.logdispatch.log(LogPriority.ERROR, self.detailedresults)

            try:
                level = int(level)
            except(ValueError):
                level = 100
            except (KeyboardInterrupt, SystemExit):
                # User initiated exit
                raise
            except Exception, err:
                self.rulesuccess = False
                self.detailedresults = self.detailedresults + "\n" + str(err) + \
                " - " + str(traceback.format_exc())
                self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
            self.logdispatch.log(LogPriority.DEBUG,
                                 ['MuteMic.report',
                                  'Value of level: ' + str(level)])
            if level > 0:
                self.compliant = False
                self.detailedresults = 'Microphone input not set to zero!'
            else:
                self.compliant = True
                self.detailedresults = 'Microphone input set to zero.'
        self.formatDetailedResults("report", self.compliant,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

    def fix(self):
        '''
        Fix method for MuteMic. Uses platform native methods to set the input
        levels to zero. Note for Linux the use of amixer presumes pulseaudio.

        @author: dkennel
        '''
        if self.mutemicrophone.getcurrvalue() == False:
            return
        setlevels = None
        if self.environ.getosfamily() == 'darwin':
            setlevels = "/usr/bin/osascript -e 'set volume input volume 0'"
        elif os.path.exists('/usr/bin/amixer'):
            setlevels = "/usr/bin/amixer sset Capture Volume 0,0 mute"

        if setlevels != None:
            try:
                proc = subprocess.Popen(setlevels, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, shell=True)
                # Sleep here to give amixer and pulse a chance to catch up
                time.sleep(5)
                self.detailedresults = self.detailedresults + \
                'Attempted to set volume to zero.'
            except (KeyboardInterrupt, SystemExit):
                # User initiated exit
                raise
            except Exception, err:
                self.rulesuccess = False
                self.detailedresults = self.detailedresults + "\n" + str(err) + \
                " - " + str(traceback.format_exc())
                self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess,
                                   self.detailedresults)

    def undo(self):
        '''
        Undo method for MuteMic. Sets the input levels to 100.

        @author: dkennel
        '''
        setlevels = None
        if self.environ.getosfamily() == 'darwin':
            setlevels = "/usr/bin/osascript -e 'set volume input volume 100'"
        elif os.path.exists('/usr/bin/amixer'):
            setlevels = '/usr/bin/amixer sset Capture Volume 65536,65536 unmute'

        try:
            subprocess.call(setlevels, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            shell=True)
        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception, err:
            self.rulesuccess = False
            self.detailedresults = self.detailedresults + "\n" + str(err) + \
            " - " + str(traceback.format_exc())
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
