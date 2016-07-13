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
@change: 2015/10/07 eball Help text cleanup
@change: 2016/03/14 eball Fixed possible casting error, PEP8 cleanup
'''
from __future__ import absolute_import
import traceback
import os
import re
import subprocess
import time

from ..rule import Rule
from ..logdispatcher import LogPriority
from ..stonixutilityfunctions import resetsecon


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
        self.helptext = '''The MuteMic rule will mute or set the microphone \
input levels to zero. This can help prevent a compromised computer from being \
used as a listening device. On most platforms input volume changes require no \
privileges so this setting can be easily undone.'''
        self.rootrequired = False
        self.mutemicrophone = self.__initializeMuteMicrophone()
        self.guidance = ['CIS']
        self.applicable = {'type': 'white',
                           'family': ['linux', 'solaris', 'freebsd'],
                           'os': {'Mac OS X': ['10.9', 'r', '10.12.10']}}
        self.pulsedefaults = '/etc/pulse/default.pa'

    def __initializeMuteMicrophone(self):
        '''
        Private method to initialize the configurationitem object for the
        MUTEMICROPHONE bool.
        @return: configuration object instance
        @author: dkennel
        '''
        datatype = 'bool'
        key = 'mutemicrophone'
        instructions = '''If set to yes or true the MUTEMICROPHONE action \
will mute the microphone. This rule should always be set to TRUE with few \
valid exceptions.'''
        default = True
        myci = self.initCi(datatype, key, instructions, default)
        return myci

    def findPulseMic(self):
        '''
        This method will attempt to determine the indexes of the sources that
        contain microphone inputs. It will return a list of strings that are
        index numbers. It is legal for the list to be of zero length in the
        cases where pulse is not running or there are no sources with
        microphones.

        @author: dkennel
        @return: list of numbers in string format
        '''
        indexlist = []
        index = ''
        listcmd = '/usr/bin/pacmd list-sources'
        proc = subprocess.Popen(listcmd, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, shell=True)
        pulsesourcelist = proc.stdout.readlines()
        for line in pulsesourcelist:
            if re.search('index:', line):
                self.logdispatch.log(LogPriority.DEBUG,
                                     ['MuteMic.findPulseMic',
                                      'Scanning ' + line])
                try:
                    elements = line.split(' ')
                    for element in elements:
                        if re.search('\d', element):
                            index = int(element)
                except (KeyboardInterrupt, SystemExit):
                    # User initiated exit
                    raise
                except ValueError:
                    self.logdispatch.log(LogPriority.DEBUG,
                                         ['MuteMic.findPulseMic',
                                          'Oops! Tried to convert non-integer '
                                          + element])
            if re.search('input-microphone', line):
                self.logdispatch.log(LogPriority.DEBUG,
                                     ['MuteMic.findPulseMic',
                                      'Found mic at index ' + str(index)])
                index = str(index)
                if index not in indexlist:
                    indexlist.append(index)
        return indexlist

    def checkpulseaudio(self):
        '''
        Report method for checking the pulse audio configuration to ensure that
        the Microphone defaults to muted. Returns True if the system is
        compliant

        @author: dkennel
        @return: Bool
        '''
        linesfound = 0
        if not os.path.exists(self.pulsedefaults):
            return True

        expectedlines = []
        try:
            indexlist = self.findPulseMic()
            if len(indexlist) > 0:
                for index in indexlist:
                    line = 'set-source-mute ' + index + ' 1\n'
                    expectedlines.append(line)

                fhandle = open(self.pulsedefaults, 'r')
                defaultsdata = fhandle.readlines()
                fhandle.close()

                for eline in expectedlines:
                    for pulseline in defaultsdata:
                        if re.search(eline, pulseline):
                            self.logdispatch.log(LogPriority.DEBUG,
                                                 ['MuteMic.findPulseMic',
                                                  'Found expected line ' +
                                                  str(pulseline)])
                            linesfound = linesfound + 1
                if linesfound == len(indexlist):
                    return True
                else:
                    return False
        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception, err:
            self.rulesuccess = False
            self.detailedresults = self.detailedresults + "\n" + str(err) + \
                " - " + str(traceback.format_exc())
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        return True

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
            chklevels = "/usr/bin/osascript -e 'get the input volume of " + \
                "(get volume settings)'"
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
                    elif not level.isdigit():
                        warning = 'Output from command "' + chklevels + \
                            '" expected to be "missing value" or a number; ' + \
                            'actual output was: "' + level + '"'
                        self.logdispatch.log(LogPriority.WARNING, warning)
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
            if level > 0 and self.checkpulseaudio():
                self.compliant = False
                self.detailedresults = 'Microphone input not set to zero!'
            elif level > 0 and not self.checkpulseaudio():
                self.compliant = False
                self.detailedresults = 'Microphone input not set to zero! ' + \
                    'and microphone not set for default mute in Pulse ' + \
                    'Audio defaults.'
            elif level == 0 and not self.checkpulseaudio():
                self.compliant = False
                self.detailedresults = 'Microphone not set for default ' + \
                    'mute in Pulse Audio defaults.'
            else:
                self.compliant = True
                self.detailedresults = 'Microphone input set to zero.'
        self.formatDetailedResults("report", self.compliant,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

    def fixPulseAudio(self):
        '''
        This method adds lines to the end of the pulse audio services default
        settings definitions file to ensure that the microphones are muted by
        default.

        @author: dkennel
        '''
        if not os.path.exists(self.pulsedefaults):
            return True

        if self.checkpulseaudio():
            return True

        expectedlines = []
        try:
            indexlist = self.findPulseMic()
            if len(indexlist) > 0:
                for index in indexlist:
                    line = 'set-source-mute ' + index + ' 1\n'
                    expectedlines.append(line)

                fhandle = open(self.pulsedefaults, 'r')
                defaultsdata = fhandle.readlines()
                fhandle.close()

                for eline in expectedlines:
                    elinefound = False
                    for pulseline in defaultsdata:
                        if re.search(eline, pulseline):
                            self.logdispatch.log(LogPriority.DEBUG,
                                                 ['fixPulseAudio',
                                                  'Found expected line ' +
                                                  str(pulseline)])
                            elinefound = True
                    if not elinefound:
                        defaultsdata.append(eline)
                        self.logdispatch.log(LogPriority.DEBUG,
                                             ['fixPulseAudio',
                                              'Appended line ' + str(eline)])
                tempfile = self.pulsedefaults + '.stonixtmp'
                whandle = open(tempfile, 'w')
                for line in defaultsdata:
                    whandle.write(line)
                whandle.close()
                mytype1 = 'conf'
                mystart1 = self.currstate
                myend1 = self.targetstate
                myid1 = '0201001'
                self.statechglogger.recordfilechange(self.pulsedefaults,
                                                     tempfile, myid1)
                event1 = {'eventtype': mytype1,
                          'startstate': mystart1,
                          'endstate': myend1,
                          'myfile': self.pulsedefaults}
                self.statechglogger.recordchgevent(myid1, event1)
                os.rename(tempfile, self.pulsedefaults)
                os.chown(self.pulsedefaults, 0, 0)
                os.chmod(self.pulsedefaults, 420)  # int of 644
                resetsecon(self.pulsedefaults)

        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception, err:
            self.rulesuccess = False
            self.detailedresults = self.detailedresults + "\n" + str(err) + \
                " - " + str(traceback.format_exc())
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)

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
        if os.path.exists(self.pulsedefaults) and self.environ.geteuid() == 0:
            self.fixPulseAudio()

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
