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
Created on Apr 27, 2015
The screen saver should be set to turn on after a period of inactivity, and
should require a password to dismiss. Disabling the screen saver would disable
the screen lock. This rule removes the functionality of using a 'hot corner'
to disable the screen saver.
@author: Breen Malmberg
@change: 2015/10/08 eball Help text/PEP8 cleanup
@change: 2016/02/02 ekkehard Enable for OS X El Capitan 10.11
@change: 2017/07/17 ekkehard - make eligible for macOS High Sierra 10.13
@change: 2017/11/13 ekkehard - make eligible for OS X El Capitan 10.11+
@change: 2018/06/08 ekkehard - make eligible for macOS Mojave 10.14
@change: 2019/03/12 ekkehard - make eligible for macOS Sierra 10.12+
@change: 2019/08/07 ekkehard - enable for macOS Catalina 10.15 only
'''


import os
import re
import traceback
from ..rule import Rule
from ..logdispatcher import LogPriority
from ..CommandHelper import CommandHelper


class SetSSCorners(Rule):
    '''classdocs'''

    def __init__(self, config, environ, logger, statechglogger):
        '''
        Constructor
        '''
        Rule.__init__(self, config, environ, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 188
        self.rulename = 'SetSSCorners'
        self.compliant = True
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.rootrequired = False
        self.sethelptext()
        self.guidance = ['CIS', '1.4.8.1', '1.4.8.2']
        self.applicable = {'type': 'white',
                           'os': {'Mac OS X': ['10.15', 'r', '10.15.10']},
                           'noroot': True}

        # set up configuration items for this rule
        datatype = 'bool'
        key = 'SETSSCORNERS'
        instructions = 'To disable this rule, set the value of ' + \
            'SetSSCorners to False'
        default = True
        self.ci = self.initCi(datatype, key, instructions, default)

    def setVars(self):
        ''' '''

        ssfound = False

        try:

            self.homedir = self.environ.geteuidhome()
            self.conffile = self.homedir + \
                '/Library/Preferences/com.apple.dock.plist'
            self.readcmd = '/usr/bin/defaults read ' + '\"' + \
                self.conffile + '\"'
            self.optlist = ["wvous-bl-corner",
                            "wvous-br-corner",
                            "wvous-tl-corner",
                            "wvous-tr-corner"]
            self.optdict = {}
            self.writecmd = '/usr/bin/defaults write ' + '\"' + \
                self.conffile + '\"'
            self.detailedresults = ""
            self.cmdhelper = CommandHelper(self.logger)
            self.compliant = True
            self.moddict = {}
            for opt in self.optlist:
                self.cmdhelper.executeCommand(self.readcmd + ' ' + opt)
                errout = self.cmdhelper.getErrorString()
                output = self.cmdhelper.getOutputString()
                if not re.search('^6', output) and not errout:
                    self.optdict[opt] = output
                if re.search('^5', output):
                    ssfound = True

            for opt in self.optlist:
                if opt not in self.optdict:
                    self.optdict[opt] = 1
            if not ssfound:
                self.optdict["wvous-tl-corner"] = 5
            for opt in self.optdict:
                if self.optdict[opt] == 6:
                    self.optdict[opt] = 1

        except Exception:
            raise

    def report(self):
        ''' '''

        found = False
        self.detailedresults = ""

        try:

            if self.environ.geteuid() == 0:
                self.detailedresults += '\nYou are running SetSSCorners ' + \
                    'in Admin mode. This rule must be run in regular ' + \
                    'user context.'
                self.logger.log(LogPriority.INFO, self.detailedresults)
                return False

            self.setVars()

            if os.path.exists(self.conffile):
                for item in self.optdict:
                    self.cmdhelper.executeCommand(self.readcmd + ' ' + item)
                    output = self.cmdhelper.getOutputString()
                    errout = self.cmdhelper.getErrorString()
                    sitem = item.split('-')
                    location = str(sitem[1])
                    if errout:
                        self.compliant = False
                        self.detailedresults += '\nSpecified key not found : ' \
                            + str(item)
                    elif re.search('^6', output):
                        self.compliant = False
                        self.detailedresults += '\nIncorrect configuration ' + \
                            'value for key: ' + str(item)
                        self.moddict['wvous-' + location + '-modifier'] = 1048576
                    elif re.search('^5', output):
                        found = True
                        self.moddict['wvous-' + location + '-modifier'] = 0
                if not found:
                    self.compliant = False
                    self.detailedresults += '\nNo corner is configured to ' + \
                        'activate screen saver'

            else:
                self.compliant = False
                self.detailedresults += '\nRequired configuration file ' + \
                    'com.apple.dock.plist could not be found'

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.detailedresults += traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

    def fix(self):
        ''' '''

        success = True
        self.detailedresults = ""

        try:

            if self.environ.geteuid() == 0:
                self.detailedresults += '\nYou are running SetSSCorners ' + \
                    'in Admin mode. This rule must be run in regular ' + \
                    'user context.'
                self.logger.log(LogPriority.INFO, self.detailedresults)
                return False

            if self.ci.getcurrvalue():

                if os.path.exists(self.conffile):
                    for item in self.optdict:
                        cmd = self.writecmd + ' ' + item + ' -int ' + \
                            str(self.optdict[item])
                        self.cmdhelper.executeCommand(cmd)
                        errout = self.cmdhelper.getErrorString()

                        if errout:
                            success = False
                            self.detailedresults += '\nUnable to execute ' + \
                                'command ' + str(cmd)
                if self.moddict:
                    for item in self.moddict:
                        cmd = self.writecmd + ' ' + item + ' -int ' + \
                            str(self.moddict[item])
                        self.cmdhelper.executeCommand(cmd)
                        errout = self.cmdhelper.getErrorString()
                        if errout:
                            success = False

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.detailedresults += traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", success,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return success
