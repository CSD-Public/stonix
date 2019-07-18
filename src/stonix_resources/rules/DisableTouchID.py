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
Created on May 15, 2017

@author: Breen Malmberg
@change: 2017/07/07 ekkehard - make eligible for macOS High Sierra 10.13
@change: 2017/08/28 Breen Malmberg - Fixing to use new help text methods
@change: 2019/07/18 Brandon R. Gonzales - Make applicable to MacOS 10.13-10.14
'''

from __future__ import absolute_import

import os
import traceback
import re

from ..rule import Rule
from ..CommandHelper import CommandHelper
from ..logdispatcher import LogPriority


class DisableTouchID(Rule):
    '''classdocs'''

    def __init__(self, config, environ, logger, statechglogger):
        '''
        Constructor
        '''
        Rule.__init__(self, config, environ, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 102
        self.rulename = 'DisableTouchID'
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.rootrequired = True
        self.environ = environ
        self.sethelptext()
        self.applicable = {'type': 'white',
                           'os': {'Mac OS X': ['10.12.3', 'r', '10.14.10']}}
        datatype = 'bool'
        key = 'DISABLETOUCHID'
        instructions = "To prevent this rule from running, set the value of DisableTouchID to False."
        default = True
        self.ci = self.initCi(datatype, key, instructions, default)
        self.guidance = ['(None)']

        self.initobjs()

    def initobjs(self):
        '''init objects used by this class
        
        @author: Breen Malmberg


        '''

        self.ch = CommandHelper(self.logger)
        self.fixed = False

    def report(self):
        '''check status of touch id


        :returns: self.compliant

        :rtype: bool
@author: Breen Malmberg

        '''

        self.detailedresults = ""
        self.compliant = True
        checkstrings = {"System Touch ID configuration:": False,
                        "Operation performed successfully": False}
        bioutil = "/usr/bin/bioutil"
        reportcmd = bioutil + " -r -s"
        touchidinstalled = False

        try:

            if not os.path.exists(bioutil):
                self.logger.log(LogPriority.DEBUG, "The required bioutil utility was not found")
                self.compliant = False
                self.formatDetailedResults("report", self.compliant, self.detailedresults)
                self.logger.log(LogPriority.INFO, self.detailedresults)
                return self.compliant

            self.ch.executeCommand(reportcmd)
            outlist = self.ch.getOutput()

            if not outlist:
                self.logger.log(LogPriority.DEBUG, "bioutil command returned no output!")
                self.compliant = False
                self.formatDetailedResults("report", self.compliant, self.detailedresults)
                self.logger.log(LogPriority.INFO, self.detailedresults)
                return self.compliant

            for line in outlist:
                if re.search("Touch ID functionality", line, re.IGNORECASE):
                    touchidinstalled = True

            if touchidinstalled:
                checkstrings = {"System Touch ID configuration:": False,
                                "Touch ID functionality: 0": False,
                                "Touch ID for unlock: 0": False,
                                "Operation performed successfully": False}

            for line in outlist:
                for cs in checkstrings:
                    if re.search(cs, line, re.IGNORECASE):
                        checkstrings[cs] = True

            for cs in checkstrings:
                if not checkstrings[cs]:
                    self.compliant = False
                    self.detailedresults += "\nTouch ID is still enabled."

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.compliant = False
            self.detailedresults = traceback.format_exc()
        self.formatDetailedResults("report", self.compliant, self.detailedresults)
        self.logger.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

    def fix(self):
        '''turn off touch id functionality


        :returns: self.rulesuccess

        :rtype: bool
@author: Breen Malmberg

        '''

        self.detailedresults = ""
        self.rulesuccess = True
        fixcmd1 = "/usr/bin/bioutil -w -s -u 0"
        fixcmd2 = "/usr/bin/bioutil -w -s -f 0"
        checkstring = "Operation performed successfully"

        try:

            if self.ci.getcurrvalue():

                self.ch.executeCommand(fixcmd1)
                outlist = self.ch.getOutput()
    
                if not outlist:
                    self.logger.log(LogPriority.DEBUG, "bioutil command returned no output!")
                    self.detailedresults += "\n"
                    self.rulesuccess = False
                    self.formatDetailedResults("fix", self.compliant, self.detailedresults)
                    self.logger.log(LogPriority.INFO, self.detailedresults)
                    return self.rulesuccess
    
                cmdsuccess = False
                for line in outlist:
                    if re.search(checkstring, line, re.IGNORECASE):
                        cmdsuccess = True
    
                if not cmdsuccess:
                    self.rulesuccess = False
                    self.detailedresults += "\nFailed to turn off Touch ID unlock"
    
                self.ch.executeCommand(fixcmd2)
                outlist = self.ch.getOutput()
    
                if not outlist:
                    self.logger.log(LogPriority.DEBUG, "bioutil command returned no output!")
                    self.rulesuccess = False
                    self.formatDetailedResults("fix", self.compliant, self.detailedresults)
                    self.logger.log(LogPriority.INFO, self.detailedresults)
                    return self.rulesuccess
    
                cmdsuccess = False
                for line in outlist:
                    if re.search(checkstring, line, re.IGNORECASE):
                        cmdsuccess = True
    
                if not cmdsuccess:
                    self.rulesuccess = False
                else:
                    self.fixed = True

            else:
                self.detailedresults += "\nCI was not enabled. Nothing was fixed."
                self.logger.log(LogPriority.DEBUG, "User ran rule without CI enabled. Nothing was fixed.")

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults = traceback.format_exc()
        self.formatDetailedResults("fix", self.compliant, self.detailedresults)
        self.logger.log(LogPriority.INFO, self.detailedresults)
        return self.rulesuccess

    def undo(self):
        '''reverse the fix actions which were applied


        :returns: success

        :rtype: bool
@author: Breen Malmberg

        '''

        self.detailedresults = ""
        success = True
        undocmd1 = "/usr/bin/bioutil -w -s -f 1"
        undocmd2 = "/usr/bin/bioutil -w -s -u 1"

        try:

            if self.fixed:

                self.ch.executeCommand(undocmd1)
                retval = self.ch.getReturnCode()
                if retval != 0:
                    success = False
                    self.detailedresults += "\nEncountered an error while trying to undo the fix actions."
    
                self.ch.executeCommand(undocmd2)
                retval = self.ch.getReturnCode()
                if retval != 0:
                    success = False
                    self.detailedresults += "\nEncountered an error while trying to undo the fix actions."
    
                if success:
                    self.fixed = False

            else:
                self.detailedresults += "\nSystem already in original state. Nothing to undo."

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            success = False
            self.detailedresults = traceback.format_exc()
        self.formatDetailedResults("undo", success, self.detailedresults)
        self.logger.log(LogPriority.INFO, self.detailedresults)
        return success
        
