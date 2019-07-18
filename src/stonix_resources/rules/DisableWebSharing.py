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
Created on Oct 6, 2014

Web Sharing uses the Apache 2.2.x web server to turn the Mac into an HTTP/Web
server. As with file sharing, web sharing is best left off and a dedicated,
well-managed web server is recommended.

@author: Breen Malmberg
@change: 2014/10/17 ekkehard OS X Yosemite 10.10 Update
@change: 2015/04/15 dkennel updated for new isApplicable
@change: 2017/07/07 ekkehard - make eligible for macOS High Sierra 10.13
@change: 2017/08/28 Breen Malmberg Fixing to use new help text methods
@change: 2017/10/23 rsn - Changing for new service helper interface
@change: 2017/11/13 ekkehard - make eligible for OS X El Capitan 10.11+
@change: 2018/02/16 bgonz12 - Fix function call to disableService
@change: 2018/06/08 ekkehard - make eligible for macOS Mojave 10.14
@change: 2019/03/12 ekkehard - make eligible for macOS Sierra 10.12+
'''



import traceback
import os
import re

from ..rule import Rule
from ..ServiceHelper import ServiceHelper
from ..stonixutilityfunctions import iterate
from ..logdispatcher import LogPriority
from ..CommandHelper import CommandHelper


class DisableWebSharing(Rule):
    '''Web Sharing uses the Apache 2.2.x web server to turn the Mac into an HTTP/Web
    server. As with file sharing, web sharing is best left off and a dedicated,
    well-managed web server is recommended.


    '''

    def __init__(self, config, environ, logger, statechglogger):
        '''
        Constructor
        '''
        Rule.__init__(self, config, environ, logger, statechglogger)
        self.rulenumber = 208
        self.rulename = 'DisableWebSharing'
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.compliant = False
        self.rootrequired = True
        self.guidance = ['CIS 1.4.14.6']
        self.applicable = {'type': 'white',
                           'os': {'Mac OS X': ['10.12', 'r', '10.14.10']}}
        self.logger = logger
        # set up CIs
        datatype = 'bool'
        key = 'DISABLEWEBSHARING'
        instructions = 'To prevent web sharing from being disabled, set the value of DisableWebSharing to False.'
        default = True
        self.disableWebSharing = self.initCi(datatype, key, instructions, default)

        # set up class var's
        self.maclongname = '/System/Library/LaunchDaemons/org.apache.httpd.plist'
        self.macshortname = 'org.apache.httpd'
        self.svchelper = ServiceHelper(self.environ, self.logger)
        self.cmhelper = CommandHelper(self.logger)
        self.sethelptext()

    def report(self):
        '''Report status of web sharing and compliance


        :returns: self.compliant

        :rtype: bool
@author: Breen Malmberg

        '''

        # defaults
        self.detailedresults = ''
        self.compliant = False

        # init servicehelper object
        if not os.path.exists(self.maclongname):
            self.compliant = True
            self.detailedresults += '\norg.apache.httpd.plist does not exist. Nothing to configure'
            self.formatDetailedResults("report", self.compliant, self.detailedresults)
            self.logdispatch.log(LogPriority.INFO, self.detailedresults)
            return self.compliant

        try:

            self.logger.log(LogPriority.DEBUG, "starting audit service for service: " + str(self.maclongname))
            if not self.svchelper.auditService(self.maclongname, serviceTarget=self.macshortname):
                self.logger.log(LogPriority.DEBUG, str(self.maclongname) + " is not running/loaded")

                self.logger.log(LogPriority.DEBUG, "Checking if " + str(self.maclongname) + " is disabled in the plist")
                self.cmhelper.executeCommand('defaults read /System/Library/LaunchDaemons/org.apache.httpd Disabled')
                retcode = self.cmhelper.getReturnCode()
                if retcode != 0:
                    errout = self.cmhelper.getErrorString()
                    self.logger.log(LogPriority.DEBUG, errout)
                else:
                    output = self.cmhelper.getOutputString()
                    if re.search('1', output):
                        self.logger.log(LogPriority.DEBUG, str(self.maclongname) + " is disabled in the plist")
                        self.compliant = True
                    else:
                        self.logger.log(LogPriority.DEBUG, str(self.maclongname) + " is NOT disabled in the plist")
            else:
                self.detailedresults += '\n' + str(self.maclongname) + ' is still loaded/enabled'

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as err:
            self.detailedresults += "\n" + str(err) + \
            " - " + str(traceback.format_exc())
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

###############################################################################
    def fix(self):
        '''Perform operations to disable web sharing


        :returns: self.rulesuccess

        :rtype: bool
@author: Breen Malmberg

        '''

        # defaults
        self.detailedresults = ''
        self.rulesuccess = True
        self.id = 0

        try:

            if self.disableWebSharing.getcurrvalue():

                #if not self.cmhelper.executeCommand('defaults write /System/Library/LaunchDaemons/org.apache.httpd Disabled -bool true'):
                #    self.rulesuccess = False
                if not self.svchelper.disableService(self.maclongname, servicename=self.macshortname):
                    self.rulesuccess = False
                    self.logger.log(LogPriority.DEBUG, "Failed to disable service: " + str(self.maclongname))
                else:
                    self.id += 1
                    myid = iterate(self.id, self.rulenumber)
                    event = {'eventtype': 'commandstring',
                             'command': 'defaults delete /System/Library/LaunchDaemons/org.apache.httpd Disabled'}
    
                    self.statechglogger.recordchgevent(myid, event)

            else:
                self.detailedresults += '\nRule was not enabled, so nothing was done.'

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as err:
            self.rulesuccess = False
            self.detailedresults += "\n" + \
            str(err) + " - " + str(traceback.format_exc())
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.rulesuccess

###############################################################################
    def afterfix(self):
        afterfixsuccessful = True
        afterfixsuccessful &= self.svchelper.auditService(self.maclongname)
        return afterfixsuccessful


