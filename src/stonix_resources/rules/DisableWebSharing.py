###############################################################################
#                                                                             #
# Copyright 2015-2017.  Los Alamos National Security, LLC. This material was  #
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
'''

from __future__ import absolute_import
import traceback
import os

from ..rule import Rule
from ..ServiceHelper import ServiceHelper
from ..stonixutilityfunctions import iterate
from ..logdispatcher import LogPriority
from ..CommandHelper import CommandHelper


class DisableWebSharing(Rule):
    '''
    Web Sharing uses the Apache 2.2.x web server to turn the Mac into an HTTP/Web
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
                           'os': {'Mac OS X': ['10.11', 'r', '10.13.10']}}
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
        '''
        Report status of web sharing and compliance

        @return: self.compliant
        @rtype: bool
        @author: Breen Malmberg
        '''

        # defaults
        self.detailedresults = ''
        self.compliant = False

        # init servicehelper object
        if not os.path.exists(self.maclongname):
            self.compliant = True
            self.detailedresults += '\norg.apache.httpd.plist does not exist.\nThis is fine'
            self.formatDetailedResults("report", self.compliant,
                                   self.detailedresults)
            self.logdispatch.log(LogPriority.INFO, self.detailedresults)
            return self.compliant

        try:
            self.macServiceTarget = "system/" + self.macshortname 
            if not self.svchelper.auditService(self.maclongname, serviceTarget=self.macshortname):

                if self.cmhelper.executeCommand('defaults read /System/Library/LaunchDaemons/org.apache.httpd Disabled'):
                    output = self.cmhelper.getOutput()
                    if self.checkPlistVal('1', output[0].strip()):
                        self.compliant = True
            else:
                self.detailedresults += '\n' + self.maclongname + ' is still loaded/enabled'

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
        '''
        Perform operations to disable web sharing

        @return: self.rulesuccess
        @rtype: bool
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
                if not self.svchelper.disableservice(self.maclongname, self.macshortname):

                    self.rulesuccess = False

                self.id += 1
                myid = iterate(self.id, self.rulenumber)
                event = {'eventtype': 'commandstring',
                         'command': 'defaults delete /System/Library/LaunchDaemons/org.apache.httpd Disabled'}

                self.statechglogger.recordchgevent(myid, event)

            else:
                self.detailedresults += '\nDisableWebSharing set to False, so nothing was done!'

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
    def checkPlistVal(self, val, output):
        '''
        check a given value, val, against a list of values, output

        @param: string/list val    given value or list of values to check
        @param: list output    given list of values to check against
        @return: retval
        @rtype: bool
        @author: Breen Malmberg
        '''

        retval = True

        try:

            for item in output:
                output = [c.replace(item, item.strip(')')) for c in output]
            for item in output:
                output = [c.replace(item, item.strip('(')) for c in output]
            for item in output:
                output = [c.replace(item, item.strip('\n')) for c in output]
            for item in output:
                output = [c.replace(item, item.strip(',')) for c in output]
            for item in output:
                output = [c.replace(item, item.strip()) for c in output]
            for item in output:
                if item == '':
                    output.remove(item)
            if len(output) > 1:
                for item in output:
                    if item == '1' or item == '0' or item == 1 or item == 0:
                        output.remove(item)

            if isinstance(val, list):
                for item in val:
                    if item not in output:
                        retval = False

            elif isinstance(val, basestring):
                if val not in output:
                    retval = False

        except Exception:
            raise
        return retval

###############################################################################
    def afterfix(self):
        afterfixsuccessful = True
        afterfixsuccessful &= self.sh.auditservice(self.maclongname, self.macshortname)
        return afterfixsuccessful


