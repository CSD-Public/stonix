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
Created on Dec 3, 2014

Apple Events is a technology that allows one program to communicate with other
programs. Remote Apple Events allows a program on one computer to communicate
with a program on a different computer. Unless needed, Remote Apple Events
should be turned off. If turned on, add users to the Allow Access for list if
possible.

@author: bemalmbe
@change: 2015/04/15 dkennel updated for new isApplicable
@change: 2017/07/07 ekkehard - make eligible for macOS High Sierra 10.13
@change 2017/08/28 Breen Malmberg Fixing to use new help text methods
'''

from __future__ import absolute_import

import os
import traceback

from ..rule import Rule
from ..logdispatcher import LogPriority
from ..stonixutilityfunctions import iterate
from ..CommandHelper import CommandHelper
from ..ServiceHelper import ServiceHelper


class DisableRemoteAppleEvents(Rule):
    '''
    classdocs
    '''

    def __init__(self, config, environ, logger, statechglogger):
        '''
        Constructor
        '''
        Rule.__init__(self, config, environ, logger, statechglogger)
        self.config = config
        self.environ = environ
        self.logger = logger
        self.statechglogger = statechglogger
        self.rulenumber = 213
        self.rulename = 'DisableRemoteAppleEvents'
        self.formatDetailedResults("initialize")
        self.compliant = False
        self.mandatory = True
        self.helptext = 'Apple Events is a technology which allows one ' \
        'program to communicate with other programs. Remote Apple Events ' \
        'allows a program on one computer to communicate with a program on ' \
        'a different computer. Unless needed, Remote Apple Events should be ' \
        'turned off. If turned on, add users to the Allow Access for list ' \
        'if possible.'
        self.rootrequired = True
        self.guidance = ['CIS 1.4.14.10']
        self.applicable = {'type': 'white',
                           'os': {'Mac OS X': ['10.9', 'r', '10.13.10']}}

        # set up CIs
        datatype = 'bool'
        key = 'DISABLEREMOTEAPPLEEVENTS'
        instructions = 'To allow the use of remote apple events on this system, set the value of DisableRemoteAppleEvents to False.'
        default = True
        self.disableremoteevents = self.initCi(datatype, key, instructions, default)

        datatype2 = 'list'
        key2 = 'REMOTEAPPLEEVENTSUSERS'
        instructions2 = 'If you have a business requirement to have remote apple events turned on, enter a list of users who will be allowed access to remote apple events on this system'
        default2 = []
        self.secureremoteevents = self.initCi(datatype2, key2, instructions2, default2)

        # set up class variables
        self.eppcfile = '/System/Library/LaunchDaemons/com.apple.eppc.plist'
        self.eppcfileshort = 'com.apple.eppc'
        self.raefile = '/private/var/db/dslocal/nodes/default/groups/com.apple.access_remote_ae.plist'
        self.raefileshort = 'com.apple.access_remote_ae'

    def report(self):
        '''
        return the compliance status of the system with this rule

        @return: bool
        @author: bemalmbe
        '''

        self.detailedresults = ''
        self.cmhelper = CommandHelper(self.logger)
        self.svchelper = ServiceHelper(self.environ, self.logger)
        self.compliant = False
        secure = True
        disabled = False

        try:

            if self.disableremoteevents.getcurrvalue():
                disabled = self.checkPlistVal('1', self.getCurPlistVal(self.eppcfile, 'Disabled'))

            if self.secureremoteevents.getcurrvalue():
                secure = self.checkPlistVal(self.secureremoteevents.getcurrvalue(), self.getCurPlistVal(self.raefile, 'users'))

            if secure and disabled:
                self.compliant = True
            elif not disabled:
                self.detailedresults += '\ndisable remote apple events is set to True, but remote apple events is currently enabled'
            elif not secure:
                self.detailedresults += '\nthe allowed users acl for remote apple events is configured incorrectly'

        except Exception:
            self.detailedresults += '\n' + traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

###############################################################################
    def fix(self):
        '''
        run commands needed to bring the system to a compliant state with this
        rule

        @return: bool
        @author: bemalmbe
        '''

        self.rulesuccess = False
        self.detailedresults = ''
        self.id = 0

        try:

            if self.secureremoteevents.getcurrvalue():
                users = self.compileUsers(self.secureremoteevents.getcurrvalue())
                if users:
                    origval = self.compileUsers(self.getCurPlistVal(self.raefile, 'users'))
                    self.rulesuccess = self.cmhelper.executeCommand('defaults write ' + self.raefile + ' users ' + users)

                    self.id += 1
                    myid = iterate(self.id, self.rulenumber)
                    event = {'eventtype': 'commandstring',
                             'command': 'defaults write ' + self.raefile + ' users ' + str(origval)}
                    self.statechglogger.recordchgevent(myid, event)

            if self.disableremoteevents.getcurrvalue():
                origval = self.getCurPlistVal(self.eppcfile, 'Disabled')
                self.rulesuccess = self.cmhelper.executeCommand('defaults write ' + self.eppcfile + ' Disabled -bool true')

                self.id += 1
                myid = iterate(self.id, self.rulenumber)
                event = {'eventtype': 'commandstring',
                         'command': 'defaults write ' + self.raefile + ' Disabled ' + str(origval)}
                self.statechglogger.recordchgevent(myid, event)

        except Exception:
            self.detailedresult += '\n' + traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.rulesuccess

###############################################################################
    def compileUsers(self, userlist):
        '''
        compile a given list of users into a string of the format: '(user1, user2, user3...)'

        @param: list userlist    list of users
        @return: string
        @author: bemalmbe
        '''

        returnstring = ''

        try:

            if userlist:
                for user in userlist:
                    userlist = [c.replace(user, user.strip().strip('\n')) for c in userlist]
                returnstring = '('
                for user in userlist:
                    returnstring += user + ','
                returnstring = returnstring[:-1]
                returnstring += ')'
                returnstring = "'" + returnstring + "'"

        except Exception:
            raise
        return returnstring

###############################################################################
    def getCurPlistVal(self, plist, key):
        '''
        get the value of the given plist key

        @param: string plist    name of plist file to query
        @param: string key    name of key to query
        @return: list
        @author: bemalmbe
        '''

        try:

            if not os.path.exists(plist):
                self.detailedresults += '\ngetCurPlistVal(): could not find specified plist file: ' + str(plist)

            self.cmhelper.executeCommand('defaults read ' + plist + ' ' + key)
            output = self.cmhelper.getOutput()

        except Exception:
            raise
        return output

###############################################################################
    def checkPlistVal(self, val, output):
        '''
        check a given value, val, against a list of values, output

        @param: string/list val    given value or list of values to check
        @param: list output    given list of values to check against
        @return: bool
        @author: bemalmbe
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
