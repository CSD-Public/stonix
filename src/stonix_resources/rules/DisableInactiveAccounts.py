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
Created on Jan 21, 2016

This rule will set the global policy for inactive accounts so that any account,
which goes 35 days beyond the password expiration date without updating its
password, will be disabled.

@author: Breen Malmberg
@change: 2016/09/08 eball Added loop to append EXCLUDEACCOUNTS items
@change: 2017/03/30 dkennel Marked as FISMA high until Apple resolves bugs
@change: 2017/07/07 ekkehard - make eligible for macOS High Sierra 10.13
@change 2017/08/28 Breen Malmberg Fixing to use new help text methods
'''

from __future__ import absolute_import

import re
import traceback
import time

from ..localize import EXCLUDEACCOUNTS
from datetime import datetime
from decimal import Decimal
from ..rule import Rule
from ..stonixutilityfunctions import iterate
from ..logdispatcher import LogPriority
from ..CommandHelper import CommandHelper


class DisableInactiveAccounts(Rule):
    '''
    This rule will set the global policy for inactive accounts so that any
    account not accessed/used within 35 days will be automatically disabled.
    '''

    def __init__(self, config, environ, logger, statechglogger):
        '''
        Constructor
        '''
        Rule.__init__(self, config, environ, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 4
        self.rulename = 'DisableInactiveAccounts'
        self.compliant = True
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.rootrequired = True
        self.sethelptext()
        self.guidance = ['CNSSI 1253', 'DISA STIG']

        datatype = 'bool'
        key = 'DisableInactiveAccounts'
        instructions = 'To disable this rule, set the value of ' + \
            'DisableInactiveAccounts to False.'
        default = True
        self.ci = self.initCi(datatype, key, instructions, default)

        self.applicable = {'type': 'white',
                           'os': {'Mac OS X': ['10.9', 'r', '10.13.10']},
                           'fisma': 'high'}
        self.initobjs()

    def initobjs(self):
        '''
        initialize objects for use by this class

        @return: void
        @author: Breen Malmberg
        '''

        self.cmdhelper = CommandHelper(self.logger)

    def report(self):
        '''
        get a list of users
        determine each user's password last set time
        determine if each user is inactive

        @return: self.compliant
        @rtype: bool
        @author: Breen Malmberg
        '''

        # defaults
        self.compliant = True
        self.detailedresults = ''
        getuserscmd = '/usr/bin/dscl . -ls /Users'
        # do not check any accounts with these regex terms found in them
        # these are accounts which would not have the passwordlastsettime key
        # in their accountpolicydata, and accounts which we do not want to
        # disable
        accexcludere = ['_', 'nobody', 'daemon', 'root']
        for account in EXCLUDEACCOUNTS:
            accexcludere.append(account)
        self.inactiveaccounts = []

        try:

            self.cmdhelper.executeCommand(getuserscmd)
            userlist = self.cmdhelper.getOutput()

            if self.cmdhelper.getReturnCode() != 0:
                self.rulesuccess = False
                self.compliant = False
                self.detailedresults += '\nThere was a problem retrieving ' + \
                    'the list of users on this system.'

            userlistnew = []
            for user in userlist:
                removeuser = False
                for element in accexcludere:
                    if re.search(element, user):
                        removeuser = True
                if not removeuser:
                    userlistnew.append(user)

            for user in userlistnew:
                inactivedays = self.getinactivedays(user.strip())
                if int(inactivedays) > 35:
                    self.compliant = False
                    self.detailedresults += '\nThe user account "' + \
                        user.strip() + \
                        '" has been inactive for more than 35 days.'
                    self.inactiveaccounts.append(user.strip())
                elif int(inactivedays) > 0 and int(inactivedays) <= 35:
                    daysleft = 35 - int(inactivedays)
                    self.detailedresults += '\nThe user account "' + \
                        user.strip() + '" has been inactive for ' + \
                        str(inactivedays) + ' days. You have ' + \
                        str(daysleft) + \
                        ' days left before this account will be disabled.'
                    self.logger.log(LogPriority.DEBUG,
                                    '\nThe user account "' + user.strip() +
                                    '" has been inactive for ' +
                                    str(inactivedays) + ' days. You have ' +
                                    str(daysleft) + ' days left before this ' +
                                    'account will be disabled.')
                else:
                    self.detailedresults += '\nThe user account "' + \
                        user.strip() + '" is not inactive. No problems.'

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

    def getinactivedays(self, user):
        '''
        Get and return the number of days a given user account has been
        inactive

        @return: inactivedays
        @rtype: int
        @param user: string the name of the account to check
        @author: Breen Malmberg
        '''

        inactivedays = 0
        date_format = "%a %b %d %H:%M:%S %Y"

        try:

            if not user:
                self.logger.log(LogPriority.DEBUG, "The given value for " +
                                "parameter user was None, or blank!")
                return inactivedays

            if not isinstance(user, basestring):
                self.logger.log(LogPriority.DEBUG,
                                "The given value for parameter user was not " +
                                "of the correct type (int)!")
                return inactivedays

            self.cmdhelper.executeCommand('/usr/bin/dscl . readpl /Users/' +
                                          user + ' accountPolicyData ' +
                                          'passwordLastSetTime')
            epochchangetimestr = self.cmdhelper.getOutputString()
            retcode = self.cmdhelper.getReturnCode()
            outstr = self.cmdhelper.getOutputString()
            if retcode != 0:
                if retcode == 181: # this is the mac os x error code when a plist path does not exist
                    if re.search("No such plist path: passwordLastSetTime", outstr, re.IGNORECASE):
                        self.detailedresults += "The local account: " + str(user) + " has never had a password set for it! We will now disable this local account on this machine."
                        self.logger.log(LogPriority.DEBUG, "The local user account: " + str(user) + " had no password for it. STONIX will disable it now.")
                        inactivedays = 9999 # this will ensure it gets added to the list of accounts to disable
                    return inactivedays
                else:
                    self.detailedresults += '\nThere was an issue reading ' + \
                        user + '\'s accountPolicyData passwordLastSetTime'
                    self.compliant = False
                    return inactivedays

            epochchangetimelist = epochchangetimestr.split(':')
            epochchangetimestropr = epochchangetimelist[1].strip()
            epochchangetime = Decimal(epochchangetimestropr)
            pwchangedate = time.ctime(epochchangetime)
            a = datetime.strptime(pwchangedate, date_format)
            now = time.ctime()
            b = datetime.strptime(now, date_format)
            diff = b - a
            if int(diff.days) > 180:
                inactivedays = int(diff.days) - 180

        except Exception:
            raise
        return inactivedays

    def fix(self):
        '''
        check if ci is enabled
        if it is, run fix actions for this rule
        if not, report that it is disabled

        @return: fixsuccess
        @rtype: bool
        @author: Breen Malmberg
        '''

        # defaults
        fixsuccess = True
        self.detailedresults = ''
        self.iditerator = 0

        try:

            if self.ci.getcurrvalue():

                if self.inactiveaccounts:
                    for user in self.inactiveaccounts:
                        self.cmdhelper.executeCommand('/usr/bin/pwpolicy ' +
                                                      '-disableuser -u ' + user)
                        errout = self.cmdhelper.getErrorString()
                        rc = self.cmdhelper.getReturnCode()
                        if rc != 0:
                            self.detailedresults += '\nThere was an issue ' + \
                                'trying to disable user account: ' + user
                            self.logger.log(LogPriority.DEBUG, errout)
                            fixsuccess = False
                        else:
                            self.iditerator += 1
                            myid = iterate(self.iditerator, self.rulenumber)
                            event = {'eventtype': 'commandstring',
                                     'command': '/usr/bin/pwpolicy -enableuser -u '
                                                + user}
                            self.statechglogger.recordchgevent(myid, event)

                else:
                    self.detailedresults += '\nNo inactive accounts ' + \
                        'detected. Nothing to do.'

            else:
                self.detailedresults += '\nThe CI for this rule was not ' + \
                    'enabled. Nothing was done.'

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", fixsuccess, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return fixsuccess
