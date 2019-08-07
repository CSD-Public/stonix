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
Created on Jan 21, 2016

This rule will set the global policy for inactive accounts so that any account,
which goes 35 days beyond the password expiration date without updating its
password, will be disabled.

@author: Breen Malmberg
@change: 2016/09/08 eball Added loop to append EXCLUDEACCOUNTS items
@change: 2017/03/30 dkennel Marked as FISMA high until Apple resolves bugs
@change: 2017/07/07 ekkehard - make eligible for macOS High Sierra 10.13
@change: 2017/08/28 Breen Malmberg Fixing to use new help text methods
@change: 2017/11/13 ekkehard - make eligible for OS X El Capitan 10.11+
@change: 2018/06/08 ekkehard - make eligible for macOS Mojave 10.14
@change: 2019/03/12 ekkehard - make eligible for macOS Sierra 10.12+
@change: 2019/08/07 ekkehard - enable for macOS Catalina 10.15 only
'''



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
    '''This rule will set the global policy for inactive accounts so that any
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
        key = 'DISABLEINACTIVEACCOUNTS'
        instructions = 'To disable this rule, set the value of ' + \
            'DisableInactiveAccounts to False.'
        default = True
        self.ci = self.initCi(datatype, key, instructions, default)

        self.applicable = {'type': 'white',
                           'os': {'Mac OS X': ['10.15', 'r', '10.15.10']},
                           'fisma': 'high'}

        self.initobjs()

    def initobjs(self):
        '''initialize objects for use by this class


        :returns: void
        @author: Breen Malmberg

        '''

        self.cmdhelper = CommandHelper(self.logger)

    def getEnabledAccounts(self):
        '''return a list of all currently enabled accounts


        :returns: enabledaccounts

        :rtype: list
@author: Breen Malmberg

        '''

        allaccounts = []
        enabledaccounts = []
        getallaccounts = "/usr/bin/dscl . -list /Users"
        getenabled = "/usr/bin/pwpolicy -u {username} --get-effective-policy"

        try:

            self.cmdhelper.executeCommand(getallaccounts)
            allaccounts = self.cmdhelper.getOutput()
            if allaccounts:
                for acc in allaccounts:
                    self.cmdhelper.executeCommand(getenabled.replace("{username}", acc))
                    outputstr = self.cmdhelper.getOutputString()
                    if re.search("isDisabled=false", outputstr, re.IGNORECASE):
                        enabledaccounts.append(acc)

        except Exception:
            raise

        return enabledaccounts

    def report(self):
        '''get a list of users
        determine each user's password last set time
        determine if each user is inactive


        :returns: self.compliant

        :rtype: bool
@author: Breen Malmberg

        '''

        # UPDATE THIS SECTION IF YOU CHANGE THE CONSTANTS BEING USED IN THE RULE
        constlist = [EXCLUDEACCOUNTS]
        if not self.checkConsts(constlist):
            self.compliant = False
            self.detailedresults = "\nPlease ensure that the constant: EXCLUDEACCOUNTS, in localize.py, is defined and is not None. This rule will not function without it."
            self.formatDetailedResults("report", self.compliant, self.detailedresults)
            return self.compliant

        self.compliant = True
        self.detailedresults = ''

        # do not check any accounts with these regex terms found in them
        # these are accounts which would not have the passwordlastsettime key
        # in their accountpolicydata, and accounts which we do not want to
        # disable
        accexcludere = ['_', 'nobody', 'daemon', 'root']
        for account in EXCLUDEACCOUNTS:
            accexcludere.append(account)
        self.inactiveaccounts = []

        try:

            userlist = self.getEnabledAccounts()

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
        '''Get and return the number of days a given user account has been
        inactive

        :param user: string the name of the account to check
        @author: Breen Malmberg
        :returns: inactivedays
        :rtype: int

        '''

        inactivedays = 0
        date_format = "%a %b %d %H:%M:%S %Y"

        try:

            if not user:
                self.logger.log(LogPriority.DEBUG, "The given value for " +
                                "parameter user was None, or blank!")
                return inactivedays

            if not isinstance(user, str):
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
        '''check if ci is enabled
        if it is, run fix actions for this rule
        if not, report that it is disabled


        :returns: fixsuccess

        :rtype: bool
@author: Breen Malmberg

        '''

        # UPDATE THIS SECTION IF YOU CHANGE THE CONSTANTS BEING USED IN THE RULE
        constlist = [EXCLUDEACCOUNTS]
        if not self.checkConsts(constlist):
            success = False
            self.formatDetailedResults("fix", success, self.detailedresults)
            return success

        # defaults
        fixsuccess = True
        self.detailedresults = ''
        self.iditerator = 0
        disabledaccounts = []

        try:

            if self.ci.getcurrvalue():

                if self.inactiveaccounts:
                    for user in self.inactiveaccounts:
                        self.cmdhelper.executeCommand('/usr/bin/pwpolicy -disableuser -u ' + user)
                        errout = self.cmdhelper.getErrorString()
                        rc = self.cmdhelper.getReturnCode()
                        if rc != 0:
                            self.detailedresults += '\nThere was an issue trying to disable user account: ' + user
                            self.logger.log(LogPriority.DEBUG, errout)
                            fixsuccess = False
                        else:
                            self.iditerator += 1
                            myid = iterate(self.iditerator, self.rulenumber)
                            event = {'eventtype': 'commandstring',
                                     'command': '/usr/bin/pwpolicy -enableuser -u ' + user}
                            self.statechglogger.recordchgevent(myid, event)
                            disabledaccounts.append(user)
                            self.logger.log(LogPriority.DEBUG, "Disabling user account: " + str(user) + " ...")
                    if disabledaccounts:
                        self.detailedresults += "\nDisabled the following accounts: " + "\n- ".join(disabledaccounts)
                else:
                    self.detailedresults += '\nNo inactive accounts detected. No accounts were disabled.'

            else:
                self.detailedresults += '\nThe CI for this rule was not enabled. Nothing was done.'

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", fixsuccess, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return fixsuccess
