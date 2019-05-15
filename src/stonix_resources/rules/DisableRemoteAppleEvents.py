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
Created on Dec 3, 2014

Apple Events is a technology that allows one program to communicate with other
programs. Remote Apple Events allows a program on one computer to communicate
with a program on a different computer. Unless needed, Remote Apple Events
should be turned off. If turned on, add users to the Allow Access for list if
possible.

@author: Breen Malmberg
@change: 2015/04/15 dkennel updated for new isApplicable
@change: 2017/07/07 ekkehard - make eligible for macOS High Sierra 10.13
@change 2017/08/28 Breen Malmberg Fixing to use new help text methods
@change: 2017/10/23 rsn - remove unused service helper
@change: 2017/11/13 ekkehard - make eligible for OS X El Capitan 10.11+
@change: 2018/06/08 ekkehard - make eligible for macOS Mojave 10.14
@change: 2019/03/12 ekkehard - make eligible for macOS Sierra 10.12+
'''

from __future__ import absolute_import

import os
import re
import traceback

from ..rule import Rule
from ..logdispatcher import LogPriority
from ..stonixutilityfunctions import iterate
from ..CommandHelper import CommandHelper


class DisableRemoteAppleEvents(Rule):
    '''classdocs'''

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
        self.rootrequired = True
        self.guidance = ['CIS 1.4.14.10']
        self.applicable = {'type': 'white',
                           'os': {'Mac OS X': ['10.12', 'r', '10.14.10']}}
        self.sethelptext()

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

    def report(self):
        '''return the compliance status of the system with this rule


        :returns: self.compliant

        :rtype: bool

@author: Breen Malmberg

        '''

        self.detailedresults = ""
        self.cmhelper = CommandHelper(self.logger)
        self.compliant = True

        try:

            print "Value of disableremoteevents CI = " + str(self.disableremoteevents.getcurrvalue())

            if self.disableremoteevents.getcurrvalue():
                if not self.reportDisabled():
                    self.compliant = False

            print "Value of secureremoteevents CI = " + str(self.secureremoteevents.getcurrvalue())

            if self.secureremoteevents.getcurrvalue() != []:
                if not self.reportSecured():
                    self.compliant = False

        except Exception:
            self.detailedresults += '\n' + traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)

        return self.compliant

    def reportDisabled(self):
        ''' '''

        self.logger.log(LogPriority.DEBUG, "Checking if remote apple events are disabled...")

        retval = False
        get_remote_ae = "/usr/sbin/systemsetup -getremoteappleevents"
        searchphrase = "Remote Apple Events: Off"

        self.cmhelper.executeCommand(get_remote_ae)
        outputlist = self.cmhelper.getOutput()
        for line in outputlist:
            if re.search(searchphrase, line, re.IGNORECASE):
                retval = True

        if not retval:
            self.detailedresults += "\nRemote Apple Events are On"
        else:
            self.detailedresults += "\nRemote Apple Events are Off"

        return retval

    def reportSecured(self):
        ''' '''

        self.logger.log(LogPriority.DEBUG, "Checking if remote apple events is secured...")

        retval = True
        uuid_list = self.getUUIDs(self.secureremoteevents.getcurrvalue())
        remote_ae_users = self.getRemoteAEUsers()

        difference = list(set(uuid_list) - set(remote_ae_users))
        if difference:
            retval = False
            self.detailedresults += "\nThe current list of allowed remote access users does not match the desired list of remote access users"
            self.detailedresults += "\nDifference: " + " ".join(difference)

        return retval

    def getRemoteAEUsers(self):
        '''return a list of uuid's of current remote ae users
        (mac os x stores the remote ae users as uuid's in a plist)


        '''

        get_remote_ae_users = "/usr/bin/dscl . read /Groups/com.apple.access_remote_ae GroupMembers"
        remote_ae_users = []

        # it is possible that the key "GroupMembers" does not exist
        # this is because when you remove the last remote ae user from the list,
        # mac os x deletes this key from the plist as well..
        self.cmhelper.executeCommand(get_remote_ae_users)
        retcode = self.cmhelper.getReturnCode()
        if retcode == 0:
            remote_ae_users = self.cmhelper.getOutputString().split()
        else:
            errmsg = self.cmhelper.getErrorString()
            self.logger.log(LogPriority.DEBUG, str(errmsg))
        if "GroupMembers:" in remote_ae_users:
            remote_ae_users.remove("GroupMembers:")

        return remote_ae_users

    def fix(self):
        '''run commands needed to bring the system to a compliant state with this
        rule


        :returns: self.rulesuccess

        :rtype: bool

@author: Breen Malmberg

        '''

        self.iditerator = 0
        self.rulesuccess = True
        self.detailedresults = ""

        try:

            if self.disableremoteevents.getcurrvalue():
                if not self.disable_remote_ae():
                    self.rulesuccess = False

            if self.secureremoteevents.getcurrvalue():
                if not self.secure_remote_ae():
                    self.rulesuccess = False

        except Exception:
            self.detailedresults += '\n' + traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)

        return self.rulesuccess

    def disable_remote_ae(self):
        ''' '''

        retval = True

        disable_remote_ae_cmd = "/usr/sbin/systemsetup setremoteappleevents off"
        undocmd = "/usr/sbin/systemsetup setremoteappleevents on"
        self.cmhelper.executeCommand(disable_remote_ae_cmd)
        retcode = self.cmhelper.getReturnCode()
        if retcode != 0:
            retval = False
        else:
            self.iditerator += 1
            myid = iterate(self.iditerator, self.rulenumber)
            event = {"eventtype": "commandstring",
                     "command": undocmd}

            self.statechglogger.recordchgevent(myid, event)

        return retval

    def secure_remote_ae(self):
        ''' '''

        retval = True
        desired_remote_ae_users = self.getUUIDs(self.secureremoteevents.getcurrvalue())
        securecmd = "/usr/bin/dscl . create /Groups/com.apple.access_remote_ae GroupMembers " + " ".join(desired_remote_ae_users)
        original_remote_ae_users = self.getRemoteAEUsers()
        if original_remote_ae_users:
            undocmd = "/usr/bin/dscl . create /Groups/com.apple.access_remote_ae GroupMembers " + " ".join(original_remote_ae_users)
        else:
            undocmd = "/usr/bin/dscl . delete /Groups/com.apple.access_remote_ae GroupMembers"

        self.cmhelper.executeCommand(securecmd)
        retcode = self.cmhelper.getReturnCode()
        if retcode == 0:
            self.iditerator += 1

            myid = iterate(self.iditerator, self.rulenumber)
            event = {"eventtype": "commandstring",
                     "command": undocmd}

            self.statechglogger.recordchgevent(myid, event)
        else:
            retval = False
            self.detailedresults += "\nFailed to properly configure the desired remote apple events users"

        # we assume the user wants to use the service if they configure the user list for it
        # and turn off the disable events CI
        if not self.disableremoteevents.getcurrvalue():
            undo_enable_remote_ae_cmd = "/usr/sbin/systemsetup setremoteappleevents off"
            enable_remote_ae_cmd = "/usr/sbin/systemsetup setremoteappleevents on"
            self.cmhelper.executeCommand(enable_remote_ae_cmd)
            retcode = self.cmhelper.getReturnCode()
            if retcode != 0:
                retval = False
                self.detailedresults += "\nFailed to enable remote apple events service"
            else:
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                event = {"eventtype": "commandstring",
                         "command": undo_enable_remote_ae_cmd}
                self.statechglogger.recordchgevent(myid, event)

        return retval

    def getUUIDs(self, userlist):
        '''convert the desired (user-specified) list of ae user names
        into uuid's; return as list

        :param userlist: 

        '''

        uuidlist = []

        for user in userlist:
            output = ""
            get_uuid = "/usr/bin/dsmemberutil getuuid -U " + user
            self.cmhelper.executeCommand(get_uuid)
            output = self.cmhelper.getOutputString()
            if re.search("no uuid", output, re.IGNORECASE):
                continue
            else:
                if output:
                    uuidlist.append(output.strip())

        return uuidlist
