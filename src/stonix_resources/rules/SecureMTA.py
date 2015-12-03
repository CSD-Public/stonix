'''
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
Created on Aug 8, 2013

Mail servers are used to send and receive mail over a network on behalf of site
users. Mail is a very common service, and MTAs are frequent targets of network
attack. Ensure that machines are not running MTAs unnecessarily, and configure
needed MTAs as defensively as possible.

@author: Breen Malmberg
@change: 02/03/2014 dwalker revised
@change: 02/16/2014 ekkehard Implemented self.detailedresults flow
@change: 02/16/2014 ekkehard Implemented isapplicable
@change: 04/21/2014 dkennel Updated CI invocation
@change: 2014/07/29 dkennel Fixed multiple calls to setPerms where 6 args were
given instead of the required five.
@change: 2014/08/11 ekkehard fixed isApplicable
@change: 03/4/2015 dwalker added new directive to dictionary
@change: 2015/04/17 dkennel updated for new isApplicable
@change: 2015/04/28 dkennel changed data dictionary in reportpostfix to
reference localize.py MAILRELAYSERVER instead of static local value.
@change: 2015/07/30 eball Changed where setPerms occurs in fix
@change: 2015/10/08 eball Help text cleanup
@change: 2015/11/09 ekkehard - make eligible of OS X El Capitan
'''

from __future__ import absolute_import
from ..rule import Rule
from ..stonixutilityfunctions import resetsecon, readFile, iterate, setPerms
from ..stonixutilityfunctions import checkPerms, writeFile
from ..logdispatcher import LogPriority
from ..pkghelper import Pkghelper
from ..KVEditorStonix import KVEditorStonix
from ..localize import MAILRELAYSERVER
import os
import traceback
import re


class SecureMTA(Rule):
    '''
    Mail servers are used to send and receive mail over a network on behalf of
site users. Mail is a very common service, and MTAs are frequent targets of
network attack. Ensure that machines are not running MTAs unnecessarily, and
configure needed MTAs as defensively as possible.
    '''

    def __init__(self, config, environ, logger, statechglogger):
        Rule.__init__(self, config, environ, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 53
        self.rulename = 'SecureMTA'
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.helptext = '''Mail servers are used to send and receive mail \
over a network on behalf of site users. Mail is a very common service, and \
MTAs are frequent targets of network attack. Ensure that machines are not \
running MTAs unnecessarily, and configure needed MTAs as defensively as \
possible.
Please be advised, in one section of this rule, the \
/etc/mail/sendmail.cf is modified two different times.  Because of this, the \
undo event that handles this file if a change is made will only revert one \
change, the change that is not reverted is the insertion or modification of \
the line that begins with DS.  If you can't remember the original format of \
that line, take a look in the /usr/share/stonix folder for the original file \
before clicking undo.'''
        self.guidance = ['CCE 4416-4', 'CCE 4663-1', 'CCE 14495-6',
                         'CCE 14068-1', 'CCE 15018-5', 'CCE 4293-7']
        self.applicable = {'type': 'white',
                           'family': ['linux', 'solaris', 'freebsd'],
                           'os': {'Mac OS X': ['10.9', 'r', '10.11.10']}}

        self.postfixfoundlist = []
        self.sendmailfoundlist = []

        datatype = 'bool'
        key = 'SECUREMTA'
        instructions = '''To prevent the configuration of the mail transfer
agent, set the value of SECUREMTA to False.'''
        default = True
        self.mta = self.initCi(datatype, key, instructions, default)
        self.mta.setsimple(True)

        self.iditerator = 0
        self.ds = True
        self.sndmailed = ""
        self.postfixpathlist = ['/etc/postfix/main.cf',
                                '/private/etc/postfix/main.cf']
        self.postfixpath = ''
        for path in self.postfixpathlist:
            if os.path.exists(path):
                self.postfixpath = path

    def report(self):
        '''
        The report method examines the current configuration and determines
        whether or not it is correct. If the config is correct then the
        self.compliant, self.detailed results and self.currstate properties are
        updated to reflect the system status. self.rulesuccess will be updated
        if the rule does not succeed.

        @return bool
        @author Breen Malmberg
        '''

        try:
            self.detailedresults = ""
            if not self.environ.operatingsystem == "Mac OS X":
                self.helper = Pkghelper(self.logger, self.environ)
            compliant = True
            sndpath = "/etc/mail/sendmail.cf"
            postfixlist = ['postfix', 'squeeze', 'squeeze-backports',
                           'wheezy', 'jessie', 'sid', 'CNDpostfix', 'lucid',
                           'lucid-updates', 'lucid-backports', 'precise',
                           'precise-updates', 'quantal', 'quantal-updates',
                           'raring', 'saucy']

            # check for installed versions of postfix on this system
            if not self.environ.operatingsystem == "Mac OS X":
                for item in postfixlist:
                    if self.helper.check(item):
                        self.postfixfoundlist.append(item)

            # check for installed versions of sendmail on this system
            # freebsd can have sendmail installed and not show as installed
            # macosx doesn't have a package manager
            if not self.environ.getostype() == "Mac OS X":
                if not self.helper.manager == "freebsd":
                    if self.helper.check("sendmail"):
                        self.sendmailfoundlist.append(item)
            # if sendmail installed, run check on sendmail
            if os.path.exists(sndpath):
                if not checkPerms(sndpath, [0, 0, 420], self.logger):
                    compliant = False
                if not self.reportsendmail():
                    compliant = False
            elif len(self.sendmailfoundlist) > 0:
                compliant = False
                self.sndmailed = False
                self.detailedresults += "sendmail is installed but \
/etc/mail/sendmail.cf is missing"
                self.logger.log(LogPriority.DEBUG, self.detailedresults)

            if os.path.exists(self.postfixpath):
                if not checkPerms(self.postfixpath, [0, 0, 420], self.logger):
                    compliant = False
                if not self.reportpostfix():
                    compliant = False

            # if postfix installed, run check on postfix
            elif len(self.postfixfoundlist) > 0:
                compliant = False
                self.postfixed = False
                self.detailedresults += "You have postfix installed but your \
/etc/postfix/main.cf is missing"
                self.logger.log(LogPriority.DEBUG, self.detailedresults)
            elif not os.path.exists(self.postfixpath):
                self.postfixed = False
            self.compliant = compliant
        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

###############################################################################
    def reportsendmail(self):
        '''
        Check config of sendmail

        @return bool
        @author Breen Malmberg
        '''
        secure = True
        path = '/etc/mail/sendmail.cf'
        tpath = '/etc/mail/sendmail.cf.tmp'
        kvtype = 'conf'
        conftype = 'closedeq'
        intent = 'present'
        data = {"O SmtpGreetingMessage": "", "O PrivacyOptions": "goaway"}
        # create the kveditor object
        self.sndmailed = KVEditorStonix(self.statechglogger, self.logger,
                                        kvtype, path, tpath, data, intent,
                                        conftype)

        # use kveditor to search the conf file for all the options in
        # postfixdata
        if not self.sndmailed.report():
            secure = False
        # check runtogether keyvalues; may replace with kveditor later if
        # kveditor gets updated to handle runtogether keyvalues
        if os.path.exists(path):
            contents = readFile(path, self.logger)
            found = False
            for line in contents:
                if re.search('^DS', line):
                    found = True
                    if not re.search('^DS' + MAILRELAYSERVER, line):
                        self.ds = True
                        secure = False
            if not found:
                self.ds = True
                secure = False
        return secure

###############################################################################
    def reportpostfix(self):
        '''
        Check config of postfix

        @return bool
        @author Breen Malmberg
        '''
        data = {'inet_interfaces': 'localhost',
                'default_process_limit': '100',
                'smtpd_client_connection_count_limit': '10',
                'smtpd_client_connection_rate_limit': '30',
                'queue_minfree': '20971520',
                'header_size_limit': '51200',
                'message_size_limit': '10485760',
                'smtpd_recipient_limit': '100',
                'smtpd_banner': '$myhostname ESMTP',
                'mynetworks_style': 'host',
                'smtpd_recipient_restrictions':
                'permit_mynetworks, reject_unauth_destination',
                'relayhost': MAILRELAYSERVER}
        tpath = self.postfixpath + '.tmp'
        kvtype = 'conf'
        conftype = 'openeq'
        intent = 'present'
        # create the kveditor object
        self.postfixed = KVEditorStonix(self.statechglogger, self.logger,
                                        kvtype, self.postfixpath, tpath, data,
                                        intent, conftype)

        # use kveditor to search the conf file for all the options in
        # postfixdata
        if not self.postfixed.report():
            return False
        else:
            return True

###############################################################################
    def fix(self):
        '''
        Call either fixpostfix() or fixsendmail() depending on which one is
        installed.

        @author Breen Malmberg
        '''
        try:
            self.detailedresults = ""
            if not self.mta.getcurrvalue():
                return

            # clear out event history so only the latest fix is recorded
            self.iditerator = 0
            success = True
            eventlist = self.statechglogger.findrulechanges(self.rulenumber)
            for event in eventlist:
                self.statechglogger.deleteentry(event)

            if self.postfixed:
                if not self.fixpostfix():
                    success = False
                if not checkPerms(self.postfixpath, [0, 0, 420],
                                  self.logger):
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    if not setPerms(self.postfixpath, [0, 0, 420],
                                    self.logger, self.statechglogger, myid):
                        success = False
            if self.sndmailed:
                if self.sndmailed.fixables or self.ds:
                    if not checkPerms("/etc/mail/sendmail.cf", [0, 0, 420],
                                      self.logger):
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        if not setPerms("/etc/mail/sendmail.cf", [0, 0, 420],
                                        self.logger, self.statechglogger, myid):
                            success = False
                    if not self.fixsendmail():
                        success = False
            elif self.ds:
                if not checkPerms("/etc/mail/sendmail.cf", [0, 0, 420],
                                  self.logger):
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    if not setPerms("/etc/mail/sendmail.cf", [0, 0, 420],
                                    self.logger, self.statechglogger, myid):
                        success = False
                if not self.fixsendmail():
                    success = False
            self.rulesuccess = success
        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception:
            success = False
            self.rulesuccess = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", success,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.rulesuccess

###############################################################################
    def fixpostfix(self):
        '''
        Configure the postfix client securely if installed.

        @author Breen Malmberg
        '''

        if not self.postfixed:
            debug = "not able to performfixpostfix because postfix is \
installed but the config file is not present.  Stonix will not attempt to \
create this file"
            self.logger.log(LogPriority.DEBUG, self.detailedresults)
            return False

        self.iditerator += 1
        myid = iterate(self.iditerator, self.rulenumber)

        self.postfixed.setEventID(myid)

        if not self.postfixed.fix():
            debug = "kveditor fix did not run successfully, returning"
            self.logger.log(LogPriority.DEBUG, debug)
            return False
        elif not self.postfixed.commit():
            debug = "kveditor commit did not run successfully, returning"
            self.logger.log(LogPriority.DEBUG, debug)
            return False

        return True

###############################################################################
    def fixsendmail(self):
        '''
        Configure the sendmail client securely if installed.

        @author Breen Malmberg
        '''
        path = "/etc/mail/sendmail.cf"
        if not self.sndmailed:
            debug = "not able to perform fixsendmail because sendmail is \
installed but the config file is not present.  Stonix will not attempt to \
create this file"
            self.logger.log(LogPriority.DEBUG, debug)
            return False
        success = True
        if self.sndmailed.fixables:
            if self.ds:
                tpath = path + ".tmp"
                contents = readFile(path, self.logger)
                tempstring = ""
                for line in contents:
                    if re.search("^DS(.)*", line):
                        continue
                    else:
                        tempstring += line
                tempstring += "DS" + MAILRELAYSERVER + "\n"
                if writeFile(tpath, tempstring, self.logger):
                    os.rename(tpath, path)
                    os.chown(path, 0, 0)
                    os.chmod(path, 420)
                    resetsecon(path)
                else:
                    self.rulesuccess = False
                    return False
            self.iditerator += 1
            myid = iterate(self.iditerator, self.rulenumber)
            self.sndmailed.setEventID(myid)
            self.sndmailed.setPath(path)
            if not self.sndmailed.fix():
                debug = "kveditor fix did not run successfully, returning"
                self.logger.log(LogPriority.DEBUG, debug)
                return False
            if not self.sndmailed.commit():
                debug = "kveditor fix did not run successfully, returning"
                self.logger.log(LogPriority.DEBUG, debug)
                return False
            os.chown(path, 0, 0)
            os.chmod(path, 420)
            resetsecon(path)
            success = True
        elif self.ds:
            tpath = path + ".tmp"
            contents = readFile(path, self.logger)
            tempstring = ""
            for line in contents:
                if re.search("^DS(.)*", line):
                    continue
                else:
                    tempstring += line
            tempstring += "DS" + MAILRELAYSERVER
            self.iditerator += 1
            myid = iterate(self.iditerator, self.rulenumber)
            if writeFile(tpath, tempstring, self.logger):
                event = {"eventtype": "conf",
                         "filepath": path,
                         "id": myid}
                self.statechglogger.recordchgevent(myid, event)
                self.statechglogger.recordfilechange(path, tpath, myid)
                os.rename(tpath, path)
                os.chown(path, 0, 0)
                os.chmod(path, 420)
                resetsecon(path)
            else:
                success = False
        return success
