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
Created on Apr 25, 2013

The AT and CRON job schedulers are used to schedule jobs for running at a later
date/time. These daemons should be configured defensively. The SecureATCRON
class restricts permissions on the files and directories associated with these
daemons to authorized users only and enables and configures logging for
these daemons.

@author: Breen Malmberg
@change: dkennel 04/21/2014 Updated CI invocation, fixed CI instruction text,
fixed bug where CI was not referenced before performing Fix() actions.
@change: 2015/04/17 dkennel updated for new isApplicable
@change: 2015/10/08 eball Help text cleanup
@change: 2015/10/27 eball Added feedback to report()
@change: 2016/08/09 Breen Malmberg Added os x implementation; refactored large
parts of the code as well
@change: 2016/08/30 eball Refactored fixLinux() method, PEP8 cleanup
@change: 2017/07/17 ekkehard - make eligible for macOS High Sierra 10.13
@change: 2017/10/23 rsn - removed unused service helper
'''

from __future__ import absolute_import
import os
import re
import traceback
import stat

from ..rule import Rule
from ..logdispatcher import LogPriority
from ..CommandHelper import CommandHelper
from ..stonixutilityfunctions import iterate, setPerms, resetsecon
from pwd import getpwuid
from grp import getgrgid


class SecureATCRON(Rule):
    '''
    This class restricts permissions on files and directories associated with
    AT and CRON to authorized users only and enables and configures logging for
    these daemons.
    '''

    def __init__(self, config, environ, logger, statechglogger):
        '''
        Constructor
        '''

        Rule.__init__(self, config, environ, logger, statechglogger)
        self.environ = environ
        self.statechglogger = statechglogger
        self.logger = logger
        self.rulenumber = 33
        self.rulename = 'SecureATCRON'
        self.mandatory = True
        self.sethelptext()
        self.rootrequired = True
        self.formatDetailedResults("initialize")
        self.compliant = False
        self.guidance = ['CIS', 'NSA(3.4)', 'CCE-4644-1', 'CCE-4543-5',
                         'CCE-4437-0', 'CCE-4693-8', 'CCE-4710-0',
                         'CCE-4230-9', 'CCE-4445-3']
        self.applicable = {'type': 'white',
                           'family': ['linux', 'solaris', 'freebsd'],
                           'os': {'Mac OS X': ['10.9', 'r', '10.13.10']}}

        # init CIs
        datatype = 'bool'
        key = 'SECUREATCRON'
        instructions = '''To prevent the restriction of access to the AT and \
CRON utilities, set the value of SECUREATCRON to False.'''
        default = True
        self.SecureATCRON = self.initCi(datatype, key, instructions, default)

        self.initobjs()
        self.localize()

    def localize(self):
        '''
        set class vars appropriate to whichever platform is currently running

        @return: void
        @author: Breen Malmberg
        '''

        atallowdirs = ['/etc/at.allow', '/var/at/at.allow']
        atdenydirs = ['/etc/at.deny', '/var/at/at.deny']
        cronallowdirs = ['/etc/cron.allow', '/usr/lib/cron/cron.allow']
        crontabdirs = ['/etc/crontab']
        cronspooldirs = ['/var/spool/cron']
        anacrondirs = ['/etc/anacrontab']
        rootaccs = {'darwin': 'root',  # mac has used 'admin' in the past
                    'linux': 'root',
                    'solaris': 'root',
                    'freebsd': 'root'}
        cronlogs = ['/var/cron/log', '/var/log/cron.log', '/var/log/cron']
        crondailydirs = ['/etc/cron.daily']
        cronhourlydirs = ['/etc/cron.hourly']
        cronweeklydirs = ['/etc/cron.weekly']
        cronmonthlydirs = ['/etc/cron.monthly']
        cronconfdirs = ['/etc/default/cron']
        crondenydirs = ['/etc/cron.deny']
        cronddirs = ['/etc/cron.d/']
        chowndirs = ['/usr/bin/chown', '/usr/sbin/chown', '/bin/chown']

        self.atallow = '/etc/at.allow'
        self.atdeny = '/etc/at.deny'
        self.rootacc = 'root'
        self.macgroups = ['admin', 'wheel']
        self.cronlog = '/var/log/cron'
        self.cronallow = '/etc/cron.allow'
        self.crontab = '/etc/crontab'
        self.anacrontab = '/etc/anacrontab'
        self.spoolcron = '/var/spool/cron'
        self.cronhourly = '/etc/cron.hourly'
        self.crondaily = '/etc/cron.daily'
        self.cronweekly = '/etc/cron.weekly'
        self.cronmonthly = '/etc/cron.monthly'
        self.cronconf = '/etc/default/cron'
        self.crondeny = '/etc/cron.deny'
        self.chown = '/usr/sbin/chown'
        self.cronddir = '/etc/cron.d/'

        for loc in cronddirs:
            if os.path.exists(loc):
                self.cronddir = loc

        for loc in crondenydirs:
            if os.path.exists(loc):
                self.crondeny = loc

        for loc in cronconfdirs:
            if os.path.exists(loc):
                self.cronconf = loc

        for loc in atallowdirs:
            if os.path.exists(loc):
                self.atallow = loc

        for loc in atdenydirs:
            if os.path.exists(loc):
                self.atdeny = loc

        osfamily = self.environ.getosfamily()
        self.rootacc = rootaccs[osfamily]

        for loc in cronlogs:
            if os.path.exists(loc):
                self.cronlog = loc

        for loc in cronallowdirs:
            if os.path.exists(loc):
                self.cronallow = loc

        for loc in crontabdirs:
            if os.path.exists(loc):
                self.crontab = loc

        for loc in cronspooldirs:
            if os.path.exists(loc):
                self.spoolcron = loc

        for loc in anacrondirs:
            if os.path.exists(loc):
                self.anacrontab = loc

        for loc in cronhourlydirs:
            if os.path.exists(loc):
                self.cronhourly = loc

        for loc in crondailydirs:
            if os.path.exists(loc):
                self.crondaily = loc

        for loc in cronweeklydirs:
            if os.path.exists(loc):
                self.cronweekly = loc

        for loc in cronmonthlydirs:
            if os.path.exists(loc):
                self.cronmonthly = loc

        for loc in chowndirs:
            if os.path.exists(loc):
                self.chown = loc

        self.verifyVars()

        # we need a separate dict for report and fix
        # because for report we need the string representation
        # of the number and for fix we need to use the int
        # and when you try to type-cast these numbers,
        # python does not preserve data integrity
        # (the numbers change wildly)
        self.reportcronchmodfiledict = {self.crontab: '0644',
                                        self.anacrontab: '0600',
                                        self.spoolcron: '0700',
                                        self.cronlog: '0644',
                                        self.cronallow: '0400',
                                        self.atallow: '0400'}
        self.fixcronchmodfiledict = {self.crontab: 0644,
                                     self.anacrontab: 0600,
                                     self.spoolcron: 0700,
                                     self.cronlog: 0644,
                                     self.cronallow: 0400,
                                     self.atallow: 0400}
        self.cronchownfilelist = [self.cronhourly, self.crondaily,
                                  self.cronweekly, self.cronmonthly,
                                  self.cronddir, self.crontab,
                                  self.anacrontab, self.cronlog,
                                  self.cronallow, self.atallow]

    def verifyVars(self):
        '''
        verify class vars are properly defined.
        log debug for each that is not.

        @return: void
        @author: Breen Malmberg
        '''

        if not self.cronddir:
            self.logger.log(LogPriority.DEBUG, "cron.d directory not defined")
        if not self.cronconf:
            self.logger.log(LogPriority.DEBUG,
                            "cron conf directory not defined")
        if not self.crondeny:
            self.logger.log(LogPriority.DEBUG,
                            "cron deny directory not defined")
        if not self.atallow:
            self.logger.log(LogPriority.DEBUG,
                            "at allow directory not defined")
        if not self.atdeny:
            self.logger.log(LogPriority.DEBUG, "at deny directory not defined")
        if not self.cronlog:
            self.logger.log(LogPriority.DEBUG,
                            "cron log directory not defined")
        if not self.cronallow:
            self.logger.log(LogPriority.DEBUG,
                            "cron allow directory not defined")
        if not self.crontab:
            self.logger.log(LogPriority.DEBUG, "crontab directory not defined")
        if not self.anacrontab:
            self.logger.log(LogPriority.DEBUG,
                            "anacrontab directory not defined")
        if not self.spoolcron:
            self.logger.log(LogPriority.DEBUG,
                            "spool cron directory not defined")
        if not self.cronhourly:
            self.logger.log(LogPriority.DEBUG,
                            "cron hourly directory not defined")
        if not self.crondaily:
            self.logger.log(LogPriority.DEBUG,
                            "cron daily directory not defined")
        if not self.cronweekly:
            self.logger.log(LogPriority.DEBUG,
                            "cron weekly directory not defined")
        if not self.cronmonthly:
            self.logger.log(LogPriority.DEBUG,
                            "cron monthly directory not defined")

    def initobjs(self):
        '''
        initialize objects to be used by this class

        @return: void
        @author: Breen Malmberg
        '''

        self.ch = CommandHelper(self.logger)

    def report(self):
        '''
        The report method examines the current configuration and determines
        whether or not it is correct. If the config is correct then the
        self.compliant, self.detailed results and self.currstate properties are
        updated to reflect the system status. self.rulesuccess will be updated
        if the rule does not succeed.

        @return: self.compliant
        @rtype: bool
        @author: Breen Malmberg
        @change: 2016/08/09 Breen Malmberg - Refactored method; fixed typos in
        doc block
        '''

        # defaults
        self.compliant = True
        self.detailedresults = ""

        try:

            if self.environ.getosfamily() == 'darwin':
                if not self.reportDarwin():
                    self.compliant = False
            else:
                if not self.reportLinux():
                    self.compliant = False

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.detailedresults += traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

    def find_ownership(self, filename):
        '''
        return dict containing user and group
        owner name of specified filename

        @return: ownership
        @rtype: dict
        @author: Breen Malmberg
        '''
        ownership = {}

        user = getpwuid(os.stat(filename).st_uid).pw_name
        group = getgrgid(os.stat(filename).st_gid).gr_name

        ownership['user'] = user
        ownership['group'] = group

        return ownership

    def reportDarwin(self):
        '''
        run report actions specific to mac os x (darwin)

        @return: retval
        @rtype: bool
        @author: Breen Malmberg
        '''

        retval = True
        cronlogopt = False
        syslog = '/etc/syslog.conf'

        try:
            # check permissions on cron/at files
            for item in self.reportcronchmodfiledict:
                if os.path.exists(item):
                    perms = self.getPerms(item)
                    wantedPerms = self.reportcronchmodfiledict[item]
                    if perms != wantedPerms:
                        retval = False
                        self.detailedresults += "\nPermissions for " + item + \
                            " are not correct: expected " + wantedPerms + \
                            ", found " + perms

            # check ownership on cron/at files
            for item in self.cronchownfilelist:
                if os.path.exists(item):
                    ownership = self.find_ownership(item)
                    if ownership['user'] != self.rootacc:
                        retval = False
                        self.detailedresults += "\nUser ownership for " + \
                            item + " is not correct: expected " + \
                            self.rootacc + ", found " + ownership['user']
                    if ownership['group'] not in self.macgroups:
                        retval = False
                        self.detailedresults += "\nGroup ownership for " + \
                            item + " is not correct: expected " + \
                            self.macgroups + ", found " + ownership['group']

            if os.path.exists(syslog):
                f = open(syslog, 'r')
                contentlines = f.readlines()
                f.close()

                for line in contentlines:
                    if re.search('cron\.\*\s*' + re.escape(self.cronlog), line,
                                 re.IGNORECASE):
                        cronlogopt = True

            if not cronlogopt:
                retval = False
                self.detailedresults += "\nCron logging not enabled in: " + \
                    "/etc/syslog.conf"

        except Exception:
            raise
        return retval

    def getPerms(self, filepath):
        '''
        return the octal representation of the permissions
        (4 digit number, 0 padded)

        @return: perms
        @rtype: string
        @author: Breen Malmberg
        '''
        # init the return variable to
        # some initial default value
        perms = '0000'

        try:

            mode = os.stat(filepath).st_mode
            perms = oct(stat.S_IMODE(mode))

        except Exception:
            raise
        return perms

    def reportLinux(self):
        '''
        run report actions for linux systems

        @return: retval
        @rtype: bool
        @author: Breen Malmberg
        '''

        retval = True

        try:

            # check permissions on cron/at files
            for item in self.reportcronchmodfiledict:
                if os.path.exists(item):
                    perms = self.getPerms(item)
                    if perms != self.reportcronchmodfiledict[item]:
                        retval = False
                        self.detailedresults += "\nPermissions for " + item + \
                            " are not correct"

            # check ownership on cron/at files
            for item in self.cronchownfilelist:
                if os.path.exists(item):
                    ownership = self.find_ownership(item)
                    if ownership['user'] != self.rootacc:
                        retval = False
                        self.detailedresults += "\nUser ownership for " + \
                            item + " is not correct"
                    if ownership['group'] != self.rootacc:
                        retval = False
                        self.detailedresults += "\nGroup ownership for " + \
                            item + " is not correct"

            # check for files that shouldn't exist
            if os.path.exists(self.crondeny):
                retval = False
                self.detailedresults += "Unwanted file: " + \
                    str(self.crondeny) + " was found and should not exist\n"
            if os.path.exists(self.atdeny):
                retval = False
                self.detailedresults += "Unwanted file: " + \
                    str(self.crondeny) + " was found and should not exist\n"

            # check for files that need to exist
            if not os.path.exists(self.cronallow):
                retval = False
                self.detailedresults += "Required configuration file: " + \
                    str(self.atdeny) + " was not found\n"
            else:
                # check for correct configuration of cron.allow
                f = open(self.cronallow, 'r')
                contentlines = f.readlines()
                f.close()

                for line in contentlines:
                    if re.search('^' + self.rootacc, line):
                        rootcronallow = True

                if not rootcronallow:
                    retval = False
                    self.detailedresults += "Required configuration option " + \
                        "not found in: " + str(self.cronallow)
            if not os.path.exists(self.atallow):
                retval = False
                self.detailedresults += "Required configuration file: " + \
                    str(self.atallow) + " was not found\n"
            else:
                # check for correct configuration of at.allow
                f = open(self.atallow, 'r')
                contentlines = f.readlines()
                f.close()

                for line in contentlines:
                    if re.search('^' + self.rootacc, line):
                        rootatallow = True

                if not rootatallow:
                    retval = False
                    self.detailedresults += "Required configuration option " + \
                        "not found in: " + str(self.atallow)

            # check if cron logging is enabled
            cronlogopt = False
            if os.path.exists(self.cronconf):
                f = open(self.cronconf, 'r')
                contentlines = f.readlines()
                f.close()

                for line in contentlines:
                    if re.search('^CRONLOG\=YES', line, re.IGNORECASE):
                        cronlogopt = True

                if not cronlogopt:
                    retval = False
                    self.detailedresults += "Required configuration option " + \
                        "not found in: " + str(self.cronconf)

            else:
                retval = False
                self.detailedresults += "Required configuration file: " + \
                    str(self.cronconf) + " was not found\n"

        except Exception:
            raise
        return retval

    def fix(self):
        '''
        The fix method will apply the required settings to the system.
        self.rulesuccess will be updated if the rule does not succeed.

        @return: self.rulesuccess
        @rtype: bool
        @author: Breen Malmberg
        @change: 2016/08/09 Breen Malmberg - Refactored method; fixed typos in
        doc block
        '''

        # defaults
        self.detailedresults = ""
        self.rulesuccess = True
        self.iditerator = 0
        # Delete old undo events
        eventlist = self.statechglogger.findrulechanges(self.rulenumber)
        for event in eventlist:
            self.statechglogger.deleteentry(event)

        try:
            if self.SecureATCRON.getcurrvalue():

                if self.environ.getosfamily() == 'darwin':
                    if not self.fixDarwin():
                        self.rulesuccess = False
                else:
                    if not self.fixLinux():
                        self.rulesuccess = False

            else:
                self.detailedresults += "\nThis rule's CI is currently " + \
                    "disabled. Fix did not run"
                self.logger.log(LogPriority.DEBUG, "SecureATCRON's fix " +
                                "method was run, but the CI was disabled")

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess,
                                   self.detailedresults)
        return self.rulesuccess

    def fixDarwin(self):
        '''
        run fix actions specific to darwin systems

        @return: retval
        @rtype: bool
        @author: Breen Malmberg
        @change: Breen Malmberg - 3/15/2017 - changed group id in os.chown
                calls (80=admin) from 0 (wheel)
        '''

        success = True
        cronlinefound = False
        unload = "/bin/launchctl unload " + \
            "/System/Library/LaunchDaemons/com.apple.syslogd.plist"
        load = "/bin/launchctl load " + \
            "/System/Library/LaunchDaemons/com.apple.syslogd.plist"
        syslog = '/etc/syslog.conf'

        try:

            for item in self.fixcronchmodfiledict:
                if os.path.exists(item):
                    os.chmod(item, self.fixcronchmodfiledict[item])
            for item in self.cronchownfilelist:
                if os.path.exists(item):
                    os.chown(item, 0, 80)

            if os.path.exists(syslog):
                tmpsyslog = syslog + '.stonixtmp'
                # get current contents of existing syslog.conf
                f = open(syslog, 'r')
                contentlines = f.readlines()
                f.close()

                for line in contentlines:
                    if re.search('cron\.\*\s+' + re.escape(self.cronlog), line, re.IGNORECASE):
                        cronlinefound = True

                if not cronlinefound:
                    # append the desired config line
                    contentlines.append('\ncron.* ' + self.cronlog)

                # write appended contents to temp file
                tf = open(tmpsyslog, 'w')
                tf.writelines(contentlines)
                tf.close()

                os.rename(tmpsyslog, syslog)
                os.chown(syslog, 0, 80)

            # restart the syslogd service to read the new setting
            self.ch.executeCommand(unload)
            retcode = self.ch.getReturnCode()
            if retcode != 0:
                self.logger.log(LogPriority.DEBUG, "Failed to run command: " + str(unload))
                success = False
            self.ch.executeCommand(load)
            retcode = self.ch.getReturnCode()
            if retcode != 0:
                self.logger.log(LogPriority.DEBUG, "Failed to run command: " + str(load))
                success = False

        except Exception:
            raise
        return success

    def fixLinux(self):
        '''
        run fix actions specific to linux systems

        @return: retval
        @rtype: bool
        @author: Breen Malmberg
        '''

        cronremovelist = [self.crondeny, self.atdeny]
        success = True

        try:
            # set ownership on files
            for item in self.cronchownfilelist:
                if os.path.exists(item):
                    perms = stat.S_IMODE(os.stat(item).st_mode)
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    setPerms(item, [0, 0, perms], self.logger,
                             self.statechglogger, myid)

            # set permissions on files
            for item in self.fixcronchmodfiledict:
                if os.path.exists(item):
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    perms = self.fixcronchmodfiledict[item]
                    setPerms(item, [-1, -1, perms], self.logger,
                             self.statechglogger, myid)

            # remove the deny files
            for item in cronremovelist:
                if os.path.exists(item):
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    event = {"eventtype": "deletion",
                             "filepath": item}
                    self.statechglogger.recordfiledelete(item, myid)
                    self.statechglogger.recordchgevent(myid, event)
                    os.remove(item)

            # write root to the cron.allow file
            if os.path.exists(self.cronallow):
                tmpcronallow = self.cronallow + '.stonixtmp'
                tf = open(tmpcronallow, 'w')
                tf.write(self.rootacc)
                tf.close()

                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                event = {'eventtype': 'conf',
                         'filename': self.cronallow}
                self.statechglogger.recordchgevent(myid, event)
                self.statechglogger.recordfilechange(self.cronallow,
                                                     tmpcronallow, myid)
                os.rename(tmpcronallow, self.cronallow)

                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                setPerms(self.cronallow, [0, 0, 0o400], self.logger,
                         self.statechglogger, myid)
                resetsecon(self.cronallow)

            else:
                f = open(self.cronallow, 'w')
                f.write(self.rootacc)
                f.close()

                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                event = {'eventtype': 'creation',
                         'filename': self.cronallow}
                self.statechglogger.recordchgevent(myid, event)
                setPerms(self.cronallow, [0, 0, 0o400], self.logger)

            # write root to the at.allow file
            if os.path.exists(self.atallow):
                tmpatallow = self.atallow + '.stonixtmp'
                tf = open(tmpatallow, 'w')
                tf.write(self.rootacc)
                tf.close()

                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                event = {'eventtype': 'conf',
                         'filename': self.atallow}
                self.statechglogger.recordchgevent(myid, event)
                self.statechglogger.recordfilechange(self.atallow,
                                                     tmpatallow, myid)
                os.rename(tmpatallow, self.atallow)

                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                setPerms(self.atallow, [0, 0, 0o400], self.logger,
                         self.statechglogger, myid)
                resetsecon(self.atallow)

            else:
                f = open(self.atallow, 'w')
                f.write(self.rootacc)
                f.close()
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                event = {'eventtype': 'creation',
                         'filename': self.atallow}
                self.statechglogger.recordchgevent(myid, event)
                setPerms(self.atallow, [0, 0, 0o400], self.logger)

            # enable cron logging
            if os.path.exists(self.cronconf):
                tmpcronconf = self.cronconf + '.stonixtmp'
                tf = open(tmpcronconf, 'w')
                tf.write('CRONLOG=YES')
                tf.close()

                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                event = {'eventtype': 'conf',
                         'filename': self.cronconf}
                self.statechglogger.recordchgevent(myid, event)
                self.statechglogger.recordfilechange(self.cronconf,
                                                     tmpcronconf, myid)
                os.rename(tmpcronconf, self.cronconf)

                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                setPerms(self.cronconf, [0, -1, 0o400], self.logger,
                         self.statechglogger, myid)
                resetsecon(self.cronconf)
            else:
                f = open(self.cronconf, 'w')
                f.write('CRONLOG=YES')
                f.close()

                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                event = {'eventtype': 'creation',
                         'filename': self.cronconf}
                self.statechglogger.recordchgevent(myid, event)
                setPerms(self.cronconf, [0, -1, 0o400], self.logger)

        except Exception:
            raise
        return success
