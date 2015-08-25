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
'''
Created on Apr 25, 2013

The AT and CRON job schedulers are used to schedule jobs for running at a later
date/time. These daemons should be configured defensively. The SecureATCRON
class restricts permissions on the files and directories associated with these
daemons to authorized users only and enables and configures logging for
these daemons.

@author: bemalmbe
@change: dkennel 04/21/2014 Updated CI invocation, fixed CI instruction text,
fixed bug where CI was not referenced before performing Fix() actions.
@change: 2015/04/17 dkennel updated for new isApplicable
'''

from __future__ import absolute_import
import os
import re
import traceback

from ..rule import Rule
from ..stonixutilityfunctions import cloneMeta, checkPerms
from ..logdispatcher import LogPriority


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
        self.config = config
        self.environ = environ
        self.statechglogger = statechglogger
        self.logger = logger
        self.rulenumber = 33
        self.currstate = "notconfigured"
        self.targetstate = "configured"
        self.rulename = 'SecureATCRON'
        self.compliant = False
        self.mandatory = True
        self.helptext = '''The AT and CRON job schedulers are used to schedule jobs for running at a later
date/time. These daemons should be configured defensively. The SecureATCRON
class restricts permissions on the files and directories associated with these
daemons to authorized users only and enables and configures logging for
these daemons'''
        self.rootrequired = True
        self.detailedresults = 'The SecureATCRON rule has not yet been run'
        self.compliant = False
        self.guidance = ['CIS', 'NSA(3.4)', 'CCE-4644-1', 'CCE-4543-5',
                         'CCE-4437-0', 'CCE-4693-8', 'CCE-4710-0',
                         'CCE-4230-9', 'CCE-4445-3']
        self.applicable = {'type': 'black',
                           'family': ['darwin']}

        #init CIs
        datatype = 'bool'
        key = 'SecureATCRON'
        instructions = '''To prevent the restriction of access to the AT and CRON utilities
set the vaule of SECUREATCRON to False.'''
        default = True
        self.SecureATCRON = self.initCi(datatype, key, instructions, default)

        # setup class vars
        self.cronchownfilelist = ['/etc/cron.hourly', '/etc/cron.daily',
                                '/etc/cron.weekly', '/etc/cron.monthly',
                                '/etc/cron.d', '/etc/crontab',
                                '/etc/anacrontab', '/var/cron/log',
                                'cron.allow', 'at.allow']
        self.cronchmodfiledict = {'/etc/crontab': 0644,
                                 '/etc/anacrontab': 0600,
                                 '/var/spool/cron': 0700,
                                 '/var/cron/log': 0600,
                                 '/etc/cron.allow': 0400,
                                 '/etc/at.allow': 0400}

    def report(self):
        '''
        The report method examines the current configuration and determines
        whether or not it is correct. If the config is correct then the
        self.compliant, self.detailed results and self.currstate properties are
        updated to reflect the system status. self.rulesuccess will be updated
        if the rule does not succeed.

        @return bool
        @author bemalmbe
        '''

        # defaults
        retval = True
        cronlogfound = False
        rootcronallow = False
        rootatallow = False

        try:

            # check for files that shouldn't exist
            if os.path.exists('/etc/cron.deny'):
                retval = False
            if os.path.exists('/etc/at.deny'):
                retval = False

            # check for files that need to exist
            if not os.path.exists('/etc/cron.allow'):
                retval = False
            else:
                # check for correct configuration of cron.allow
                f = open('/etc/cron.allow', 'r')
                contentlines = f.readlines()
                f.close()

                for line in contentlines:
                    if re.search('^root$', line):
                        rootcronallow = True

                if not rootcronallow:
                    retval = False
            if not os.path.exists('/etc/at.allow'):
                retval = False
            else:
                # check for correct configuration of at.allow
                f = open('/etc/at.allow', 'r')
                contentlines = f.readlines()
                f.close()

                for line in contentlines:
                    if re.search('^root$', line):
                        rootatallow = True

                if not rootatallow:
                    retval = False

            # check if cron logging is enabled
            if os.path.exists('/etc/default/cron'):
                f = open('/etc/default/cron', 'r')
                contentlines = f.readlines()
                f.close()

                for line in contentlines:
                    if re.search('^CRONLOG=YES', line):
                        cronlogfound = True

                if not cronlogfound:
                    retval = False

            else:
                retval = False

            # check ownership/permissions on cron/at files
            for item in self.cronchmodfiledict:
                if os.path.exists(item):
                    perms = [0, 0, self.cronchmodfiledict[item]]
                    if not checkPerms(item, perms, self.logger):
                        retval = False

            if retval:
                self.compliant = True
                self.detailedresults = 'This system is compliant with the SecureATCron rule'
                self.currstate = 'configured'
            else:
                self.compliant = False
                self.detailedresults = 'This system is not compliant with the SecureATCron rule'
                self.currstate = 'notconfigured'

            return retval

        except IOError:
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.DEBUG, ['SecureATCRON.report ',
                                               self.detailedresults])
        except (KeyboardInterrupt, SystemExit):
            self.rulesuccess = False
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.ERROR, ['SecureATCRON.report ',
                                                self.detailedresults])
            return False

    def fix(self):
        '''
        The fix method will apply the required settings to the system.
        self.rulesuccess will be updated if the rule does not succeed.

        @author bemalmbe
        '''

        # defaults
        cronremovelist = ['/etc/cron.deny', '/etc/at.deny']
        croncfgfile = '/etc/default/cron'
        if self.SecureATCRON.getcurrvalue():
            try:

                # set ownership on files
                for item in self.cronchownfilelist:
                    if os.path.exists(item):
                        os.chown(item, 0, 0)

                # set permissions on files
                for item in self.cronchmodfiledict:
                    if os.path.exists(item):
                        os.chmod(item, self.cronchmodfiledict[item])

                # remove the deny files
                for item in cronremovelist:
                    if os.path.exists(item):
                        os.remove(item)

                # write root to the cron.allow file
                if os.path.exists('/etc/cron.allow'):

                    tempcronallow = open('/etc/cron.allow.stonixtmp', 'w')
                    tempcronallow.write('root')
                    tempcronallow.close()

                    cloneMeta(self.logger, '/etc/cron.allow',
                              '/etc/cron.allow.stonixtmp')
                    event = {'eventtype': 'conf',
                             'eventstart': self.currstate,
                             'eventend': self.targetstate,
                             'filename': '/etc/cron.allow'}
                    myid = '0033001'
                    self.statechglogger.recordchgevent(myid, event)
                    self.statechglogger.recordfilechange('/etc/cron.allow',
                                                         '/etc/cron.allow.stonixtmp',
                                                         myid)
                    os.rename('/etc/cron.allow.stonixtmp', '/etc/cron.allow')

                else:
                    f = open('/etc/cron.allow', 'w')
                    f.write('root')
                    f.close()
                    event = {'eventtype': 'creation',
                             'eventstart': 'False',
                             'eventend': 'True',
                             'filename': '/etc/cron.allow'}
                    myid = '0033001'
                    os.chown('/etc/cron.allow', 0, 0)
                    os.chmod('/etc/cron.allow', 0400)
                    self.statechglogger.recordchgevent(myid, event)

                # write root to the at.allow file
                if os.path.exists('/etc/at.allow'):

                    tempatallow = open('/etc/at.allow.stonixtmp', 'w')
                    tempatallow.write('root')
                    tempatallow.close()

                    cloneMeta(self.logger, '/etc/at.allow', '/etc/at.allow.stonixtmp')
                    event = {'eventtype': 'conf',
                             'eventstart': self.currstate,
                             'eventend': self.targetstate,
                             'filename': '/etc/at.allow'}
                    myid = '0033002'
                    self.statechglogger.recordchgevent(myid, event)
                    self.statechglogger.recordfilechange('/etc/at.allow',
                                                         '/etc/at.allow.stonixtmp',
                                                         myid)
                    os.rename('/etc/at.allow.stonixtmp', '/etc/at.allow')

                else:
                    f = open('/etc/at.allow', 'w')
                    f.write('root')
                    f.close()
                    event = {'eventtype': 'creation',
                             'eventstart': 'False',
                             'eventend': 'True',
                             'filename': '/etc/at.allow'}
                    myid = '0033002'
                    os.chown('/etc/at.allow', 0, 0)
                    os.chmod('/etc/at.allow', 0400)
                    self.statechglogger.recordchgevent(myid, event)

                # enable cron logging
                if os.path.exists(croncfgfile):

                    cronlog = open(croncfgfile + '.stonixtmp', 'w')
                    cronlog.write('CRONLOG=YES')
                    cronlog.close()

                    cloneMeta(self.logger, croncfgfile, croncfgfile + \
                              '.stonixtmp')
                    event = {'eventtype': 'conf',
                             'eventstart': self.currstate,
                             'eventend': self.targetstate,
                             'filename': croncfgfile}
                    myid = '0033003'
                    self.statechglogger.recordchgevent(myid, event)
                    self.statechglogger.recordfilechange(croncfgfile,
                                                         croncfgfile + \
                                                         '.stonixtmp',
                                                         myid)
                    os.rename(croncfgfile + '.stonixtmp', croncfgfile)
                else:
                    f = open('/etc/default/cron', 'w')
                    f.write('CRONLOG=YES')
                    f.close()

                    event = {'eventtype': 'creation',
                             'eventstart': 'False',
                             'eventend': 'True',
                             'filename': '/etc/default/cron'}
                    myid = '0033003'

                    # can't use os.chmod because we don't know what gid bin
                    # group is
                    os.system('chown root:bin /etc/default/cron')
                    os.chmod('/etc/default/cron', 0400)
                    self.statechglogger.recordchgevent(myid, event)

            except (IOError, OSError):
                self.detailedresults = traceback.format_exc()
                self.logger.log(LogPriority.DEBUG, ['SecureATCRON.fix ',
                                                   self.detailedresults])
            except (KeyboardInterrupt, SystemExit):
                self.rulesuccess = False
                self.detailedresults = traceback.format_exc()
                self.logger.log(LogPriority.ERROR, ['SecureATCRON.fix',
                                                    self.detailedresults])
