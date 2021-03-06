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
Created on Oct 11, 2012
The Software Patching class checks to see if the system is patched, is using
gpg secured updates where applicable and ensures that the system is
updating automatically from a scheduled job where feasible.
@author: dkennel
@change: 04/18/2014 ekkehard Implemented self.detailedresults flow
@change: 04/18/2014 ekkehard ci updates
@change: 2015/04/17 dkennel updated for new isApplicable
@change: 2015/04/20 dkennel updated to check rpmrc files for "nosignature"
         option per DISA STIG.
@change: 2015/09/11 eball Fix apt-get compatibility
@change: 2017/04/12 Breen Malmberg changed applicability to exclude opensuse
        for the time being, until the problems discovered in 0.9.7 triage can
        be fixed for it
'''

import os
import re
import subprocess
import traceback
import random

from rule import Rule
from CommandHelper import CommandHelper
from pkghelper import Pkghelper
from stonixutilityfunctions import resetsecon
from logdispatcher import LogPriority
from localize import PROXY, UPDATESERVERS


class SoftwarePatching(Rule):
    '''The Software Patching class checks to see if the system is patched, is
    using gpg secured updates where applicable is using local update servers
    when available, and ensures that the system is
    updating automatically from a scheduled job where feasible.


    '''

    def __init__(self, config, environ, logger, statechglogger):
        '''
        Constructor
        '''
        Rule.__init__(self, config, environ, logger, statechglogger)
        self.logger = logger
        self.statechglogger = statechglogger
        self.rulenumber = 7
        self.rulename = 'SoftwarePatching'
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.sethelptext()
        self.rootrequired = True
        self.environ = environ
        self.applicable = {'type': 'black',
                           'family': ['darwin', 'solaris', 'suse']}

        data = "bool"
        key = "SCHEDULEUPDATE"
        instructions = "To disable creation of a scheduled " + \
                       "update job set the value of this " + \
                       "setting to no or false. Doing so " + \
                       "puts a larger burden for keeping " + \
                       "this system up to date on the system " + \
                       "administrators. This setting doesn't " + \
                       "apply to some systems whose updates " + \
                       "cannot be installed automatically " + \
                       "for various reasons. "
        default = True

        self.ci = self.initCi(data, key, instructions, default)

        self.guidance = ['CCE 14813-0', 'CCE 14914-6', 'CCE 4218-4',
                         'CCE 14440-2']
        self.caveats = ''
        self.ch = CommandHelper(self.logger)
        self.ph = Pkghelper(self.logger, self.environ)
        self.constlist = [PROXY, UPDATESERVERS]

    def updated(self):
        '''This method checks to see if the system is fully patched or if there
        are updates that need to be done. Returns True if the system
        is patched or the check doesn't apply. If there are updates that need
        to be applied then it returns False.


        :returns: updated

        :rtype: bool
@author: dkennel
@change: Breen Malmberg - 4/26/2017 - added method call checkUpdate()
        added code to use package helper instead of dynamically looking
        up the package manager and command to use

        '''

        updated = False
        osEnvBkup = os.environ
        if PROXY is not None:
            os.environ["http_proxy"] = PROXY
            os.environ["https_proxy"] = PROXY
        self.ph = Pkghelper(self.logger, self.environ)

        try:

            if not self.ph.checkUpdate():
                updated = True

        except Exception:
            raise
        os.environ = osEnvBkup
        return updated

    def report(self):
        '''Method to report on the configuration status of the system.


        :returns: self.compliant

        :rtype: bool
@author: dkennel

        '''

        self.detailedresults = ""
        self.caveats = ""

        # UPDATE THIS SECTION IF THE CONSTANTS BEING USED IN THIS CLASS CHANGE
        if not self.checkConsts(self.constlist):
            self.compliant = False
            self.detailedresults += "\nThis rule requires that the following constants, in localize.py, be defined and not None: PROXY, UPDATESERVERS"
            self.formatDetailedResults("report", self.compliant, self.detailedresults)
            return self.compliant

        try:

            self.logger.log(LogPriority.DEBUG, 'Checking patching')
            patchingcurrent = self.updated()
            self.logger.log(LogPriority.DEBUG, 'Checking cron jobs')
            crons = self.cronsconfigured()
            if not self.ph.determineMgr() == "apt-get":
                self.logger.log(LogPriority.DEBUG, 'Checking update source')
                localupdates = self.localupdatesource()
                self.logger.log(LogPriority.DEBUG, 'Checking update security')
                updatesec = self.updatesecurity()
                self.logger.log(LogPriority.DEBUG,
                                'patchingcurrent=' +
                                str(patchingcurrent))
                self.logger.log(LogPriority.DEBUG,
                                'crons=' + str(crons))
                self.logger.log(LogPriority.DEBUG,
                                'localupdates=' + str(localupdates))
                self.logger.log(LogPriority.DEBUG,
                                'updatesec=' + str(updatesec))
            else:
                localupdates = True
                updatesec = True

            if patchingcurrent and crons and localupdates and \
                    updatesec:
                self.compliant = True
                self.currstate = 'configured'
                self.detailedresults = 'System appears to be up to date ' + \
                                       'and all software patching settings look correct.\n'

            else:
                self.detailedresults = 'The following problems were ' + \
                                       'detected with system software patching:\n'
            if not patchingcurrent:
                self.detailedresults = self.detailedresults + \
                                       'The system is not current on available updates.\n'
            if not crons:
                self.detailedresults = self.detailedresults + \
                                       'The system is not configured for automatic updates.\n'
            if not localupdates:
                self.detailedresults = self.detailedresults + \
                                       'The system is not configured to use a local ' + \
                                       'update source.\n'
            if not updatesec:
                self.detailedresults = self.detailedresults + \
                                       'The system is not configured to use signed updates. ' + \
                                       'Check yum.conf, all rpmrc files and all .repo files. '

            # Make variables available to fix()
            self.crons = crons
            self.updatesec = updatesec

            self.detailedresults = self.detailedresults + self.caveats

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.compliant = False
            self.rulesuccess = False
            self.detailedresults = traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

    def cronsconfigured(self):
        '''Method to check to see if updates are scheduled to run automatically


        :returns: cronpresent

        :rtype: bool
@author: dkennel
@change: Breen Malmberg - 4/26/2017 - doc string edit; added try/except

        '''

        cronpresent = False

        try:

            if os.path.exists('/var/spool/cron/root'):
                fhandle = open('/var/spool/cron/root')
                crons = fhandle.readlines()
                fhandle.close()
                for line in crons:
                    if re.search('^#', line):
                        continue
                    elif re.search('yum', line) and re.search('-y update', line):
                        cronpresent = True
                    elif re.search('emerge -[NuD]{2,3}', line) and \
                            re.search('emerge --sync', line):
                        cronpresent = True
                    elif re.search('zypper -n', line) and \
                            re.search('patch|update|up|', line):
                        cronpresent = True
                    elif re.search('apt-get update', line) and \
                            re.search('apt-get -y upgrade', line):
                        cronpresent = True
                    elif re.search('freebsd-update fetch', line) and \
                            re.search('freebsd-update install', line):
                        cronpresent = True

        except Exception:
            raise
        return cronpresent

    def localupdatesource(self):
        '''Method to check to see if the system is getting updates from a local
        source.


        :returns: local

        :rtype: bool
@author: dkennel
@change: Breen Malmberg - 4/26/2017 - doc string edit; added try/except

        '''

        local = False
        myos = self.environ.getostype()

        if re.search('Red Hat Enterprise', myos):
            up2file = '/etc/sysconfig/rhn/up2date'
            if os.path.exists(up2file):
                fhandle = open(up2file, 'r')
                config = fhandle.read()
                fhandle.close()
                for server in UPDATESERVERS:
                    if re.search(server, config):
                        local = True
        elif self.environ.getosfamily() == 'darwin':
            pass
            # check plist value set local = True if correct.
        else:
            self.caveats = self.caveats + \
                           'A local update source may not be available for this platform. '
        return local

    def updatesecurity(self):
        '''Method to check to see if the package signing is set up correctly.


        :returns: pkgsigning

        :rtype: bool
@author: dkennel
@change: Breen Malmberg - 4/26/2017 - doc string edit; method now
        returns a variable; added try/except

        '''

        gpgok = False
        gpgcheckok = True

        try:

            if os.path.exists('/bin/rpm'):
                rpmcmd = '/bin/rpm -q --queryformat "%{SUMMARY}\n" gpg-pubkey'
                cmd = subprocess.Popen(rpmcmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True,
                                       close_fds=True)
                cmddata = cmd.stdout.readlines()

                for line in cmddata:
                    if re.search('security@redhat.com|security@suse|fedora@fedoraproject|security@centos',
                                 line.decode('utf-8')) and re.search('gpg', line.decode('utf-8')):
                        gpgok = True

            rpmrc = ['/etc/rpmrc', '/usr/lib/rpm/rpmrc',
                     '/usr/lib/rpm/redhat/rpmrc', '/root/.rpmrc']
            for rcfile in rpmrc:
                if os.path.exists(rcfile):
                    self.logger.log(LogPriority.DEBUG,
                                    ['SoftwarePatching.updatesecurity',
                                     'Checking RC file ' + rcfile])
                    rchandle = open(rcfile, 'r')
                    rcdata = rchandle.read()
                    self.logger.log(LogPriority.DEBUG,
                                    ['SoftwarePatching.updatesecurity',
                                     'RC File Data: ' + str(rcdata)])
                    if re.search('nosignature', rcdata):
                        gpgcheckok = False
                    rchandle.close()

            pkgsigning = gpgok and gpgcheckok

        except Exception:
            raise
        return pkgsigning

    def fix(self):
        '''Method to set system settings to configure software update sources
        and schedule updates.


        :returns: self.rulesuccess

        :rtype: bool
@author: dkennel

        '''

        if not self.checkConsts(self.constlist):
            self.rulesuccess = False
            self.formatDetailedResults("fix", self.rulesuccess, self.detailedresults)
            return self.rulesuccess

        try:

            self.detailedresults = ""
            if self.ci.getcurrvalue() and not self.crons:
                self.makecrons()
                mytype = 'conf'
                mystart = self.currstate
                myend = self.targetstate
                myid = '0007001'
                event = {'eventtype': mytype,
                         'startstate': mystart,
                         'endstate': myend}
                self.statechglogger.recordchgevent(myid, event)
                if not self.updatesec:
                    self.installkeys()
                self.detailedresults = "Automated updates configured. " + \
                                       "Local software update sources may need to be configured " + \
                                       "manually. "
            elif not self.ci.getcurrvalue():
                self.detailedresults = str(self.ci.getkey()) + \
                                       " was disabled. No action was taken. "
        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception as err:
            self.rulesuccess = False
            self.detailedresults = self.detailedresults + "\n" + str(err) + \
                                   " - " + str(traceback.format_exc())
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.rulesuccess

    def makecrons(self):
        '''This method creates cron entries for automating update installations.

        @author: dkennel


        '''
        rootcron = "/var/spool/cron/root"
        random.seed()
        hour = random.randrange(0, 5)
        minute = random.randrange(0, 59)
        crontime = str(minute) + " " + str(hour) + "  * * * "
        if os.path.exists('/usr/bin/yum') and \
                os.path.exists('/usr/sbin/rhn_check'):
            command = "/usr/sbin/rhn_check > /dev/null 2>&1 && /usr/bin/yum " \
                      + "--exclude=kernel* -y update > /dev/null 2>&1"
        elif os.path.exists('/usr/bin/yum'):
            command = "/usr/bin/yum --exclude=kernel* -y update > /dev/null 2>&1"
        elif os.path.exists('/usr/sbin/freebsd-update'):
            command = "/usr/sbin/freebsd-update fetch &> && " + \
                      "/usr/sbin/freebsd-update install &>"
        elif os.path.exists('/usr/bin/apt-get'):
            command = '/usr/bin/apt-get update &> && ' + \
                      '/usr/bin/apt-get -y upgrade'
        elif os.path.exists('/usr/bin/emerge'):
            command = '/usr/bin/emerge --sync &> && ' + \
                      '/usr/bin/emerge --NuD &> && /usr/bin/revdep-rebuild &>'
        elif os.path.exists('/usr/bin/zypper'):
            command = '/usr/bin/zypper -n up -l &>'
        cronentry = crontime + command
        self.logger.log(LogPriority.DEBUG,
                        ['SoftwarePatching.makecrons',
                         "Cronentry: " + cronentry])
        try:
            crontab = open(rootcron, 'a')
            crontab.write(cronentry)
            crontab.close()
        except (IOError):
            self.logger.log(LogPriority.ERROR,
                            ['SoftwarePatching.makecrons',
                             "Error writing to root user crontab entry"])
            self.rulesuccess = False

    def installkeys(self):
        '''This method will install the gpg keys used by RPM based distros to
        authenticate updates.

        @author: dkennel


        '''
        importcmd = '/bin/rpm --import '
        keylist = ['/etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release',
                   '/usr/share/rhn/RPM-GPG-KEY',
                   '/etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-17-primary',
                   '/etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-17-secondary',
                   '/etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-16-primary',
                   '/etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-16-secondary',
                   '/etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-6']
        for key in keylist:
            if not os.path.exists(key):
                continue
            try:
                proc = subprocess.Popen(importcmd + key, shell=True,
                                        close_fds=True, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE)
                cmdoutput = proc.stdout.read() + proc.stderr.read()
                self.logger.log(LogPriority.DEBUG,
                                ['SoftwarePatching.installkeys', cmdoutput])
            except (KeyboardInterrupt, SystemExit):
                # User initiated exit
                raise

            except Exception:
                self.detailedresults = traceback.format_exc()
                self.rulesuccess = False
                self.logger.log(LogPriority.ERROR,
                                ['SoftwarePatching.installkeys',
                                 self.detailedresults])

    def undo(self):
        '''


        :returns: @author: D. Kennel

        '''
        self.targetstate = 'notconfigured'
        try:
            event1 = self.statechglogger.getchgevent('0007001')
            if event1['startstate'] == 'notconfigured' and \
                    event1['endstate'] == 'configured':
                rootcron = "/var/spool/cron/root"
                fhandle = open(rootcron, 'r')
                crondata = fhandle.readlines()
                fhandle.close()
                newcron = []
                if os.path.exists('/usr/bin/yum') and \
                        os.path.exists('/usr/sbin/rhn_check'):
                    command = "/usr/sbin/rhn_check > /dev/null 2>&1 && /usr/bin/yum " \
                              + "--exclude=kernel* -y update > /dev/null 2>&1"
                elif os.path.exists('/usr/bin/yum'):
                    command = "/usr/bin/yum --exclude=kernel* -y update > /dev/null 2>&1"
                elif os.path.exists('/usr/sbin/freebsd-update'):
                    command = "/usr/sbin/freebsd-update fetch &> && " + \
                              "/usr/sbin/freebsd-update install &>"
                elif os.path.exists('/usr/bin/apt-get'):
                    command = '/usr/bin/apt-get update &> && ' + \
                              '/usr/bin/apt-get -y upgrade'
                elif os.path.exists('/usr/bin/emerge'):
                    command = '/usr/bin/emerge --sync &> && ' + \
                              '/usr/bin/emerge --NuD &> && /usr/bin/revdep-rebuild &>'
                elif os.path.exists('/usr/bin/zypper'):
                    command = '/usr/bin/zypper -n up -l &>'
                else:
                    command = ''
                if len(command) != 0:
                    for line in crondata:
                        if not re.search(command, line):
                            newcron.append(line)
                    whandle = open(rootcron, 'w')
                    whandle.writelines(newcron)
                    whandle.close()
                    os.chown(rootcron, 0, 0)
                    os.chmod(rootcron, 384)
                    resetsecon(rootcron)

        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except KeyError:
            # Key not found in statechglogger
            return
        except Exception:
            self.detailedresults = traceback.format_exc()
            self.rulesuccess = False
            self.logger.log(LogPriority.ERROR,
                            ['SoftwarePatching.undo',
                             self.detailedresults])
        self.report()
        if self.currstate == self.targetstate:
            self.detailedresults = '''SoftwarePatching: Some changes successfully reverted'''
