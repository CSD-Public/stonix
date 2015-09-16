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
'''
from __future__ import absolute_import
import os
import re
import subprocess
import traceback
import random

from ..rule import Rule
from ..CommandHelper import CommandHelper
from ..pkghelper import Pkghelper
from ..stonixutilityfunctions import resetsecon
from ..logdispatcher import LogPriority
from ..localize import PROXY, UPDATESERVERS


class SoftwarePatching(Rule):
    '''
    The Software Patching class checks to see if the system is patched, is
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
        self.helptext = "The SoftwarePatching rule will check to see if " + \
            "all software is patched, if the computer is using local " + \
            "update sources (if available), and if the package manager is " + \
            "using GPG secured updates where applicable. This rule will " + \
            "also ensure that the system has a scheduled (cron) job to " + \
            "install updates automatically on systems where that is feasible."
        self.rootrequired = True
        self.applicable = {'type': 'black', 'family': ['darwin', 'solaris']}
        self.ci = self.initCi("bool",
                              "scheduledupdate",
                              "To disable creation of a scheduled " +
                              "update job set the value of this " +
                              "setting to no or false. Doing so " +
                              "puts a larger burden for keeping " +
                              "this system up to date on the system " +
                              "administrators. This setting doesn't " +
                              "apply to some systems whose updates " +
                              "cannot be installed automatically " +
                              "for various reasons.",
                              True)
        self.guidance = ['CCE 14813-0', 'CCE 14914-6', 'CCE 4218-4',
                         'CCE 14440-2']
        self.caveats = ''
        self.ch = CommandHelper(self.logger)
        self.ph = Pkghelper(self.logger, self.environ)

    def updated(self):
        '''
        This method checks to see if the system is fully patched or if there
        are updates that need to be done. Returns True if the system
        is patched or the check doesn't apply. If there are updates that need
        to be applied then it returns False.

        @return: bool
        @author: dkennel
        '''
        updated = False
        osEnvBkup = os.environ
        try:
            self.logger.log(LogPriority.DEBUG, 'Looking for packaging system')
            if os.path.exists('/usr/bin/yum'):
                self.logger.log(LogPriority.DEBUG, 'Found yum')
                if PROXY is not None:
                    os.environ["http_proxy"] = PROXY
                    os.environ["https_proxy"] = PROXY
                cmd = '/usr/bin/yum -q check-update &> /dev/null'
                ret = subprocess.call(cmd, shell=True, close_fds=True)
                self.logger.log(LogPriority.DEBUG,
                                'Value of yum check: ' + str(ret))
                if ret == 0:
                    updated = True
            elif os.path.exists('/usr/sbin/freebsd-update'):
                self.logger.log(LogPriority.DEBUG, 'Found freebsd-update')
                cmd = '/usr/sbin/freebsd-update fetch'
                chk = subprocess.Popen(cmd, shell=True, close_fds=True,
                                       stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE)
                chkdata = chk.stdout.readlines()
                self.logger.log(LogPriority.DEBUG,
                                'Value of freebsd-update fetch: ' +
                                str(chkdata))
                for line in chkdata:
                    if re.search('No updates needed', line):
                        updated = True
            elif os.path.exists('/usr/bin/apt-get'):
                self.logger.log(LogPriority.DEBUG, 'Found apt-get')
                cmd = '/usr/bin/apt-get'
                if PROXY is not None:
                    os.environ["http_proxy"] = PROXY
                    os.environ["https_proxy"] = PROXY
                cmd1 = cmd + ' -q update &> /dev/null'
                cmd2 = cmd + ' -s upgrade'
                self.ch.executeCommand(cmd1)
                ret = self.ch.getReturnCode()
                self.logger.log(LogPriority.DEBUG,
                                'Value of apt-get update: ' + str(ret))
                if ret != 0:
                    # we couldn't update the apt-get cache network problem?
                    return False
                self.ch.executeCommand(cmd2)
                chk = self.ch.getReturnCode()
                chkdata = self.ch.getOutputString()
                self.logger.log(LogPriority.DEBUG,
                                'Value of apt-get -s upgrade: ' + chkdata)
                if re.search('^0 upgraded', chkdata, re.M):
                    updated = True
            elif os.path.exists('/usr/bin/emerge'):
                self.logger.log(LogPriority.DEBUG, 'Found emerge')
                cmd = '/usr/bin/emerge'
                cmd = '/usr/bin/apt-get'
                if PROXY is not None:
                    os.environ["http_proxy"] = PROXY
                    os.environ["https_proxy"] = PROXY
                cmd1 = cmd + ' --sync'
                cmd2 = cmd + ' -NuDp'
                ret = subprocess.call(cmd1, shell=True, close_fds=True)
                self.logger.log(LogPriority.DEBUG,
                                'Value of emerge --sync: ' + str(ret))
                if ret != 0:
                    # we couldn't update the portage cache network problem?
                    return False
                chk = subprocess.Popen(cmd2, shell=True, close_fds=True,
                                       stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE)
                chkdata = chk.stdout.readlines()
                updatecount = 0
                self.logger.log(LogPriority.DEBUG,
                                'Value of updatecount: ' + str(updatecount))
                for line in chkdata:
                    if re.search('ebuild', line):
                        updatecount = updatecount + 1
                if updatecount == 0:
                    updated = True
            elif os.path.exists('/usr/bin/zypper'):
                self.logger.log(LogPriority.DEBUG, 'Found zypper')
                if PROXY is not None:
                    os.environ["http_proxy"] = PROXY
                    os.environ["https_proxy"] = PROXY
                cmd = '/usr/bin/zypper lp'
                chk = subprocess.Popen(cmd, shell=True, close_fds=True,
                                       stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE)
                chkdata = chk.stdout.readlines()
                updatecount = 0
                self.logger.log(LogPriority.DEBUG,
                                'Value of updatecount: ' + str(updatecount))
                for line in chkdata:
                    if re.search('security', line):
                        updatecount = updatecount + 1
                if updatecount == 0:
                    updated = True
            else:
                self.caveats = self.caveats + 'Could not determine update ' + \
                    'status of this system. '
        except(OSError):
            # Something bad happened while checking the status of updates
            return False
        os.environ = osEnvBkup
        return updated

    def report(self):
        '''Method to report on the configuration status of the system.

        @return: bool
        @author: dkennel
        '''
        try:
            self.detailedresults = ""
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
                    'The system is not configured to use signed updates.' + \
                    'Check yum.conf, all rpmrc files and all .repo files.'

            # Make variables available to fix()
            self.crons = crons
            self.updatesec = updatesec

            self.detailedresults = self.detailedresults + self.caveats
        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception, err:
            self.rulesuccess = False
            self.detailedresults = self.detailedresults + "\n" + str(err) + \
                " - " + str(traceback.format_exc())
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

    def cronsconfigured(self):
        '''Method to check to see if updates are scheduled to run automatically

        @return: bool
        @author: dkennel
        '''
        cronpresent = False
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
        return cronpresent

    def localupdatesource(self):
        '''Method to check to see if the system is getting updates from a local
        source.

        @return: bool
        @author: dkennel
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
                'A local update source may not be available for this platform.'
        return local

    def updatesecurity(self):
        '''Method to check to see if the package signing is set up correctly.

        @return: bool
        @author: dkennel
        '''
        gpgok = False
        gpgcheckok = True
        if os.path.exists('/bin/rpm'):
            rpmcmd = '/bin/rpm -q --queryformat "%{SUMMARY}\n" gpg-pubkey'
            cmd = subprocess.Popen(rpmcmd, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, shell=True,
                                   close_fds=True)
            cmddata = cmd.stdout.readlines()
            for line in cmddata:
                if re.search('security@redhat.com|security@suse|fedora@fedoraproject|security@centos', line) and re.search('gpg', line):
                    gpgok = True

        filelist = []
        repodir = '/etc/yum.repos.d'
        if os.path.exists(repodir):
            for repo in os.listdir(repodir):
                filelist.append(os.path.join(repodir, repo))
            for conffile in filelist:
                self.logger.log(LogPriority.DEBUG,
                                ['SoftwarePatching.updatesecurity',
                                 'Checking conf file ' + conffile])
                handle = open(conffile, 'r')
                confdata = handle.read()
                self.logger.log(LogPriority.DEBUG,
                                ['SoftwarePatching.updatesecurity',
                                 'Conf file data: ' + str(confdata)])
                if re.search('gpgcheck=0', confdata):
                    gpgcheckok = False
                handle.close()
            if os.path.exists('/etc/yum.conf'):
                handle = open('/etc/yum.conf', 'r')
                confdata = handle.read()
                if not re.search('gpgcheck=1', confdata):
                    gpgcheckok = False
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

        if gpgok and gpgcheckok:
            return True
        else:
            return False

    def fix(self):
        '''Method to set system settings to configure software update sources
        and schedule updates.

        @return: bool
        @author: dkennel
        '''
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
                "manually."
            elif not self.ci.getcurrvalue():
                self.detailedresults = str(self.ci.getkey()) + \
                " was disabled. No action was taken."
        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception, err:
            self.rulesuccess = False
            self.detailedresults = self.detailedresults + "\n" + str(err) + \
            " - " + str(traceback.format_exc())
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.rulesuccess

    def makecrons(self):
        '''
        This method creates cron entries for automating update installations.

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
        '''
        This method will install the gpg keys used by RPM based distros to
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
        """
        Return the system to the state that it was in before this rule ran.

        @author: D. Kennel
        """
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
