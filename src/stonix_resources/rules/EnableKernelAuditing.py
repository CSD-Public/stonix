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
Created on Aug 12, 2015

The kernel auditing service is provided for system auditing. By default, the
service audits certain types of security-relevant events such as system logins,
account modifications, and authentication events.

@author: Breen Malmberg
@change: 2015/10/07 eball Help text/PEP8 cleanup
@change: 2015/11/09 ekkehard - make eligible of OS X El Capitan
@change: 2017/07/07 ekkehard - make eligible for macOS High Sierra 10.13
@change: 2017/08/28 Breen Malmberg Fixing to use new help text methods
@change: 2017/10/23 rsn - change to new service helper interface
'''

from __future__ import absolute_import

from ..logdispatcher import LogPriority
from ..rule import Rule
from ..KVEditorStonix import KVEditorStonix
from ..CommandHelper import CommandHelper
from ..ServiceHelper import ServiceHelper
from ..pkghelper import Pkghelper
from ..stonixutilityfunctions import resetsecon
from ..stonixutilityfunctions import iterate

import traceback
import os
import re


class EnableKernelAuditing(Rule):
    '''
    classdocs
    '''

    def __init__(self, config, environ, logger, statechglogger):
        '''
        Constructor
        '''
        Rule.__init__(self, config, environ, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 67
        self.rulename = 'EnableKernelAuditing'
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.sethelptext()
        self.rootrequired = True
        self.compliant = False
        self.guidance = ['CIS', 'NSA 2.6.2', 'CCE-4665-5', 'CCE-4679-7',
                         'CCE-4075-8', 'CCE-4600-3', 'CCE-4498-2',
                         'CCE-4401-6', 'CCE-4337-2', 'CCE-4606-0',
                         'CCE-4610-2']
        self.iditerator = 0
        self.applicable = {'type': 'white',
                           'family': ['linux', 'solaris', 'freebsd'],
                           'os': {'Mac OS X': ['10.9', 'r', '10.13.10']}}
        # init CIs
        datatype = 'bool'
        key = 'EnableKernelAuditing'
        instructions = """To prevent kernel auditing from being enabled on \
this system, set the value of EnableKernelAuditing to False"""
        default = True
        self.ci = self.initCi(datatype, key, instructions, default)

    def searchFileContents(self, contents, searchstring):
        '''
        search specified filepath for regex param searchstring
        return true if found, false if not

        @param contents: list of strings to search through, looking for value
                         searchstring
        @param searchstring: string regex string value to search for in
                             filepath's contents
        @return: found
        @rtype: bool
        @author: Breen Malmberg
        '''

        found = False

        self.logger.log(LogPriority.DEBUG, "Executing searchFileContents()...")

        try:

            if not contents:
                self.logger.log(LogPriority.DEBUG, "Contents parameter " +
                                "provided was blank/empty. Nothing to " +
                                "search. Returning False...")
                return found
            if not searchstring:
                self.logger.log(LogPriority.DEBUG, "Searchstring parameter " +
                                "provided was blank/empty. Nothing to " +
                                "search for. Returning False...")
                return found

            for line in contents:
                if re.search(searchstring, line):
                    found = True

        except Exception:
            raise
        return found

    def getFileContents(self, filepath):
        '''
        retrieve specified file path's contents and return them in list form

        @param filepath: string full path to file to read
        @return: contentlines
        @rtype: list
        @author: Breen Malmberg
        '''

        contentlines = []

        self.logger.log(LogPriority.DEBUG, "Executing getFileContents()...")

        try:

            if not os.path.exists(filepath):
                self.logger.log(LogPriority.DEBUG, "Specified filepath does " +
                                "not exist! Returning empty list...")
                return contentlines

            if os.path.exists(filepath):
                f = open(filepath, 'r')
                contentlines = f.readlines()
                f.close()

        except Exception:
            raise
        return contentlines

    def localization(self):
        '''
        determine which operating system and version of operating system (if
        relevant), and then set all variables, paths, commands, etc. to the
        correct versions for that os type and version.

        @author: Breen Malmberg
        '''

        try:

            self.logger.log(LogPriority.DEBUG, 'Executing localization()...')

            self.logger.log(LogPriority.DEBUG, "Determining OS...")
            # DETERMINE OS
            releasefilelocs = ['/etc/os-release', '/etc/redhat-release']
            self.releasefile = ''
            for loc in releasefilelocs:
                if os.path.exists(loc):
                    self.releasefile = loc
            if not self.releasefile:
                self.logger.log(LogPriority.DEBUG,
                                "Couldn't determine the OS type")
            self.logger.log(LogPriority.DEBUG, "releasefile = " +
                            str(self.releasefile))
            releasecontents = self.getFileContents(self.releasefile)
            osdict = {'Fedora': 'Fedora',
                      'Red Hat.*release 6.*': 'Redhat 6',
                      'Red Hat.*release 7.*': 'Redhat 7',
                      'CentOS': 'CentOS',
                      'openSUSE': 'OpenSuSE',
                      'Debian': 'Debian',
                      'Ubuntu': 'Ubuntu'}
            self.osname = ''
            for item in osdict:
                if self.searchFileContents(releasecontents, item):
                    self.osname = osdict[item]
            if not self.osname:
                self.logger.log(LogPriority.DEBUG, "Couldn't determine " +
                                "the OS type")
            self.logger.log(LogPriority.DEBUG, "osname = " + str(self.osname))

            self.logger.log(LogPriority.DEBUG, "Setting up Audit daemon " +
                            "configuration variables...")
            # AUDIT DAEMON CONFIGURATION SECTION
            auditconflocs = ['/etc/audit/auditd.conf', '/etc/auditd.conf']
            self.auditconffile = ''
            for loc in auditconflocs:
                if os.path.exists(loc):
                    self.auditconffile = loc
            if not self.auditconffile:
                self.logger.log(LogPriority.DEBUG, "Couldn't locate audit " +
                                "configuration file")
            self.auditconftmp = self.auditconffile + '.stonixtmp'
            self.auditconfoptions = {'log_file': '/var/log/audit/audit.log',
                                     'log_format': 'RAW',
                                     'flush': 'data',
                                     'num_logs': '20',
                                     'dispatcher': '/sbin/audispd',
                                     'disp_qos': 'lossy',
                                     'max_log_file': '200',
                                     'max_log_file_action': 'ROTATE',
                                     'space_left': '200',
                                     'space_left_action': 'EMAIL',
                                     'action_mail_acct': 'root',
                                     'admin_space_left': '50',
                                     'admin_space_left_action': 'HALT',
                                     'disk_full_action': 'HALT',
                                     'disk_error_action': 'SINGLE'}
            auditdcmddict = {'Fedora': '/usr/bin/systemctl enable ' +
                             str(self.auditdpkg),
                             'Redhat 6': '/usr/sbin/chkconfig ' +
                             str(self.auditdpkg) + ' on',
                             'Redhat 7': '/usr/bin/systemctl enable ' +
                             str(self.auditdpkg),
                             'CentOS': '/usr/bin/systemctl enable ' +
                             str(self.auditdpkg),
                             'Ubuntu': '/usr/sbin/update-rc.d ' +
                             str(self.auditdpkg) + ' enable',
                             'Debian': '/usr/bin/systemctl enable ' +
                             str(self.auditdpkg),
                             'OpenSuSE': '/usr/bin/systemctl enable ' +
                             str(self.auditdpkg)}
            if self.osname:
                self.auditenablecmd = auditdcmddict[self.osname]
            else:
                self.logger.log(LogPriority.DEBUG, "Unable to set audit " +
                                "enable command, due to osname being " +
                                "unspecified")

            self.logger.log(LogPriority.DEBUG, "Setting up Audit Dispatcher " +
                            "variables...")
            # AUDIT DISPATCHER SECTION
            auditdispconflocs = ['/etc/audisp/audispd.conf']
            self.auditdispconffile = ''
            for loc in auditdispconflocs:
                if os.path.exists(loc):
                    self.auditdispconffile = loc
            if not self.auditdispconffile:
                self.logger.log(LogPriority.DEBUG, "Couldn't locate audit " +
                                "dispatcher configuration file")
            self.audisptmp = self.auditdispconffile + '.stonixtmp'
            self.auditdispconfoptions = {'q_depth': '1024'}

            self.logger.log(LogPriority.DEBUG, "Setting up Audit Rules " +
                            "variables...")
            # AUDIT RULES SECTION
            auditruleslocs = ['/etc/audit/audit.rules',
                              '/etc/audit/rules.d/audit.rules']
            self.auditrulesfile = '/etc/audit/audit.rules'
            if not os.path.exists(self.auditrulesfile):
                for loc in auditruleslocs:
                    if os.path.exists(loc):
                        self.auditrulesfile = loc

            self.logger.log(LogPriority.DEBUG, "Setting up Grub variables...")
            # GRUB SECTION
            grubconflocs = ['/boot/grub/grub.conf', '/etc/default/grub']
            self.grubconffile = ''
            for loc in grubconflocs:
                if os.path.exists(loc):
                    self.grubconffile = loc
            if not self.grubconffile:
                self.logger.log(LogPriority.DEBUG,
                                "Could not locate the grub configuration file")
            else:
                if self.grubconffile == '/boot/grub/grub.conf':
                    self.set_grub_one()
                elif self.grubconffile == '/etc/default/grub':
                    self.set_grub_two()

        except Exception:
            raise

    def set_grub_one(self):
        '''
        set up grub v1 variables and objects

        @author: Breen Malmberg
        '''

        self.logger.log(LogPriority.DEBUG, "Setting Grub v1 variables...")

        self.grubver = 1

    def set_grub_two(self):
        '''
        set up grub v2 variables and objects

        @author: Breen Malmberg
        '''

        self.logger.log(LogPriority.DEBUG, "Setting Grub v2 variables...")
        self.grubver = 2
        self.grubcfgloc = ''
        grubcfglocs = ['/boot/grub/grub.cfg', '/boot/grub2/grub.cfg']
        for loc in grubcfglocs:
            if os.path.exists(loc):
                self.grubcfgloc = loc
        if not self.grubcfgloc:
            self.logger.log(LogPriority.DEBUG,
                            "Could not locate the grub v2 cfg file")
        grubmkconfignames = ['/usr/sbin/grub2-mkconfig',
                             '/usr/sbin/grub-mkconfig']
        for name in grubmkconfignames:
            if os.path.exists(name):
                grubmkconfigname = name
        self.grubupdatecmd = grubmkconfigname + ' -o ' + self.grubcfgloc

    def report(self):
        '''
        run report actions to determine the current system's compliancy status

        @author: Breen Malmberg
        '''

        self.compliant = True
        self.aurulesstatus = True
        self.audispstatus = True
        self.auditdstatus = True
        self.grubstatus = True
        self.auditpkgstatus = False
        self.detailedresults = ""
        suidfiles = []
        arch = ''
        uidstart = ''
        self.auditrulesoptions = {'-w /etc/localtime -p wa -k time-change': True,
                                  '-w /etc/group -p wa -k identity': True,
                                  '-w /etc/passwd -p wa -k identity': True,
                                  '-w /etc/gshadow -p wa -k identity': True,
                                  '-w /etc/shadow -p wa -k identity': True,
                                  '-w /etc/security/opasswd -p wa -k identity': True,
                                  '-w /etc/issue -p wa -k audit_rules_networkconfig_modification': True,
                                  '-w /etc/issue.net -p wa -k audit_rules_networkconfig_modification': True,
                                  '-w /etc/hosts -p wa -k audit_rules_networkconfig_modification': True,
                                  '-w /etc/sysconfig/network -p wa -k audit_rules_networkconfig_modification': True,
                                  '-w /etc/selinux/ -p wa -k MAC-policy': True,
                                  '-w /var/log/faillog -p wa -k logins': True,
                                  '-w /var/log/lastlog -p wa -k logins': True,
                                  '-w /var/run/utmp -p wa -k session': True,
                                  '-w /var/log/btmp -p wa -k session': True,
                                  '-w /var/log/wtmp -p wa -k session': True,
                                  '-w /etc/sudoers -p wa -k actions': True,
                                  '-w /sbin/insmod -p x -k modules': True,
                                  '-w /sbin/rmmod -p x -k modules': True,
                                  '-w /sbin/modprobe -p x -k modules': True,
                                  '-w /etc/localtime -p wa -k audit_time_rules': True,
                                  '-a always,exit -F arch=b32 -S chmod -S lchown -S fsetxattr -S fremovexattr -S fchownat -S fchown -S fchmodat -S fchmod -S chown -S lremovexattr -S lsetxattr -S setxattr -F auid>=1000 -F auid!=4294967295 -k perm_mod': True,
                                  '-a always,exit -F arch=b32 -S creat -S open -S openat -S open_by_handle_at -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access': True,
                                  '-a always,exit -F arch=b32 -S creat -S open -S openat -S open_by_handle_at -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access': True,
                                  '-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k export': True,
                                  '-a always,exit -F arch=b32 -S rmdir -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete': True,
                                  '-a always,exit -F arch=b32 -S init_module -S delete_module -k modules': True,
                                  '-a always,exit -F arch=b32 -S settimeofday -S adjtimex -S clock_settime -k audit_time_rules': True,
                                  '-a always,exit -F arch=b32 -S stime -k audit_time_rules': True,
                                  '-a always,exit -F arch=b32 -S sethostname -S setdomainname -k audit_rules_networkconfig_modification': True,
                                  '-a always,exit -F perm=x -F euid=0 -F auid>=1000 -F auid!=4294967295 -k privileged': True,
                                  '-e 2': True}
        self.cmdhelper = CommandHelper(self.logger)
        self.svchelper = ServiceHelper(self.environ, self.logger)

        try:

            if self.environ.getosfamily() == 'darwin':
                if not self.reportmac():
                    self.compliant = False
                self.formatDetailedResults("report", self.compliant,
                                           self.detailedresults)
                self.logdispatch.log(LogPriority.INFO, self.detailedresults)
                return self.compliant

            outputlines = []

            # get the system's architecture type (32 or 64)
            self.cmdhelper.executeCommand('uname -m')
            outputlines = self.cmdhelper.getOutput()
            errout = self.cmdhelper.getErrorString()
            retcode = self.cmdhelper.getReturnCode()
            if retcode != 0:
                self.detailedresults += '\nCould not determine this system\'s architecture (32/64).'
                self.logger.log(LogPriority.DEBUG, errout)
            if outputlines:
                for line in outputlines:
                    if re.search('x86\_64', line):
                        arch = '64'

            if not arch:
                arch = '32'

            outputlines = []

            # get list of setuid/setgid files on the system
            self.cmdhelper.executeCommand('find / -xdev -type f -perm -4000 -o -type f -perm -2000')
            outputlines = self.cmdhelper.getOutput()
            errout = self.cmdhelper.getErrorString()
            retcode = self.cmdhelper.getReturnCode()
            if retcode != 0:
                self.detailedresults += '\nThere was an error running the find command to get the list of setuid/setgid files.'
                self.logger.log(LogPriority.DEBUG, errout)
            if outputlines:
                for line in outputlines:
                    if re.search('^/', line):
                        suidfiles.append(line.strip())
            else:
                self.logger.log(LogPriority.DEBUG, "no setuid or setgid files were found in root (/)")

            # add privileged access rule for all existing setuid/setgid files on the system
            if suidfiles:
                self.logger.log(LogPriority.DEBUG, "Found setuid/setgid files on the system; Adding audit rules for them...")
                for sf in suidfiles:
                    self.auditrulesoptions['-a always,exit -F path=' + str(sf) + ' -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged'] = True
                self.logger.log(LogPriority.DEBUG, "Finished adding audit rules for setuid/setgid files.")
            else:
                self.logger.log(LogPriority.DEBUG, "no setuid or setgid files were found, to add to audit rules")

            # add 64bit copies of rules, if the system is 64 bit
            if arch == '64':
                newaurulesoptsdict = {}
                self.logger.log(LogPriority.DEBUG, "System is 64 bit architecture; Adding 64 bit rules to list...")
                for item in self.auditrulesoptions:
                    if re.search('arch=b32', item):
                        # the syscall stime only has a 32bit component
                        # so we can't change the arch for it to 64bit -
                        # even on 64 bit systems!
                        if not re.search('stime', item):
                            newitem = item.replace('arch=b32', 'arch=b64')
                            newaurulesoptsdict[newitem] = True
                if newaurulesoptsdict:
                    for item in newaurulesoptsdict:
                        self.auditrulesoptions[item] = True
            self.logger.log(LogPriority.DEBUG, "Finished adding 64 bit rules to list.")

            # if the system starts issuing user id's at 500 instead of the newer 1000
            # then change all auid>=1000 entries, in auditrulesoptions dict, to auid>=500
            # first find whether the system starts issuing uid's at 500 or 1000
            if os.path.exists('/etc/login.defs'):
                f = open('/etc/login.defs')
                contentlines = f.readlines()
                f.close()
                for line in contentlines:
                    if re.search('^UID\_MIN\s+500', line):
                        uidstart = '500'
                    if re.search('^UID\_MIN\s+1000', line):
                        uidstart = '1000'
            else:
                self.logger.log(LogPriority.DEBUG, "Could not locate login.defs file. Cannot determine uid start number.")

            # if this system starts uid's for users at 500, then replace all instances of auid>=1000
            if uidstart == '500':
                for item in self.auditrulesoptions:
                    if re.search('auid>=1000', item):
                        newitem = item.replace('auid>=1000', 'auid>=500')
                        self.auditrulesoptions[newitem] = self.auditrulesoptions.pop(item)

            self.pkghelper = Pkghelper(self.logger, self.environ)
            self.auditpkgs = ['auditd', 'audit']

            # check if the auditing package is installed
            for pkg in self.auditpkgs:
                if self.pkghelper.check(pkg):
                    self.auditpkgstatus = True
                    self.auditdpkg = pkg

            # if we have no audit installation to report on, we cannot continue
            if not self.auditpkgstatus:
                self.compliant = False
                self.detailedresults += '\nKernel auditing package is not ' + \
                    'installed'
                self.formatDetailedResults("report", self.compliant,
                                           self.detailedresults)
                self.logdispatch.log(LogPriority.INFO, self.detailedresults)
                return self.compliant

            self.localization()

            self.auditdeditor = KVEditorStonix(self.statechglogger,
                                               self.logger, "conf",
                                               self.auditconffile,
                                               self.auditconftmp,
                                               self.auditconfoptions,
                                               "present", "openeq")
            self.audispeditor = KVEditorStonix(self.statechglogger,
                                               self.logger, "conf",
                                               self.auditdispconffile,
                                               self.audisptmp,
                                               self.auditdispconfoptions,
                                               "present", "openeq")

            if not self.reportAuditRules():
                self.compliant = False
                self.aurulesstatus = False

            if not self.audispeditor.report():
                self.compliant = False
                self.detailedresults += '\nThe following required options ' + \
                    'are missing (or incorrect) from ' + \
                    str(self.auditdispconffile) + ':\n' + \
                    '\n'.join(str(f) for f in self.audispeditor.fixables) + '\n'
                self.audispstatus = False

            if not self.auditdeditor.report():
                self.compliant = False
                self.detailedresults += '\nThe following required options ' + \
                    'are missing (or incorrect) from ' + \
                    str(self.auditconffile) + ':\n' + \
                    '\n'.join(str(f) for f in self.auditdeditor.fixables) + '\n'
                self.auditdstatus = False

            if self.grubver == 1:
                if not self.report_grub_one():
                    self.detailedresults += '\nThe required audit=1 ' + \
                        'configuration option was missing from the grub ' + \
                        'conf file\n'
                    self.compliant = False
                    self.grubstatus = False
            elif self.grubver == 2:
                if not self.report_grub_two():
                    self.detailedresults += '\nThe required audit=1 ' + \
                        'configuration option was missing from the grub ' + \
                        'conf file\n'
                    self.compliant = False
                    self.grubstatus = False

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

    def reportmac(self):
        '''
        run report actions for Mac OS X systems

        @return: retval
        @rtype: bool
        @author: Breen Malmberg
        '''

        retval = True

        self.logger.log(LogPriority.DEBUG, "Executing reportmac()...")

        try:

            self.audituserfile = '/etc/security/audit_user'
            self.auditcontrolfile = '/etc/security/audit_control'

            if not os.path.exists(self.auditcontrolfile):
                retval = False
                self.detailedresults += '\nCould not find audit_control file'
                return retval
            if not os.path.exists(self.audituserfile):
                retval = False
                self.detailedresults += '\nCould not find audit_user file'
                return retval

            # audit_control section
            contentlines = self.getFileContents(self.auditcontrolfile)
            self.controlopts = {'dir:/var/audit': True,
                                'flags:lo,aa': True,
                                'minfree:20': True,
                                'naflags:lo,aa': True,
                                'policy:ahlt': True,
                                'filesz:2M': True,
                                'expire-after:10M': True,
                                'superuser-set-sflags-mask:has_' +
                                'authenticated,has_console_access': True,
                                'superuser-clear-sflags-mask:has_' +
                                'authenticated,has_console_access': True,
                                'member-set-sflags-mask:': True,
                                'member-clear-sflags-mask:has_authenticated':
                                True}
            for opt in self.controlopts:
                if not self.searchFileContents(contentlines, opt):
                    retval = False
                    self.controlopts[opt] = False
                    self.detailedresults += '\nRequired config option ' + \
                        'missing: ' + str(opt)

            # audit_user section
            self.useropts = {'root:lo:no': True}
            contentlines = self.getFileContents(self.audituserfile)
            for opt in self.useropts:
                if not self.searchFileContents(contentlines, opt):
                    retval = False
                    self.useropts[opt] = False
                    self.detailedresults += '\nRequired config option ' + \
                        'missing: ' + str(opt)

        except Exception:
            raise
        return retval

    def report_grub_one(self):
        '''
        run report actions for grub version 1

        @return: retval
        @rtype: bool
        @author: Breen Malmberg
        '''

        retval = False

        try:

            contentlines = self.getFileContents(self.grubconffile)
            for line in contentlines:
                if re.search('kernel\s+.*audit=1', line):
                    retval = True

        except Exception:
            raise
        return retval

    def report_grub_two(self):
        '''
        run report actions for grub version 2

        @return: retval
        @rtype: bool
        @author: Breen Malmberg
        '''

        retval = False

        try:

            contentlines = self.getFileContents(self.grubconffile)
            for line in contentlines:
                if re.search('^GRUB_CMDLINE_LINUX_DEFAULT=\".*audit=1.*\"',
                             line):
                    retval = True
        except Exception:
            raise
        return retval

    def reportAuditRules(self):
        '''
        private method to report status on the audit rules configuration

        @return: retval
        @rtype: bool
        @author: Breen Malmberg
        '''

        retval = True

        self.logger.log(LogPriority.DEBUG, "Executing reportAuditRules()...")

        try:

            if not self.auditrulesfile:
                self.detailedresults += '\nKernel Auditing is not installed'
                retval = False
                return retval

            if not os.path.exists(self.auditrulesfile):
                self.detailedresults += '\nKernel Auditing is not installed'
                retval = False
                return retval

            contentlines = self.getFileContents(self.auditrulesfile)
            for item in self.auditrulesoptions:
                if not self.searchFileContents(contentlines, item):
                    retval = False
                    self.auditrulesoptions[item] = False
                    self.detailedresults += '\nRequired configuration ' + \
                        'option: "' + str(item) + '\" was not found in ' + \
                        str(self.auditrulesfile) + '\n'

        except Exception:
            raise
        return retval

    def fix(self):
        '''
        run general fix actions, and call fix sub-methods based on system-type
        decision logic

        @author: Breen Malmberg
        '''

        fixsuccess = True
        self.detailedresults = ""
        self.iditerator = 0

        try:

            if self.ci.getcurrvalue():

                if self.environ.getosfamily() == 'darwin':
                    if not self.fixmac():
                        fixsuccess = False
                    self.formatDetailedResults("fix", fixsuccess,
                                               self.detailedresults)
                    self.logdispatch.log(LogPriority.INFO,
                                         self.detailedresults)
                    return fixsuccess

                if not self.auditpkgstatus:
                    for pkg in self.auditpkgs:
                        if self.pkghelper.install(pkg):
                            self.auditpkgstatus = True
                            self.auditdpkg = pkg
                            self.report()
                # if we have no installation upon which to act, we cannot continue
                if not self.auditpkgstatus:
                    fixsuccess = False
                    self.detailedresults += '\nFailed to install audit package on this system. ' + \
                    'Please check your package manager configuration and connection and try again.'
                    self.formatDetailedResults("fix", fixsuccess, self.detailedresults)
                    self.logdispatch.log(LogPriority.INFO, self.detailedresults)
                    return fixsuccess

                if not self.fixAuditRules():
                    fixsuccess = False

                if self.audispeditor.fixables:
                    if not self.audispeditor.fix():
                        fixsuccess = False
                        self.detailedresults += '\nAudit dispatcher editor ' + \
                            'fix failed'
                    else:
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        self.auditdeditor.setEventID(myid)
                    if not self.audispeditor.commit():
                        fixsuccess = False
                        self.detailedresults += '\nAudit dispatcher editor ' + \
                            'commit failed'
                else:
                    self.logger.log(LogPriority.DEBUG, "Nothing to fix for audit dispatcher")

                if self.auditdeditor.fixables:
                    if not self.auditdeditor.fix():
                        fixsuccess = False
                        self.detailedresults += '\nAudit daemon editor fix failed'
                    else:
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        self.auditdeditor.setEventID(myid)
                    if not self.auditdeditor.commit():
                        fixsuccess = False
                        self.detailedresults += '\nAudit daemon editor ' + \
                            'commit failed'
                else:
                    self.logger.log(LogPriority.DEBUG, "Nothing to fix for audit daemon")

                if not self.grubstatus:
                    if self.grubver == 1:
                        if not self.fix_grub_one():
                            fixsuccess = False
                    if self.grubver == 2:
                        if not self.fix_grub_two():
                            fixsuccess = False

                # start/restart the audit service so it reads the new config
                self.logger.log(LogPriority.DEBUG, "Checking 'auditd' service status...")
                if self.svchelper.isRunning('auditd', _="_"):
                    self.logger.log(LogPriority.DEBUG, "auditd service was running. Restarting the auditd service...")
                    self.svchelper.reloadService('auditd', _="_")
                else:
                    self.logger.log(LogPriority.DEBUG, "auditd service was not running. Attempting to start the auditd service...")
                    self.svchelper.enableService('auditd', _="_")

            else:
                self.detailedresults += '\nRule was not enabled. Nothing was done...'
                self.logger.log(LogPriority.DEBUG, self.detailedresults)

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            fixsuccess = False
            self.detailedresults += traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", fixsuccess, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return fixsuccess

    def fixAuditRules(self):
        '''
        private method to fix audit rules configuration
        kveditor will not work for this rule because the keys used in
        the dictionary have spaces

        @return: retval
        @rtype: bool
        @author: Breen Malmberg
        '''

        self.logger.log(LogPriority.DEBUG, "Executing fixAuditRules()...")

        retval = True

        try:

            if not self.auditrulesfile:
                self.detailedresults += '\nAudit rules configuration file ' + \
                    'path undefined. Returning False...'
                retval = False
                return retval

        except AttributeError:
            self.detailedresults += '\nAudit rules configuration file ' + \
                'path undefined. Returning False...'
            retval = False
            return retval

        try:

            if os.path.exists(self.auditrulesfile):
                self.logger.log(LogPriority.DEBUG,
                                str(self.auditrulesfile) + " path exists")

                f = open(self.auditrulesfile, 'r')
                contentlines = f.readlines()
                f.close()

                aurulestmp = self.auditrulesfile + '.stonixtmp'

                # find -e 2 line if it already exists, remove it
                # and move it to the end of the file
                for line in contentlines:
                    if re.search('-e 2', line):
                        contentlines.remove(line)

                for item in self.auditrulesoptions:
                    if not self.auditrulesoptions[item]:
                        if not re.search('-e 2', item):
                            contentlines.append(item + '\n')

                contentlines.append('-e 2\n')

                self.logger.log(LogPriority.DEBUG,
                                "Writing contentlines to " +
                                str(self.auditrulesfile))
                f = open(aurulestmp, 'w')
                f.writelines(contentlines)
                f.close()

                os.rename(aurulestmp, self.auditrulesfile)
                os.chown(self.auditrulesfile, 0, 0)
                os.chmod(self.auditrulesfile, 0640)
                resetsecon(self.auditrulesfile)

            else:

                self.logger.log(LogPriority.DEBUG,
                                str(self.auditrulesfile) +
                                " path does not exist")
                contentlines = []
                for item in self.auditrulesoptions:
                    if not re.search('-e 2', item):
                        contentlines.append(item + '\n')

                contentlines.append('-e 2\n')

                self.logger.log(LogPriority.DEBUG,
                                "Creating " + str(self.auditrulesfile) +
                                " and writing to it...")
                f = open(self.auditrulesfile, 'w')
                f.writelines(contentlines)
                f.close()

                os.chown(self.auditrulesfile, 0, 0)
                os.chmod(self.auditrulesfile, 0640)
                resetsecon(self.auditrulesfile)

        except Exception:
            raise
        return retval

    def fixmac(self):
        '''
        run fix actions for Mac OS X systems

        @return: retval
        @rtype: bool
        @author: Breen Malmberg
        '''

        retval = True
        contentlines = []

        self.logger.log(LogPriority.DEBUG, "Executing fixmac()...")

        try:

            # audit_control section
            self.logger.log(LogPriority.DEBUG, "Fixing audit_control...")
            if not os.path.exists(self.auditcontrolfile):
                f = open(self.auditcontrolfile, 'w')
                contentlines.append('# This file created by STONIX\n')
                for opt in self.controlopts:
                    contentlines.append(opt + '\n')
                f.writelines(contentlines)
                f.close()
                os.chmod(self.auditcontrolfile, 0400)
                os.chown(self.auditcontrolfile, 0, 0)

                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                event = {'eventtype': 'creation',
                         'filepath': self.auditcontrolfile}

                self.statechglogger.recordchgevent(myid, event)
            else:
                contentlines = self.getFileContents(self.auditcontrolfile)
                tmpauditcontrolfile = self.auditcontrolfile + '.stonixtmp'
                for opt in self.controlopts:
                    optsplit = opt.split(':')
                    for line in contentlines:
                        if re.search('^' + str(optsplit[0]), line):
                            contentlines = [c.replace(line, opt + '\n')
                                            for c in contentlines]
                            self.controlopts[opt] = True
                for opt in self.controlopts:
                    if not self.controlopts[opt]:
                        contentlines.append(opt + '\n')
                tf = open(tmpauditcontrolfile, 'w')
                tf.writelines(contentlines)
                tf.close()

                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                event = {'eventtype': 'conf',
                         'filepath': self.auditcontrolfile}

                self.statechglogger.recordfilechange(self.auditcontrolfile,
                                                     tmpauditcontrolfile, myid)
                self.statechglogger.recordchgevent(myid, event)

                os.rename(tmpauditcontrolfile, self.auditcontrolfile)
                os.chmod(self.auditcontrolfile, 0400)
                os.chown(self.auditcontrolfile, 0, 0)

            # audit_user section
            self.logger.log(LogPriority.DEBUG, "Fixing audit_user...")
            if not os.path.exists(self.audituserfile):
                f = open(self.audituserfile, 'w')
                contentlines.append('# This file created by STONIX\n')
                for opt in self.useropts:
                    contentlines.append(opt + '\n')
                f.writelines(contentlines)
                f.close()
                os.chmod(self.audituserfile, 0400)
                os.chown(self.audituserfile, 0, 0)

                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                event = {'eventtype': 'creation',
                         'filepath': self.audituserfile}

                self.statechglogger.recordchgevent(myid, event)
            else:
                contentlines = self.getFileContents(self.audituserfile)
                tmpaudituserfile = self.audituserfile + '.stonixtmp'
                for opt in self.useropts:
                    optsplit = opt.split(':')
                    for line in contentlines:
                        if re.search('^' + str(optsplit[0]), line):
                            contentlines = [c.replace(line, opt + '\n')
                                            for c in contentlines]
                            self.useropts[opt] = True
                for opt in self.useropts:
                    if not self.useropts[opt]:
                        contentlines.append(opt + '\n')
                tf = open(tmpaudituserfile, 'w')
                tf.writelines(contentlines)
                tf.close()

                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                event = {'eventtype': 'conf',
                         'filepath': self.audituserfile}

                self.statechglogger.recordfilechange(self.audituserfile,
                                                     tmpaudituserfile, myid)
                self.statechglogger.recordchgevent(myid, event)

                os.rename(tmpaudituserfile, self.audituserfile)
                os.chmod(self.auditcontrolfile, 0400)
                os.chown(self.auditcontrolfile, 0, 0)

                auditinitcmd = '/usr/sbin/audit -i'
                self.logger.log(LogPriority.DEBUG, "Executing command: " +
                                str(auditinitcmd) + ' ...')
                self.cmdhelper.executeCommand(auditinitcmd)
                errout = self.cmdhelper.getErrorString()
                retcode = self.cmdhelper.getReturnCode()
                if retcode != 0:
                    retval = False
                    self.detailedresults += '\nUnable to successfully complete command: ' + str(auditinitcmd)
                    self.logger.log(LogPriority.DEBUG, errout)

        except Exception:
            raise
        return retval

    def fix_grub_one(self):
        '''
        run fix actions for grub version one

        @author: Breen Malmberg
        '''

        retval = True
        replaced = False

        try:

            if not self.grubconffile:
                retval = False
                self.detailedresults += '\nUnable to locate grub conf file'
                return retval

            tmpgrubconf = self.grubconffile + '.stonixtmp'

            contentlines = self.getFileContents(self.grubconffile)

            if not contentlines:
                retval = False
                self.detailedresults += '\nUnable to get contents from ' + \
                    'grub conf file'
                return retval

            for line in contentlines:
                if re.search('kernel\s+.*', line):
                    if not re.search('audit=1', line):
                        contentlines = [c.replace(line, line.rstrip() + ' audit=1\n') for c in contentlines]
                        replaced = True

            if replaced:
                tf = open(tmpgrubconf, 'w')
                tf.writelines(contentlines)
                tf.close()

                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                event = {'eventtype': 'conf',
                         'filepath': self.grubconffile}
                self.statechglogger.recordchgevent(myid, event)
                self.statechglogger.recordfilechange(self.grubconffile,
                                                     tmpgrubconf, myid)

                os.rename(tmpgrubconf, self.grubconffile)
                os.chown(self.grubconffile, 0, 0)
                os.chmod(self.grubconffile, 0644)
                resetsecon(self.grubconffile)

        except Exception:
            raise
        return retval

    def fix_grub_two(self):
        '''
        run fix actions for grub version two

        @author: Breen Malmberg
        '''

        retval = True
        replaced = False
        appended = False

        try:

            if not self.grubconffile:
                retval = False
                self.detailedresults += '\nUnable to locate grub conf file'
                return retval

            tmpgrubconf = self.grubconffile + '.stonixtmp'

            contentlines = self.getFileContents(self.grubconffile)

            if not contentlines:
                retval = False
                self.detailedresults += '\nUnable to get contents from ' + \
                    'grub conf file'
                return retval

            for line in contentlines:
                if re.search('^GRUB_CMDLINE_LINUX_DEFAULT=\".*\"', line):
                    if re.search('audit=1', line):
                        continue
                    else:
                        self.logger.log(LogPriority.DEBUG,
                                        "Grub configuration line found, " +
                                        "but without audit=1 option. " +
                                        "Adding audit=1 to line...")
                        contentlines = [c.replace(line, line.strip()[:-1] +
                                                  ' audit=1"\n')
                                        for c in contentlines]
                        replaced = True

            if not replaced:
                self.logger.log(LogPriority.DEBUG,
                                "Grub audit configuration line not found in " +
                                "grub conf file. Appending it to grub conf " +
                                "file...")
                contentlines.append('GRUB_CMDLINE_LINUX_DEFAULT="quiet ' +
                                    'splash audit=1"\n')
                appended = True

            if replaced or appended:

                self.logger.log(LogPriority.DEBUG, "The grub conf file " +
                                "contents have been edited. Saving those " +
                                "changes to the file now...")
                tf = open(tmpgrubconf, 'w')
                tf.writelines(contentlines)
                tf.close()

                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                event = {'eventtype': 'conf',
                         'filepath': self.grubconffile}
                self.statechglogger.recordchgevent(myid, event)
                self.statechglogger.recordfilechange(self.grubconffile,
                                                     tmpgrubconf, myid)

                os.rename(tmpgrubconf, self.grubconffile)
                os.chown(self.grubconffile, 0, 0)
                os.chmod(self.grubconffile, 0644)
                resetsecon(self.grubconffile)

                if not self.grubupdatecmd:
                    retval = False
                    self.detailedresults += '\ngrub update command was ' + \
                        'not correctly set and could not be run'
                    return retval

                self.logger.log(LogPriority.DEBUG, "Executing grub update " +
                                "command, to update the grub.cfg file...")
                self.cmdhelper.executeCommand(self.grubupdatecmd)
                errout = self.cmdhelper.getErrorString()
                retcode = self.cmdhelper.getReturnCode()
                if retcode != 0:
                    retval = False
                    self.detailedresults += '\nThere was an error running the grub update command.'
                    self.logger.log(LogPriority.DEBUG, errout)

        except Exception:
            raise
        return retval
