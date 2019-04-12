###############################################################################
#                                                                             #
# Copyright 2015-2018.  Los Alamos National Security, LLC. This material was  #
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
@change: 2017/11/13 ekkehard - make eligible for OS X El Capitan 10.11+
@change: 2018/06/08 ekkehard - make eligible for macOS Mojave 10.14
@change: 2019/03/12 ekkehard - make eligible for macOS Sierra 10.12+
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
                           'os': {'Mac OS X': ['10.12', 'r', '10.14.10']}}
        # init CIs
        datatype = 'bool'
        key = 'ENABLEKERNELAUDITING'
        instructions = """To prevent kernel auditing from being enabled on \
this system, set the value of EnableKernelAuditing to False"""
        default = True
        self.ci = self.initCi(datatype, key, instructions, default)

        freq_instructions = 'This value represents the number of auditable events which can occur before they are written to disk. A smaller number will mean more frequent writes, which can affect performance on some machines. Acceptable values are between 1 to 100.'
        freq_default = 20
        self.freqci = self.initCi('int', 'AUDITFLUSHFREQUENCY', freq_instructions, freq_default)
        self.flushfrequency = str(self.freqci.getcurrvalue())

        allowable_flush_types = ['data', 'incremental', 'sync', 'incremental_async']

        flushtype_instructions = 'This value represents the mode that the audit daemon will use when handling writing audit events to disk. Acceptable values are: data, incremental, or sync. "data" will ensure that every time an auditable event occurs it is written to disk. "incremental" will wait until a specified number of events occur until they are all written at once. "sync" means that both data and meta-data will be written to disk every time an auditable event occurs. The most performance-intensive option is "sync" while the least perfomance-intensive option is "incremental".'
        flushtype_default = "incremental_async"

        self.flushtypeci = self.initCi('string', 'AUDITFLUSHTYPE', flushtype_instructions, flushtype_default)
        if self.flushtypeci.getcurrvalue() not in allowable_flush_types:
            self.flushtypeci.updatecurrvalue('incremental_async')
        self.flushtype = str(self.flushtypeci.getcurrvalue())

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

        try:

            if not contents:
                return found

            if not searchstring:
                return found

            for line in contents:
                if re.search(searchstring, line, re.IGNORECASE):
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

        try:

            if not os.path.exists(filepath):
                self.logger.log(LogPriority.DEBUG, "Specified filepath does not exist! Returning empty list...")
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

            self.logger.log(LogPriority.DEBUG, 'Starting localization()...')

# DETERMINE OS DISTRIBUTION
            self.logger.log(LogPriority.DEBUG, "Determining OS distribution/type...")
            # for now, common will refer to: fedora, rhel, centos, ubuntu
            self.osname = 'common'
            relfile = '/etc/os-release'
            relfiles = ['/etc/os-release', '/etc/redhat-release']
            if not os.path.exists(relfile):
                for rf in relfiles:
                    if os.path.exists(rf):
                        relfile = rf
            if relfile:
                if os.path.exists(relfile):
                    f = open(relfile, 'r')
                    contentlines = f.readlines()
                    f.close()
                    if contentlines:
                        for line in contentlines:
                            if re.search('debian', line, re.IGNORECASE):
                                self.osname = 'debian'
                            elif re.search('opensuse', line, re.IGNORECASE):
                                self.osname = 'opensuse'
            else:
                self.logger.log(LogPriority.DEBUG, "Could not determine OS distro")

# SET AUDITD RESTART COMMAND
            if self.osname == 'common':
                self.auditrestart = 'service auditd restart'
            elif self.osname == 'debian':
                self.auditrestart = '/etc/init.d/auditd restart'
            elif self.osname == 'opensuse':
                self.auditrestart = 'systemctl restart auditd'

# SET AUDITD PACKAGES
            self.auditpkgs = ['auditd', 'audit']

# AUDIT DAEMON CONFIGURATION SECTION
            self.logger.log(LogPriority.DEBUG, "Setting up Audit Daemon variables...")
            auditconflocs = ['/etc/audit/auditd.conf', '/etc/auditd.conf']
            self.auditconffile = ''
            for loc in auditconflocs:
                if os.path.exists(loc):
                    self.auditconffile = loc
            if not self.auditconffile:
                self.logger.log(LogPriority.DEBUG, "Couldn't locate audit configuration file")
            self.auditconftmp = self.auditconffile + '.stonixtmp'

            self.auditconfoptions = {'log_file': '/var/log/audit/audit.log',
                                     'log_format': 'RAW',
                                     'flush': str(self.flushtype),
                                     'freq': str(self.flushfrequency),
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

            self.flushfrequency = str(self.freqci.getcurrvalue())
            allowable_flush_types = ['data', 'incremental', 'sync']
            allowable_freq_range = range(1,100)
            if self.flushtypeci.getcurrvalue() not in allowable_flush_types:
                self.flushtypeci.updatecurrvalue('incremental')
                self.logger.log(LogPriority.DEBUG, "User entered value for flush type was not one of the acceptable types. Changed to default incremental.")
            self.flushtype = self.flushtypeci.getcurrvalue()
            if int(self.flushfrequency) not in allowable_freq_range:
                self.flushfrequency = '20'
                self.logger.log(LogPriority.DEBUG, "User entered value for flush frequency was not within acceptable range. Changed to default 20.")

# AUDIT DISPATCHER SECTION
            self.logger.log(LogPriority.DEBUG, "Setting up Audit Dispatcher variables...")
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

# AUDIT RULES SECTION
            self.logger.log(LogPriority.DEBUG, "Setting up Audit Rules variables...")
            self.auditrulesfiles = []
            self.auditrulesbasedir = '/etc/audit/rules.d/'
            if os.path.exists(self.auditrulesbasedir):
                self.auditrulesfile = self.auditrulesbasedir + 'audit.rules'
                self.auditrulesfiles = [f for f in os.listdir(self.auditrulesbasedir) if os.path.isfile(os.path.join(self.auditrulesbasedir, f))]
            else:
                self.auditrulesfile = '/etc/audit/audit.rules'

# GRUB SECTION
            self.logger.log(LogPriority.DEBUG, "Setting up Grub variables...")
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
        self.cmdhelper = CommandHelper(self.logger)
        self.svchelper = ServiceHelper(self.environ, self.logger)
        self.pkghelper = Pkghelper(self.logger, self.environ)

        try:

            self.arch = ''
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
                        self.arch = '64'
    
            if not self.arch:
                self.arch = '32'
            uidstart = ''
            self.auditrulesoptions = {'-w /etc/selinux/ -p wa -k MAC-policy': True,
                                      '-w /etc/sudoers -p wa -k actions': True,
                                      '-w /etc/localtime -p wa -k time-change': True,
                                      '-w /etc/group -p wa -k identity': True,
                                      '-w /etc/passwd -p wa -k identity': True,
                                      '-w /etc/gshadow -p wa -k identity': True,
                                      '-w /etc/shadow -p wa -k identity': True,
                                      '-w /etc/security/opasswd -p wa -k identity': True,
                                      '-w /etc/issue -p wa -k audit_rules_networkconfig_modification': True,
                                      '-w /etc/issue.net -p wa -k audit_rules_networkconfig_modification': True,
                                      '-w /etc/hosts -p wa -k audit_rules_networkconfig_modification': True,
                                      '-w /etc/sysconfig/network -p wa -k audit_rules_networkconfig_modification': True,
                                      '-w /etc/localtime -p wa -k audit_time_rules': True,
                                      '-w /var/log/faillog -p wa -k logins': True,
                                      '-w /var/log/lastlog -p wa -k logins': True,
                                      '-w /var/run/utmp -p wa -k session': True,
                                      '-w /var/log/btmp -p wa -k session': True,
                                      '-w /var/log/wtmp -p wa -k session': True,
                                      '-w /sbin/insmod -p x -k modules': True,
                                      '-w /sbin/rmmod -p x -k modules': True,
                                      '-w /sbin/modprobe -p x -k modules': True,
                                      '-a always,exit -F arch=b' + str(self.arch) + ' -S chmod -S lchown -S fsetxattr -S fremovexattr -S fchownat -S fchown -S fchmodat -S fchmod -S chown -S lremovexattr -S lsetxattr -S setxattr -F auid>=1000 -F auid!=4294967295 -k perm_mod': True,
                                      '-a always,exit -F arch=b' + str(self.arch) + ' -S creat -S open -S openat -S open_by_handle_at -S truncate -S ftruncate -F exit=-EACCES -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access': True,
                                      '-a always,exit -F arch=b' + str(self.arch) + ' -S mount -F auid>=1000 -F auid!=4294967295 -k export': True,
                                      '-a always,exit -F arch=b' + str(self.arch) + ' -S rmdir -F auid>=1000 -F auid!=4294967295 -k delete': True,
                                      # the following rule commented out due to the massive log spam it creates (system-killer)
                                      # this is due primarily to cache and temp files management by java, browsers, and other applications as well
                                      # '-a always,exit -F ' + str(self.arch) + ' -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete': True,
                                      '-a always,exit -F arch=b' + str(self.arch) + ' -S init_module -S delete_module -k modules': True,
                                      '-a always,exit -F arch=b' + str(self.arch) + ' -S settimeofday -S adjtimex -S clock_settime -k audit_time_rules': True,
                                      '-a always,exit -F arch=b32 -S stime -k audit_time_rules': True,
                                      '-a always,exit -F arch=b' + str(self.arch) + ' -S sethostname -S setdomainname -k audit_rules_networkconfig_modification': True,
                                      '-a always,exit -F perm=x -F euid=0 -F auid>=1000 -F auid!=4294967295 -k privileged': True}

            if self.environ.getosfamily() == 'darwin':
                self.localization()
                if not self.reportmac():
                    self.compliant = False
                self.formatDetailedResults("report", self.compliant,
                                           self.detailedresults)
                self.logdispatch.log(LogPriority.INFO, self.detailedresults)
                return self.compliant

            outputlines = []

            # GET LIST OF SETUID & SETGID FILES ON SYSTEM
            self.logger.log(LogPriority.DEBUG, "Getting list of setuid and setgid files on this system...")
            self.cmdhelper.executeCommand('find / -xdev -type f -perm -4000 -o -type f -perm -2000')
            outputlines = self.cmdhelper.getOutput()
            errout = self.cmdhelper.getErrorString()
            retcode = self.cmdhelper.getReturnCode()
            if retcode != 0:
                self.detailedresults += "\nCommand to get setuid and setgid files failed with error code: " + str(retcode)
                self.logger.log(LogPriority.DEBUG, errout)
            if outputlines:
                for line in outputlines:
                    if re.search('^/', line):
                        suidfiles.append(line.strip())

            # ADD PRIVILEGED ACCESS RULES FOR ALL SETUID/SETGID FILES FOUND ON THIS SYSTEM
            if suidfiles:
                self.logger.log(LogPriority.DEBUG, "Found setuid/setgid files on the system; Adding audit rules for them...")
                for sf in suidfiles:
                    self.auditrulesoptions['-a always,exit -S all -F path=' + str(sf) + ' -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged'] = True
                self.logger.log(LogPriority.DEBUG, "Finished adding audit rules for setuid/setgid files")
            else:
                self.logger.log(LogPriority.DEBUG, "No setuid or setgid files were found in root (/)")

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

            self.localization()

            # check if the auditing package is installed
            for pkg in self.auditpkgs:
                if self.pkghelper.check(pkg):
                    self.auditpkgstatus = True

            # if we have no audit installation to report on, we cannot continue
            if not self.auditpkgstatus:
                self.compliant = False
                self.detailedresults += '\nKernel auditing package is not installed'
                self.formatDetailedResults("report", self.compliant, self.detailedresults)
                self.logdispatch.log(LogPriority.INFO, self.detailedresults)
                return self.compliant

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
        run report actions for Mac OS systems

        @return: retval
        @rtype: bool
        @author: Breen Malmberg
        '''

        retval = True

        self.logger.log(LogPriority.DEBUG, "Executing reportmac()...")

        try:

            self.audituserfile = '/etc/security/audit_user'
            self.auditcontrolfile = '/etc/security/audit_control'
            self.accontrolopts = {'dir:/var/audit': True,
                                'flags:lo,aa': True,
                                'minfree:20': True,
                                'naflags:lo,aa': True,
                                'policy:ahlt': True,
                                'filesz:2M': True,
                                'expire-after:300d': True,
                                'superuser-set-sflags-mask:has_authenticated,has_console_access': True,
                                'superuser-clear-sflags-mask:has_authenticated,has_console_access': True,
                                'member-set-sflags-mask:': True,
                                'member-clear-sflags-mask:has_authenticated': True}
            self.useropts = {'root:lo,ad:no': True}
            self.auditinitcmd = ''
            if os.path.exists('/usr/sbin/audit'):
                self.auditinitcmd = '/usr/sbin/audit -i'

            if not os.path.exists(self.auditcontrolfile):
                retval = False
                self.detailedresults += '\nCould not find audit_control file'
                return retval
            if not os.path.exists(self.audituserfile):
                retval = False
                self.detailedresults += '\nCould not find audit_user file'
                return retval

            # audit_control section
            accontentlines = self.getFileContents(self.auditcontrolfile)
            missingacopts = []
            for opt in self.accontrolopts:
                if not self.searchFileContents(accontentlines, opt):
                    retval = False
                    self.accontrolopts[opt] = False
                    missingacopts.append(opt)
            if missingacopts:
                self.detailedresults += "\nFollowing required audit_control options missing:\n" + "\n".join(missingacopts)

            # audit_user section
            missingauopts = []
            aucontentlines = self.getFileContents(self.audituserfile)
            for opt in self.useropts:
                if not self.searchFileContents(aucontentlines, opt):
                    retval = False
                    self.useropts[opt] = False
                    missingauopts.append(opt)
            if missingauopts:
                self.detailedresults += "\nFollowing required audit_user options missing:\n" + "\n".join(missingauopts)

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

            if self.auditrulesfiles:
                if not self.reportAURulesParts():
                    retval = False

            else:
                if not self.reportAURulesSingle():
                    retval = False

            # check to see if all of the audit rules are loaded (running)
#             command = '/usr/sbin/auditctl -l'
#             self.cmdhelper.executeCommand(command)
#             outlines = self.cmdhelper.getOutput()
#             retcode = self.cmdhelper.getReturnCode()
#             if retcode != 0:
#                 retval = False
#                 errmsg = self.cmdhelper.getErrorString()
#                 self.logger.log(LogPriority.DEBUG, "Command auditctl -l failed, with return code: " + str(retcode))
#                 self.logger.log(LogPriority.DEBUG, errmsg)
#             elif outlines:
#                 outlines = map(str.strip, outlines)
#                 notloaded = []
#                 checkdict = self.auditrulesoptions
#                 for ar in checkdict:
#                     # auditctl -l interprets this number as -1 in the
#                     # output of the command so this is what we have to
#                     # actually check for
#                     ar = ar.replace("auid!=4294967295", "auid!=-1")
#                     ar = ar.replace("-k ", "-F k=" )
#                     print "\n\nChecking for : " + str(ar) + "\n\n"
#                     if ar not in outlines:
#                         retval = False
#                         notloaded.append(ar)
#                 if notloaded:
#                     self.detailedresults += "\nThe following required Audit Rules are NOT loaded:\n" + "\n".join(notloaded)

        except Exception:
            raise
        return retval

    def reportAURulesSingle(self):
        '''
        check audit rules which are stored only in a single
        file (audit.rules)

        @return: retval
        @rtype: bool
        @author: Breen Malmberg
        '''

        retval = True
        configoptsnotfound = []

        self.logger.log(LogPriority.DEBUG, "Running reportAURulesSingle()...")

        try:

            contentlines = self.getFileContents('/etc/audit/audit.rules')
            for item in self.auditrulesoptions:
                if not self.searchFileContents(contentlines, '^' + item):
                    retval = False
                    self.auditrulesoptions[item] = False
            for ar in self.auditrulesoptions:
                if not self.auditrulesoptions[ar]:
                    configoptsnotfound.append(ar)

            if configoptsnotfound:
                self.detailedresults += "\nFollowing required audit rule entries not found:\n" + "\n".join(configoptsnotfound)

        except Exception:
            raise

        return retval

    def reportAURulesParts(self):
        '''
        check audit rules which are stored in multiple files
        within rules.d/ directory on systems which use this
        structure

        @return: retval
        @rtype: bool
        @author: Breen Malmberg
        '''

        retval = True
        configoptsnotfound = []

        self.logger.log(LogPriority.DEBUG, "Running reportAURulesParts()...")

        try:

            for ar in self.auditrulesoptions:
                self.auditrulesoptions[ar] = False

            for arf in self.auditrulesfiles:
                contentlines = self.getFileContents(self.auditrulesbasedir + arf)
                for ar in self.auditrulesoptions:
                    if self.searchFileContents(contentlines, ar):
                        self.auditrulesoptions[ar] = True

            for ar in self.auditrulesoptions:
                if self.auditrulesoptions[ar] == False:
                    retval = False
                    configoptsnotfound.append(ar)

            if configoptsnotfound:
                self.detailedresults += "\nFollowing required audit rule entries not found:\n" + "\n".join(configoptsnotfound)

        except Exception:
            raise

        return retval

    def fix(self):
        '''
        fix audit rules
        ensure audit package is installed
        ensure audit daemon is configured and running
        ensure audit dispatcher is configured

        @author: Breen Malmberg
        '''

        fixsuccess = True
        self.detailedresults = ""
        self.iditerator = 0

        try:

            # only run fix actions if the CI is enabled
            if self.ci.getcurrvalue():

                self.logger.log(LogPriority.DEBUG, "Entering fix()...")

                # run fix actions for mac os x systems
                if self.environ.getosfamily() == 'darwin':
                    self.logger.log(LogPriority.DEBUG, "System detected as Mac OS")
                    if not self.fixmac():
                        fixsuccess = False
                    self.formatDetailedResults("fix", fixsuccess, self.detailedresults)
                    self.logdispatch.log(LogPriority.INFO, self.detailedresults)
                    return fixsuccess

                if not self.auditpkgstatus:
                    self.logger.log(LogPriority.DEBUG, "Audit package is not installed")
                    self.logger.log(LogPriority.DEBUG, "Attempting to install audit package...")
                    for pkg in self.auditpkgs:
                        if self.pkghelper.install(pkg):
                            self.logger.log(LogPriority.DEBUG, "Audit package: " + str(pkg) + " installed successfully")
                            self.auditpkgstatus = True
                            self.report()
                            self.fix()
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

                self.logger.log(LogPriority.DEBUG, "Running kveditor fix for audit dispatcher...")
                if self.audispeditor.fixables:
                    if not self.audispeditor.fix():
                        fixsuccess = False
                        self.detailedresults += '\nAudit dispatcher editor fix failed'
                    else:
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        self.auditdeditor.setEventID(myid)
                    if not self.audispeditor.commit():
                        fixsuccess = False
                        self.detailedresults += '\nAudit dispatcher editor commit failed'
                else:
                    self.logger.log(LogPriority.DEBUG, "Nothing to fix for audit dispatcher")

                self.logger.log(LogPriority.DEBUG, "Running kveditor fix for audit daemon...")
                if self.auditdeditor.fixables:
                    if not self.auditdeditor.fix():
                        fixsuccess = False
                        self.detailedresults += '\nAudit daemon fix failed'
                    else:
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        self.auditdeditor.setEventID(myid)
                    if not self.auditdeditor.commit():
                        fixsuccess = False
                        self.detailedresults += '\nAudit daemon commit failed'
                else:
                    self.logger.log(LogPriority.DEBUG, "Nothing to fix for audit daemon")

                if not self.grubstatus:
                    self.logger.log(LogPriority.DEBUG, "Fixing grub config...")
                    if self.grubver == 1:
                        if not self.fix_grub_one():
                            fixsuccess = False
                    if self.grubver == 2:
                        if not self.fix_grub_two():
                            fixsuccess = False

                # start/restart the audit service so it reads the new config
                self.cmdhelper.executeCommand(self.auditrestart)
                retcode = self.cmdhelper.getReturnCode()
                if retcode != 0:
                    self.logger.log(LogPriority.DEBUG, "Failed to restart auditd service. Command failed with error code: " + str(retcode))
                    errmsg = self.cmdhelper.getErrorString()
                    self.logger.log(LogPriority.DEBUG, errmsg)

                # re-read all of the new rules into the audit daemon
                if os.path.exists("/etc/audit/audit.rules"):
                    if os.path.exists("/usr/sbin/auditctl"):
                        aureread = "/usr/sbin/auditctl -R /etc/audit/audit.rules"
                        self.cmdhelper.executeCommand(aureread)
                        retcode = self.cmdhelper.getReturnCode()
                        if retcode != 0:
                            errmsg = self.cmdhelper.getErrorString()
                            fixsuccess = False
                            self.detailedresults += "\nThere was a problem reloading the audit rules from file: /etc/audit/audit.rules"
                            self.logger.log(LogPriority.DEBUG, errmsg)
                        else:
                            self.logger.log(LogPriority.DEBUG, "Audit rules successfully reloaded from file: /etc/audit/audit.rules")

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

        self.logger.log(LogPriority.DEBUG, "Fixing audit rules...")

        retval = True
        owner = [0, 0]
        perms = 0640

        try:

            if not self.auditrulesfile:
                self.detailedresults += '\nFailed to fix audit rules'
                self.logger.log(LogPriority.DEBUG, "The audit rules file path was undefined. Did not fix audit rules.")
                retval = False
                return retval

        except AttributeError:
            self.detailedresults += '\nFailed to fix audit rules'
            self.logger.log(LogPriority.DEBUG, "The audit rules file path was undefined. Did not fix audit rules.")
            retval = False
            return retval

        try:

            contentlines = []

            if os.path.exists(self.auditrulesfile):
                self.logger.log(LogPriority.DEBUG, str(self.auditrulesfile) + " path exists")

                contentlines = self.getFileContents(self.auditrulesfile)

            if not contentlines:
                contentlines.append('-D\n')
                contentlines.append('-b 320\n')
            else:
                # find -e 2 line if it already exists, remove it
                # and move it to the end of the file
                for line in contentlines:
                    if re.search('^-e 2', line):
                        contentlines.remove(line)

            # append all missing audit rules options
            for item in self.auditrulesoptions:
                if item not in map(str.strip, contentlines):
                    contentlines.append(item + '\n')

            # fix arch= flags
            contentlines = self.fixArches(contentlines)

            # append -e 2 (to lock audit rules) last
            contentlines.append('-e 2\n')

            # remove any duplicate entries
            contentlines = self.fixDuplicates(contentlines)

            # the line -a task,never (added by default on some distro's)
            # would nullify the logging of all syscalls added by this rule
            for line in contentlines:
                if re.search("^-a\s+task,never", line, re.IGNORECASE):
                    contentlines = [c.replace(line, '') for c in contentlines]

            # write file contents
            if not self.writeFileContents(contentlines, self.auditrulesfile, owner, perms):
                retval = False

            # also write the contents to the primary audit rule file
            if os.path.exists('/etc/audit/audit.rules'):
                primcontentlines = self.getFileContents('/etc/audit/audit.rules')
                primcontentlines.extend(contentlines)
                for line in primcontentlines:
                    if re.search('(^-D|^-b|^-e)', line, re.IGNORECASE):
                        primcontentlines.remove(line)
                primcontentlines.insert(0, "-b 320\n")
                primcontentlines.insert(0, "-D\n")
                primcontentlines = self.fixArches(primcontentlines)
                primcontentlines.append('-e 2\n')
                primcontentlines = self.fixDuplicates(primcontentlines)
                # the line '-a task,never' (added by default on some distro's)
                # would nullify the logging of all syscalls added by this rule
                for line in primcontentlines:
                    if re.search("^-a\s+task,never", line, re.IGNORECASE):
                        primcontentlines = [c.replace(line, '') for c in primcontentlines]
                if not self.writeFileContents(primcontentlines, '/etc/audit/audit.rules', owner, perms):
                    retval = False

            if not self.remBadRules():
                self.detailedresults += "\nFailed to remove potentially disruptive and unwanted audit rules"

        except Exception:
            raise
        return retval

    def fixArches(self, contentlines):
        '''
        fix any arch flags to be appropriate to the current
        system's arch (64 or 32)
        cannot have rule entries for both 64 and 32 of the
        same sys calls, because audit control reads them as
        duplicates and will not load the rules file if it
        detects duplicates

        @param: contentlines: list; list of strings to search and
                replace
        @return: contentlines
        @rtype: list
        @author: Breen Malmberg
        '''

        self.logger.log(LogPriority.DEBUG, "Fixing arches...")

        linefixedcount = 0

        if not contentlines:
            return contentlines
        if not isinstance(contentlines, list):
            return contentlines

        try:

            if self.arch == '64':
                for line in contentlines:
                    if re.search("arch=b32", line, re.IGNORECASE):
                        # stime only has a 32 bit call, even on 64 bit systems
                        if not re.search("stime", line, re.IGNORECASE):
                            fixedline = line.replace("arch=b32", "arch=b64")
                            linefixedcount += 1
                            contentlines = [c.replace(line, fixedline) for c in contentlines]
            elif self.arch == '32':
                for line in contentlines:
                    if re.search("arch=b64", line, re.IGNORECASE):
                        fixedline = line.replace("arch=b64", "arch=b32")
                        linefixedcount += 1
                        contentlines = [c.replace(line, fixedline) for c in contentlines]

            if linefixedcount > 0:
                self.logger.log(LogPriority.DEBUG, "Fixed " + str(linefixedcount) + " arch lines")
                self.detailedresults += "\nFixed " + str(linefixedcount) + " arch flags in audit rules"
            else:
                self.logger.log(LogPriority.DEBUG, "Nothing was changed")

        except Exception:
            raise
        return contentlines

    def fixDuplicates(self, contentlines):
        '''
        build a new list which is a copy of contentlines
        except for removing all duplicate entries

        @param contentlines: list; list of strings to search
                through and remove duplicates from
        @return: fixedlist
        @rtype: list
        @author: Breen Malmberg
        '''

        self.logger.log(LogPriority.DEBUG, "Fixing duplicate audit rules entries...")
        linesfixed = 0

        # got nothing, return nothing
        if not contentlines:
            return contentlines
        # not a list, can't do anything
        if not isinstance(contentlines, list):
            return contentlines

        fixedlist = []

        try:

            for i in contentlines:
                if i not in fixedlist:
                    fixedlist.append(i)

            linesfixed = (len(contentlines) - len(fixedlist))

            if linesfixed > 0:
                self.logger.log(LogPriority.DEBUG, "Removed " + str(linesfixed) + " duplicate entries")
                self.detailedresults += "\nRemoved " + str(linesfixed) + " duplicate entries in audit rules"
            else:
                self.logger.log(LogPriority.DEBUG, "Nothing was changed")

            # don't want to erase anything by accident
            if not fixedlist:
                fixedlist = contentlines

        except Exception:
            raise
        return fixedlist

    def remBadRules(self):
        '''
        look for, and remove any unwanted or "bad" audit
        rules (rules which may be disruptive or harmful to
        the normal operation of a system)
        simply add the correct regex to find the rule you
        want to remove, to the badrules list below

        @return: success
        @rtype: bool
        @author: Breen Malmberg
        '''

        success = True
        linesfixedcount = 0

        self.logger.log(LogPriority.DEBUG, "Removing bad/unwanted audit rules...")

        # the unlink and rename encorporates all temp file and cache
        # management for all applications, which is EXTREMELY verbose
        # in logging
        badrules = ["^-a.*-S\s+(unlink|rename).*-k\s+delete"]
        repdict = {}
        for br in badrules:
            repdict[br] = ''

        # all files in rules.d/ have these
        # as well as audit.rules in /etc/audit/
        owner = [0, 0]
        perms = 0640

        try:

            # if we are using a rules.d/ dir with multiple files
            if self.auditrulesfiles:
                for arf in self.auditrulesfiles:
                    replaced = False
                    contentlines = self.getFileContents(self.auditrulesbasedir + arf)
                    for br in badrules:
                        for line in contentlines:
                            if re.search(br, line, re.IGNORECASE):
                                contentlines = [c.replace(line, '') for c in contentlines]
                                linesfixedcount += 1
                                replaced = True
                    if replaced:
                        if not self.writeFileContents(contentlines, self.auditrulesbasedir + arf, owner, perms):
                            success = False
            # or if we are using a single audit.rules file
            if os.path.exists('/etc/audit/audit.rules'):
                replaced = False
                contentlines = self.getFileContents('/etc/audit/audit.rules')
                for br in badrules:
                        for line in contentlines:
                            if re.search(br, line, re.IGNORECASE):
                                contentlines = [c.replace(line, '') for c in contentlines]
                                linesfixedcount += 1
                                replaced = True
                if replaced:
                    if not self.writeFileContents(contentlines, '/etc/audit/audit.rules', owner, perms):
                        success = False

            if linesfixedcount > 0:
                self.logger.log(LogPriority.DEBUG, "Removed " + str(linesfixedcount) + " potentially disruptive audit rule entries")
                self.detailedresults += "\nRemoved " + str(linesfixedcount) + " audit rules which would have an unacceptable impact on system resources"
            else:
                self.logger.log(LogPriority.DEBUG, "Nothing was changed")

        except Exception:
            raise
        return success

    def writeFileContents(self, contents, filepath, owner, perms):
        '''
        write new contents to a temp file then rename it to the
        intended/original file name
        set the given ownership and permissions to the renamed file
        reset the security context of the renamed file
        record a statechglogger change event
        return True if method successfully writes contents
        return False if failed to write contents

        @param contents: list; string list of contents to write to filepath
        @param filepath: string; full path to file to write to (will write to
                a temp file first, then rename to filepath)
        @param owner: list; integer list of owner (first) and group (second) permissions
                ex: [0, 0]
        @param perms: int; integer representation of file permissions to be applied to filepath
                (will use OCTAL form of this int!) ex: 0640 = rw, r, none
        @return: success
        @rtype: bool
        @author: Breen Malmberg
        '''

        success = True
        eventtype = 'conf'
        if not os.path.exists(filepath):
            eventtype = 'creation'

        # we will not attempt to create base directories
        # if they do not already exist
        # that usually means that something else is wrong
        # or needs to be done first
        if not os.path.exists(os.path.dirname(filepath)):
            success = False
            self.logger.log(LogPriority.DEBUG, "The base directory for the specified filepath does not exist!")
            return success

        if not isinstance(filepath, basestring):
            success = False
            self.logger.log(LogPriority.DEBUG, "Parameter: filepath must be type: string. Got: " + str(type(filepath)))
            return success

        if not isinstance(contents, list):
            success = False
            self.logger.log(LogPriority.DEBUG, "Parameter: contents must be type: list. Got: " + str(type(contents)))
            return success

        if not owner:
            success = False
            self.logger.log(LogPriority.DEBUG, "Parameter: owner was empty!")
            return success

        if not isinstance(owner, list):
            success = False
            self.logger.log(LogPriority.DEBUG, "Parameter: owner must be type: list. Got: " + str(type(owner)))
            return success

        if not perms:
            success = False
            self.logger.log(LogPriority.DEBUG, "Parameter: perms was empty!")
            return success

        if not isinstance(perms, int):
            success = False
            self.logger.log(LogPriority.DEBUG, "Parameter: perms must be type: int. Got: " + str(type(perms)))
            return success

        # set the temporary file path to write to
        tmpfile = filepath + '.stonixtmp'

        self.logger.log(LogPriority.DEBUG, "Writing new contents to file: " + str(filepath) + " ...")

        try:

            # to let the end user know this file was created
            # because the path passed in did not exist
            if eventtype == 'creation':
                contents.insert(0, "# This file created by STONIX\n\n")

            f = open(tmpfile, 'w')
            f.writelines(contents)
            f.close()

            self.iditerator += 1
            myid = iterate(self.iditerator, self.rulenumber)
            event = {'eventtype': eventtype,
                     'filepath': filepath}
            self.statechglogger.recordchgevent(myid, event)
            self.statechglogger.recordfilechange(filepath, tmpfile, myid)

            os.rename(tmpfile, filepath)
            os.chown(filepath, owner[0], owner[1])
            os.chmod(filepath, perms)
            resetsecon(filepath)

        except Exception:
            raise
        return success

    def fixmac(self):
        '''
        run fix actions for Mac OS systems

        @return: retval
        @rtype: bool
        @author: Breen Malmberg
        '''

        retval = True
        accontentlines = []
        aucontentlines = []

        self.logger.log(LogPriority.DEBUG, "Executing fixmac()...")

        try:

            # audit_control section
            self.logger.log(LogPriority.DEBUG, "Fixing audit_control...")
            if os.path.exists(self.auditcontrolfile):
                accontentlines = self.getFileContents(self.auditcontrolfile)
                accontentlines.append("\n")

            for aco in self.accontrolopts:
                if not self.searchFileContents(accontentlines, aco):
                    accontentlines.append(aco + "\n")

            if not self.writeFileContents(accontentlines, self.auditcontrolfile, [0, 0], 0400):
                    retval = False

            # audit_user section
            self.logger.log(LogPriority.DEBUG, "Fixing audit_user...")
            if os.path.exists(self.audituserfile):
                aucontentlines = self.getFileContents(self.audituserfile)
                aucontentlines.append("\n")

            for auo in self.useropts:
                if not self.searchFileContents(aucontentlines, auo):
                    aucontentlines.append(auo + '\n')

            if not self.writeFileContents(aucontentlines, self.audituserfile, [0, 0], 0400):
                retval = False

            # restart audit service
            self.logger.log(LogPriority.DEBUG, "Attempting to restart audit service...")
            if self.auditinitcmd:
                self.cmdhelper.executeCommand(self.auditinitcmd)
                retcode = self.cmdhelper.getReturnCode()
                if retcode != 0:
                    errout = self.cmdhelper.getErrorString()
                    retval = False
                    self.detailedresults += "\nFailed to restart audit service"
                    self.logger.log(LogPriority.DEBUG, errout)
                else:
                    self.logger.log(LogPriority.DEBUG, "\nSuccessfully restarted audit service")
            else:
                self.logger.log(LogPriority.DEBUG, "Could not detect command to restart audit service")

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

            self.logger.log(LogPriority.DEBUG, "Entering fix_grub_one()...")

            if not self.grubconffile:
                retval = False
                self.detailedresults += '\nUnable to locate grub conf file'
                return retval

            contentlines = self.getFileContents(self.grubconffile)

            if not contentlines:
                retval = False
                self.detailedresults += '\nUnable to get contents from grub conf file'
                return retval

            for line in contentlines:
                if re.search('kernel\s+.*', line):
                    if not re.search('audit=1', line):
                        contentlines = [c.replace(line, line.rstrip() + ' audit=1\n') for c in contentlines]
                        replaced = True

            if replaced:
                if not self.writeFileContents(contentlines, self.grubconffile, [0, 0], 0644):
                    retval = False

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

            self.logger.log(LogPriority.DEBUG, "Entering fix_grub_two()...")

            if not self.grubconffile:
                retval = False
                self.detailedresults += '\nUnable to locate grub conf file'
                return retval

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
                self.logger.log(LogPriority.DEBUG, "Grub audit configuration line not found in grub conf file. Appending it to grub conf " +
                                "file...")
                contentlines.append('GRUB_CMDLINE_LINUX_DEFAULT="quiet splash audit=1"\n')
                appended = True

            if replaced or appended:

                self.logger.log(LogPriority.DEBUG, "The grub conf file contents have been edited. Saving those changes to the file now...")

                if not self.writeFileContents(contentlines, self.grubconffile, [0, 0], 0644):
                    retval = False

                if not self.grubupdatecmd:
                    retval = False
                    self.detailedresults += '\ngrub update command was not correctly set and could not be run'
                    return retval

                self.logger.log(LogPriority.DEBUG, "Executing grub update command, to update the grub.cfg file...")
                self.cmdhelper.executeCommand(self.grubupdatecmd)
                errout = self.cmdhelper.getErrorString()
                retcode = self.cmdhelper.getReturnCode()
                if retcode != 0:
                    retval = False
                    self.detailedresults += '\nThe grub update command failed with error code: ' + str(retcode)
                    self.logger.log(LogPriority.DEBUG, errout)

        except Exception:
            raise
        return retval
