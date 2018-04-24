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
Created on Jan 30, 2013

The ConfigureMACPolicy class enables and configures SELinux on support OS
platforms.

@author: Breen Malmberg
@change: 2014/03/10 dwalker
@change: 2014/04/18 dkennel Replaced old style CI invocation
@change: 2015/04/15 dkennel updated for new isApplicable
@change: 2015/10/07 eball Help text cleanup
@change: 2015/10/20 dwalker Update report and fix methods for applicability
@change: 2015/10/26 Breen Malmberg - merged apparmor code with selinux code;
    added method doc strings
@change: 2016/10/20 eball Improve feedback, PEP8 fixes
'''

from __future__ import absolute_import
import traceback
import re
import os
from ..rule import Rule
from ..stonixutilityfunctions import checkPerms, setPerms, readFile, writeFile
from ..stonixutilityfunctions import iterate, resetsecon
from ..logdispatcher import LogPriority
from ..pkghelper import Pkghelper
from ..CommandHelper import CommandHelper


class ConfigureMACPolicy(Rule):
    '''
    The ConfigureMACPolicy class configures either selinux or apparmor
    depending on the os platform.
    @change: dwalker - created two config items, one for enable/disable, and
        another for whether the user wants to use permissive or enforcing
    '''

    def __init__(self, config, environ, logger, statechglogger):
        Rule.__init__(self, config, environ, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 107
        self.rulename = 'ConfigureMACPolicy'
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.sethelptext()
        self.guidance = ['NSA(2.1.1.6)(2.4.2)', 'CCE-3977-6', 'CCE-3999-0',
                         'CCE-3624-4', 'CIS 1.7']
        self.setype = "targeted"
        self.universal = "#The following lines were added by stonix\n"
        self.iditerator = 0
        self.seinstall = False
        self.kernel = True
        self.applicable = {'type': 'white',
                           'family': ['linux']}

        datatype = "bool"
        key = "CONFIGUREMAC"
        instructions = "To prevent the configuration of a mandatory " + \
            "access control policy, set the value of CONFIGUREMAC to " + \
            "False. Note: The 'mandatory access control' is either SELinux " + \
            "or AppArmor, depending on your system type."
        default = True
        self.ConfigureMAC = self.initCi(datatype, key, instructions, default)

        datatype2 = "string"
        key2 = "MODE"
        default2 = "permissive"
        instructions2 = "Valid modes for SELinux are: permissive or " + \
            "enforcing\nValid modes for AppArmor are: complain or enforce"
        self.modeci = self.initCi(datatype2, key2, instructions2, default2)

        self.statuscfglist = ['SELinux status:(\s)+enabled',
                              'Current mode:(\s)+(permissive|enforcing)',
                              'Mode from config file:(\s)+' +
                              '(permissive|enforcing)',
                              'Policy from config file:(\s)+' +
                              '(targeted|default)|Loaded policy name:(\s)+' +
                              '(targeted|default)']
        self.localization()

    def localization(self):
        '''
        wrapper for setting up initial variables and helper objects based on
        which OS type you have

        @return: void
        @author: Breen Malmberg
        '''

        self.initobjs()
        self.setcommon()

        if self.pkghelper.manager == "zypper":
            self.setopensuse()
        if self.pkghelper.manager == "apt-get":
            if re.search("Debian", self.environ.getostype()):
                self.setDebian()
            else:
                self.setubuntu()
        if self.pkghelper.manager == 'yum':
            self.setRedHat()
        if self.pkghelper.manager == 'dnf':
            self.setFedora()

    def setcommon(self):
        '''
        set common variables for use with both/either ubuntu and/or opensuse

        @return: void
        @author: Breen Malmberg
        '''

        self.releasefiles = ['/etc/os-release', '/etc/redhat-release']
        self.path1 = "/etc/selinux/config"
        self.tpath1 = "/etc/selinux/config.tmp"
        self.ubuntu = False
        self.opensuse = False
        self.fedora = False
        self.debian = False
        self.redhat = False
        self.editedgrub = False

        # for generating a new profile, you need the command, plus the target
        # profile name
        self.genprofcmd = '/usr/sbin/aa-genprof'
        self.aaprofiledir = '/etc/apparmor.d/'
        self.aastatuscmd = '/usr/sbin/apparmor_status'
        self.aaunconf = '/usr/sbin/aa-unconfined'
        self.grubbootdir = '/boot/grub2/grub.cfg'
        grubupdatecmds = ['/usr/sbin/update-grub', '/usr/sbin/grub2-mkconfig', '/usr/sbin/grub-mkconfig']
        self.updategrubcmd = ''
        self.updategrubbase = ''
        for cmd in grubupdatecmds:
            if os.path.exists(cmd):
                self.updategrubbase = cmd
        if self.updategrubbase == '/usr/sbin/update-grub':
            self.updategrubcmd = self.updategrubbase
        else:
            self.updategrubcmd = self.updategrubbase + ' -o ' + self.grubbootdir

    def initobjs(self):
        '''
        initialize helper objects

        @return: void
        @author: Breen Malmberg
        '''

        try:

            self.cmdhelper = CommandHelper(self.logger)
            self.pkghelper = Pkghelper(self.logger, self.environ)

        except Exception:
            raise

    def setRedHat(self):
        '''
        set variables for red hat systems

        @return: void
        @author: Breen Malmberg
        '''

        self.logger.log(LogPriority.DEBUG,
                        "This system is using Red Hat operating system")
        self.redhat = True
        self.selinux = 'libselinux'
        self.setype = 'targeted'
        self.path2 = ''
        self.tpath2 = ''
        self.perms2 = []

        try:

            if re.search('(7\.)|(^[7-9]$)', self.getOsVer()):
                # set variables for redhat 7 or higher
                self.logger.log(LogPriority.DEBUG,
                                "This system is using version 7 or higher " +
                                "of the operating system")
                self.path2 = '/etc/default/grub'
                self.perms2 = [0, 0, 384]
            elif re.search('(6\.)|(^[1-6]$)', self.getOsVer()):
                # set variables for redhat 6 or lower
                self.logger.log(LogPriority.DEBUG,
                                "This system is using version 6 or lower " +
                                "of the operating system")
                self.path2 = '/etc/grub.conf'
                self.perms2 = [0, 0, 420]
            else:
                self.logger.log(LogPriority.DEBUG,
                                "Unable to determine os version number")
                self.setRedHatBackupMethod()

            if not self.path2:
                self.logger.log(LogPriority.DEBUG, "Could not determine location of grub file")

            self.tpath2 = self.path2 + '.tmp'

        except Exception:
            raise

    def setRedHatBackupMethod(self):
        '''
        a backup method for attempting to determine, ad-hoc, which file names
        and directories apply to this system

        @return: void
        @author: Breen Malmberg
        '''

        self.logger.log(LogPriority.DEBUG,
                        "This system is using Red Hat operating system")
        self.redhat = True

        try:

            # attempt to set grub path
            possiblegrublocs = ['/etc/default/grub', '/etc/grub.conf']
            for loc in possiblegrublocs:
                if os.path.exists(loc):
                    self.path2 = loc
            if not self.path2:
                self.logger.log(LogPriority.DEBUG,
                                "Backup Method for determining grub conf " +
                                "location failed.")

        except Exception:
            raise

        # attempt to set permissions
        if self.path2 == '/etc/default/grub':
            self.perms2 = [0, 0, 0o600]
        else:
            self.perms2 = [0, 0, 0o644]

    def getOsVer(self):
        '''
        get and return the os version number (x.y) as a string

        @return: osver
        @rtype: string
        @author: Breen Malmberg
        '''

        osver = ""
        releasefile = ""

        try:

            # determine which release file name this system uses
            for relfile in self.releasefiles:
                if os.path.exists(relfile):
                    releasefile = relfile

            # read the release file
            if os.path.exists(releasefile):
                f = open(releasefile, 'r')
                contentlines = f.readlines()
                f.close()

                # parse the release file
                if releasefile == '/etc/redhat-release':
                    # parse redhat-release file
                    osver = self.parseRedhatRelease(contentlines)
                elif releasefile == '/etc/os-release':
                    # parse os-release file
                    osver = self.parseRedhatRelease(contentlines)
            else:
                self.logger.log(LogPriority.DEBUG, "Unable to locate release file")

        except Exception:
            raise

        return osver

    def parseRedhatRelease(self, contentlines):
        '''
        parse the contents of the redhat-release file

        @param contentlines: list list of strings
        @return: osver
        @rtype: string
        @author: Breen Malmberg
        '''

        osver = ""

        try:

            for line in contentlines:
                sline = line.split()
                for item in sline:
                    if re.search('([1-6]\.)|(^[1-6]$)', item):
                        osver = item
                    elif re.search('([7-9]\.)|(^[7-9]$)', item):
                        osver = item

        except Exception:
            raise

        return osver

    def parseOSRelease(self, contentlines):
        '''
        parse the contents of the os-release file

        @param contentlines: list list of strings
        @return: osver
        @rtype: string
        @author: Breen Malmberg
        '''

        osver = ""

        try:

            for line in contentlines:
                if re.search('VERSION=\"', line):
                    sline = line.split('=')
                    osver = str(sline[1]).strip()

        except Exception:
            raise

        return osver

    def setFedora(self):
        '''
        set variables for fedora systems

        @return: void
        @author: Breen Malmberg
        @change: increased the version number accounted for, in
                the regex search (now 20-29; was 20-23 (oops!))
        '''

        self.logger.log(LogPriority.DEBUG, "This system is using Fedora operating system")

        self.fedora = True
        self.selinux = 'libselinux'
        self.setype = 'targeted'
        self.path2 = ''
        self.tpath2 = ''
        self.perms2 = []

        try:

            if re.search('([2][0-9]\.)|(^[2][0-9]$)', self.getOsVer()):
                # set options for fedora 20 to 29
                self.logger.log(LogPriority.DEBUG, "This system is using version 20 or higher of the operating system. Setting grub conf path to /etc/default/grub")
                self.path2 = '/etc/default/grub'
                self.perms2 = [0, 0, 384]
            elif re.search('([1][0-9]\.)|(^[1][0-9]$)', self.getOsVer()):
                # set options for fedora 10 to 19
                self.logger.log(LogPriority.DEBUG, "This system is using version 19 or lower of the operating system. Setting grub conf path to /etc/grub.conf")
                self.path2 = '/etc/grub.conf'
                self.perms2 = [0, 0, 420]
            else:
                self.logger.log(LogPriority.DEBUG, "Unable to determine OS version number")

            if not self.path2:
                self.logger.log(LogPriority.DEBUG, "Could not determine location of grub file")
            self.tpath2 = self.path2 + '.tmp'

        except Exception:
            raise

    def setDebian(self):
        '''
        set variables for Debian systems
        although many things are the same for Debian and Ubuntu,
        not all of them are..

        @return: void
        @author: Breen Malmberg
        '''

        self.logger.log(LogPriority.DEBUG,
                        "This system is using Debian operating system")
        self.modeci.updatecurrvalue("complain")
        self.debian = True
        self.selinux = "selinux-basics"
        self.setype = "default"
        self.path2 = "/etc/default/grub"
        self.tpath2 = self.path2 + ".tmp"
        self.perms2 = [0, 0, 420]
        self.pkgdict = {'apparmor': True,
                        'apparmor-notify': True,
                        'apparmor-utils': True,
                        'apparmor-profiles': True}

        self.aastartcmd = 'invoke-rc.d apparmor start'
        self.aaupdatecmd = 'update-rc.d apparmor start 5 S .'
        self.aareloadprofscmd = 'invoke-rc.d apparmor reload'
        self.aadefscmd = 'update-rc.d apparmor defaults'
        self.aastatuscmd = '/usr/sbin/aa-status'
        if not self.updategrubcmd:
            self.updategrubcmd = '/usr/sbin/update-grub'

    def setopensuse(self):
        '''
        set variables for opensuse systems

        @return: void
        @author: Breen Malmberg
        '''

        self.logger.log(LogPriority.DEBUG,
                        "This system is using OpenSUSE operating system")
        self.selinux = 'libselinux1'
        self.setype = "default"
        self.path2 = "/etc/default/grub"
        self.tpath2 = self.path2 + ".tmp"
        self.perms2 = [0, 0, 420]

        self.opensuse = True
        self.pkgdict = {'libapparmor1': True,
                        'apparmor-profiles': True,
                        'apparmor-utils': True,
                        'apparmor-parser': True,
                        'yast2-apparmor': True,
                        'apparmor-docs': True}
        self.aastartcmd = 'rcapparmor start'
        self.aareloadprofscmd = 'rcapparmor reload'
        self.aastatuscmd = 'rcapparmor status'

    def setubuntu(self):
        '''
        set variables for ubuntu systems

        @return: void
        @author: Breen Malmberg
        '''

        self.logger.log(LogPriority.DEBUG,
                        "This system is using Ubuntu operating system")
        self.modeci.updatecurrvalue("complain")
        self.selinux = 'selinux'
        self.setype = "default"
        self.path2 = "/etc/default/grub"
        self.tpath2 = self.path2 + ".tmp"
        self.perms2 = [0, 0, 420]

        self.ubuntu = True
        self.pkgdict = {'apparmor': True,
                        'apparmor-utils': True,
                        'apparmor-profiles': True}

        self.aastartcmd = 'invoke-rc.d apparmor start'
        self.aaupdatecmd = 'update-rc.d apparmor start 5 S .'
        self.aareloadprofscmd = 'invoke-rc.d apparmor reload'
        self.aadefscmd = 'update-rc.d apparmor defaults'
        self.aastatuscmd = '/usr/sbin/aa-status'
        if not self.updategrubcmd:
            self.updategrubcmd = '/usr/sbin/update-grub'

    def report(self):
        '''
        decide which report method(s) to run, based on package manager

        @return: self.compliant
        @rtype: bool
        @author: Derek Walker
        @change: Breen Malmberg - 10/26/2015 - filled in stub method; added
            method doc string
        '''

        self.compliant = True
        self.detailedresults = ''

        try:
            if str(self.pkghelper.manager).strip() in ("yum", "portage", "dnf"):
                if not self.reportSELinux():
                    self.compliant = False
            elif str(self.pkghelper.manager).strip() in ("zypper", "apt-get"):
                if not self.reportAppArmor():
                    self.compliant = False
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

    def reportAppArmor(self):
        '''
        run report actions for each piece of apparmor in sequence

        @return: retval
        @rtype: bool
        @author: Breen Malmberg
        '''

        retval = True

        try:

            if not self.reportAApkg():
                retval = False
            if retval:
                if not self.reportAAstatus():
                    retval = False
                if not self.reportAAprofs():
                    retval = False

            if self.needsrestart and self.editedgrub:
                self.detailedresults += 'System needs to be restarted ' + \
                    'before AppArmor module can be loaded.\n'

        except Exception:
            raise
        return retval

    def reportAApkg(self):
        '''
        check whether the AppArmor package is installed

        @return: retval
        @rtype: bool
        @author: Breen Malmberg
        '''

        # defaults
        retval = True
        self.needsrestart = False
        for pkg in self.pkgdict:
            self.pkgdict[pkg] = True

        try:

            if not self.pkgdict:
                self.logger.log(LogPriority.DEBUG,
                                "The list of packages needed is blank")

            for pkg in self.pkgdict:
                if not self.pkghelper.check(pkg):
                    self.pkgdict[pkg] = False
            for pkg in self.pkgdict:
                if not self.pkgdict[pkg]:
                    retval = False
                    self.detailedresults += 'Package: ' + str(pkg) + \
                        ' is not installed\n'
                    self.needsrestart = True

        except Exception:
            raise
        return retval

    def reportAAstatus(self):
        '''
        check whether the AppArmor module is loaded

        @return: retval
        @rtype: bool
        @author: Breen Malmberg
        '''

        retval = True
        notloadedterms = ['AppArmor not enabled', 'AppArmor filesystem is not mounted']

        try:

            # we cannot use the AppArmor utilities to check the status, if they
            # are not installed!
            if not self.pkgdict['apparmor-utils']:
                self.detailedresults += 'Cannot check AppArmor status ' + \
                    'without apparmor-utils installed\n'
                retval = False
                return retval

            self.cmdhelper.executeCommand(self.aastatuscmd)
            output = self.cmdhelper.getOutputString()
            retcode = self.cmdhelper.getReturnCode()

            if retcode == 1|127:
                errmsg = self.cmdhelper.getErrorString()
                self.detailedresults += "\nThere was a problem determining the status of apparmor"
                self.logger.log(LogPriority.DEBUG, errmsg)
                retval = False

            for term in notloadedterms:
                if re.search(term, output, re.IGNORECASE):
                    self.needsrestart = True
                    retval = False
                    self.detailedresults += '\n' + str(term)

            f = open(self.path2, 'r')
            contentlines = f.readlines()
            f.close()

            defgrubline = "GRUB_CMDLINE_LINUX_DEFAULT"
            apparmorfound = False
            securityfound = False
            securityopt = "security=apparmor"
            apparmoropt = "apparmor=1"
            for line in contentlines:
                if re.search(defgrubline, line, re.IGNORECASE):
                    if re.search(securityopt, line, re.IGNORECASE):
                        securityfound = True
                    if re.search(apparmoropt, line, re.IGNORECASE):
                        apparmorfound = True
            if not apparmorfound:
                retval = False
                self.detailedresults += '\napparmor=1 not found in default grub config'
            if not securityfound:
                retval = False
                self.detailedresults += '\nsecurity=apparmor not found in default grub config'

        except Exception:
            raise
        return retval

    def reportAAprofs(self):
        '''
        check whether or not there are any unconfined (by AppArmor) services or
        applications

        @return: retval
        @rtype: bool
        @author: Breen Malmberg
        '''

        self.unconflist = []
        unconfined = False
        retval = True

        try:

            if not self.pkgdict['apparmor-utils']:
                self.detailedresults += 'Cannot check AppArmor profile ' + \
                    'status without apparmor-utils installed\n'
                retval = False
                return retval
            if not self.pkgdict['apparmor-profiles']:
                self.detailedresults += 'Cannot accurately determine ' + \
                    'profile status without apparmor-profiles installed\n'
                retval = False
                return retval

            self.cmdhelper.executeCommand(self.aaunconf)
            errout = self.cmdhelper.getErrorString()
            output = self.cmdhelper.getOutputString()
            if re.search('error|Traceback', output):
                retval = False
                if re.search('codecs\.py', output):
                    self.detailedresults += 'There is a bug with ' + \
                        'running a required command in this version of ' + \
                        'Debian. This rule will remain NCAF until Debian ' + \
                        'can fix this issue. This is not a STONIX bug.\n'
            if re.search('error|Traceback', errout):
                retval = False
                if re.search('codecs\.py', errout):
                    self.detailedresults += 'There is a bug with running ' + \
                        'a required command in this version of Debian. ' + \
                        'This rule will remain NCAF until Debian can fix ' + \
                        'this issue. This is not a STONIX bug.\n'
                else:
                    self.detailedresults += 'There was an error running ' + \
                        'command: ' + str(self.aaunconf) + '\n'
                    self.detailedresults += 'The error was: ' + str(errout) + \
                        '\n'
                    self.logger.log(LogPriority.DEBUG,
                                    "Error running command: " +
                                    str(self.aaunconf) + "\nError was: " +
                                    str(errout))
            output = self.cmdhelper.getOutput()
            for line in output:
                if re.search('not confined', line):
                    retval = False
                    unconfined = True
                    sline = line.split()
                    self.unconflist.append(str(sline[1]))
                    self.detailedresults += str(sline[1]) + \
                        ' is not confined by AppArmor\n'
            if unconfined:
                self.detailedresults += "\nIf you have services or " + \
                    "applications which are not confined by AppArmor, this " + \
                    "can only be corrected manually, by the administrator " + \
                    "of your system. (See the man page for apparmor).\n"

        except Exception:
            raise
        return retval

    def reportSELinux(self):
        '''
        Determine whether SELinux is already enabled and properly configured.
        self.compliant, self.detailed results and self.currstate properties are
        updated to reflect the system status. self.rulesuccess will be updated
        if the rule does not succeed.

        @return bool
        @author Breen Malmberg
        @change: dwalker 4/04/2014 implemented commandhelper, added more
            accurate implementation per system basis for apt-get systems
            especially.
        @change: Breen Malmberg 6/2/2016 moved all of the localization to the
        separate localization methods chain at the top of the class
        @change: Breen Malmberg 6/10/2016 changed the commands to look for
        unconfined daemons and unlabled device files so that they actually work
        and do not produce errors when run on rhel7
        '''

        self.detailedresults = ""
        self.mode = self.modeci.getcurrvalue()
        compliant = True

        if not self.pkghelper.check(self.selinux):
            compliant = False
            self.detailedresults += "SELinux is not installed\n"
            self.formatDetailedResults("report", self.compliant,
                                       self.detailedresults)
            self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        else:
            cmd = "ps -eZ | egrep 'initrc' | egrep -vw 'tr | ps | egrep | " + \
                "bash | awk' | tr ':' ' ' | awk '{ print $NF }'"
            if not self.cmdhelper.executeCommand(cmd):
                self.detailedresults += "Unable to check for unconfined " + \
                    "daemons\n"
                compliant = False
            elif self.cmdhelper.getReturnCode() != 0:
                self.detailedresults += "Unconfined daemons found running\n"
                compliant = False
            cmd = "ls -Z /dev | grep -i unlabled_t"
            if not self.cmdhelper.executeCommand(cmd):
                self.detailedresults += "Unable to check for unlabled " + \
                    "device files\n"
                compliant = False
            # for whatever reason, the success exit code for the above command
            # on rhel7 is 1 instead of 0...
            elif self.cmdhelper.getReturnCode() != 1:
                self.detailedresults += "Unlabeled device files found\n"
                compliant = False
            self.f1 = readFile(self.path1, self.logger)
            self.f2 = readFile(self.path2, self.logger)
            if self.f1:
                if not checkPerms(self.path1, [0, 0, 420], self.logger):
                    compliant = False
                conf1 = True
                conf2 = True
                found1 = False
                found2 = False
                for line in self.f1:
                    if re.match("^#", line) or re.match("^\s*$", line):
                        continue
                    if re.match("^SELINUX\s{0,1}=", line.strip()):
                        found1 = True
                        if re.search("=", line.strip()):
                            temp = line.split("=")
                            if temp[1].strip() == self.mode or \
                                    temp[1].strip() == "enforcing":
                                continue
                            else:
                                conf1 = False
                    if re.match("^SELINUXTYPE", line.strip()):
                        found2 = True
                        if re.search("=", line.strip()):
                            temp = line.split("=")
                            if temp[1].strip() == self.setype:
                                continue
                            else:
                                conf2 = False
                if not found1 or not found2:
                    self.detailedresults += "The desired contents " + \
                        "were not found in /etc/selinux/config\n"
                    compliant = False
                elif not conf1 or not conf2:
                    self.detailedresults += "The desired contents " + \
                        "were not found in /etc/selinux/config\n"
                    compliant = False
            else:
                self.detailedresults += "/etc/selinux/config file " + \
                    "is blank\n"
                compliant = False
            if self.f2:
                conf1 = False
                conf2 = False
                if self.pkghelper.manager == "apt-get":
                    if not checkPerms(self.path2, self.perms2,
                                      self.logger):
                        compliant = False
                    for line in self.f2:
                        if re.match("^#", line) or re.match("^\s*$",
                                                            line):
                            continue
                        if re.match("^GRUB_CMDLINE_LINUX_DEFAULT",
                                    line.strip()):
                            if re.search("=", line):
                                temp = line.split("=")
                                if re.search("security=selinux",
                                             temp[1].strip()):
                                    conf1 = True
                                if re.search("selinux=0",
                                             temp[1].strip()):
                                    conf2 = True
                    if conf1 or conf2:
                        self.detailedresults += "Grub file is non compliant\n"
                        compliant = False
                else:
                    conf1 = False
                    conf2 = False
                    for line in self.f2:
                        if re.match("^#", line) or re.match("^\s*$",
                                                            line):
                            continue
                        if re.match("^kernel", line.strip()):
                            if re.search("^selinux=0", line.strip()):
                                conf1 = True
                            if re.match("^enforcing=0", line.strip()):
                                conf2 = True
                    if conf1 or conf2:
                        self.detailedresults += "Grub file is non compliant\n"
                        compliant = False
            if self.cmdhelper.executeCommand(["/usr/sbin/sestatus"]):
                output = self.cmdhelper.getOutput()
                error = self.cmdhelper.getError()
                if output:
                    # self.statuscfglist is a list of regular expressions to
                    # match
                    for item in self.statuscfglist:
                        found = False
                        for item2 in output:
                            if re.search(item, item2):
                                found = True
                                break
                        if not found:
                            if self.pkghelper.manager == "apt-get":
                                if self.seinstall:
                                    self.detailedresults += "Since stonix \
just installed SELinux, you will need to reboot your system before this rule \
shows compliant. After stonix is finished running, reboot system, run stonix \
and do a report run on EnableSELinux rule again to verify if fix was \
completed successfully\n"
                            else:
                                self.detailedresults += "Contents of \
sestatus output is not what it's supposed to be\n"
                                compliant = False
                elif error:
                    self.detailedresults += "There was an error running \
the sestatus command to see if SELinux is configured properly\n"
                    compliant = False
        return compliant

###############################################################################
    def fix(self):
        '''
        decide which fix method(s) to run, based on package manager

        @return: fixresult
        @rtype: bool
        @author: Derek Walker
        @change: Breen Malmberg - 10/26/2015 - filled in stub method;
            added doc string; changed method to use correct return variable
        @change: added dnf package manager type to the detectable types; this
                fixed an issue where the package manager could not be detected
                correctly on later versions of fedora OS
        '''

        fixresult = True
        self.detailedresults = ""
        self.iditerator = 0

        try:

            if self.ConfigureMAC.getcurrvalue():

                if str(self.pkghelper.manager).strip() in ["yum", "portage", "dnf"]:
                    if not self.fixSELinux():
                        fixresult = False
                elif str(self.pkghelper.manager).strip() in ["zypper", "apt-get"]:
                    if not self.fixAppArmor():
                        fixresult = False
                if str(self.pkghelper.manager).strip() not in ["zypper", "apt-get", "yum", "portage", "dnf"]:
                    self.detailedresults += 'Could not identify your OS ' + \
                        'type, or OS not supported for this rule.\n'
                    fixresult = False

            else:
                self.detailedresults += 'The CI for this rule was not ' + \
                    'enabled. Nothing was done.\n'
                self.logger.log(LogPriority.DEBUG, self.detailedresults)

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", fixresult, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return fixresult

    def fixAppArmor(self):
        '''
        wrapper to decide which fix actions to run and in what order, for
        apparmor

        @return: retval
        @rtype: bool
        @author: Breen Malmberg
        '''

        retval = True

        try:

            if self.modeci.getcurrvalue() in ['complain', 'permissive']:
                aamode = '/usr/sbin/aa-complain'
            elif self.modeci.getcurrvalue() in ['enforce', 'enforcing']:
                aamode = '/usr/sbin/aa-enforce'
            if not aamode:
                self.detailedresults += 'No valid mode was specified ' + \
                    'for AppArmor profiles. Valid modes include: enforce, ' + \
                    'or complain.\n'
                self.detailedresults += 'Fix was not run to completion. ' + \
                    'Please enter a valid mode and try again.\n'
                self.logger.log(LogPriority.DEBUG, self.detailedresults)
                retval = False
                return retval

            self.aaprofcmd = aamode + ' ' + self.aaprofiledir + '*'

            if not self.fixAApkg():
                retval = False
            if retval:  # Should not continue unless apparmor pkg is installed
                if not self.fixAAstatus():
                    retval = False

        except Exception:
            raise
        return retval

    def fixAApkg(self):
        '''
        install all packages which are required for apparmor to function
        properly

        @return: retval
        @rtype: bool
        @author: Breen Malmberg
        '''

        retval = True

        try:

            for pkg in self.pkgdict:
                if not self.pkgdict[pkg]:
                    if not self.pkghelper.install(pkg):
                        retval = False
                        self.detailedresults += '\nFailed to install required package: ' + str(pkg) + '\n'
            if not retval:
                self.detailedresults += "|nFailed to install one or more required packages. Please check your network connection and ensure that you can reach your repository(ies)."

        except Exception:
            raise
        return retval

    def getFileContents(self, filepath):
        '''
        retrieve and return contents of given filepath
        in list form

        @param filepath: string; full path to file from which to
                read contents
        @return: contents
        @rtype: list
        @author: Breen Malmberg
        '''

        contents = []

        try:

            if not filepath:
                self.logger.log(LogPriority.DEBUG, "Parameter: filepath was blank!")
                return contents
            if not isinstance(filepath, basestring):
                self.logger.log(LogPriority.DEBUG, "Parameter: filepath needs to be type: string. Got: " + str(type(filepath)))
                return contents
            if not os.path.exists(filepath):
                self.logger.log(LogPriority.DEBUG, "The specified filepath does not exist. Nothing to retrieve.")
                return contents

            f = open(filepath, 'r')
            contents = f.readlines()
            f.close()

        except Exception:
            raise
        return contents

    def fixGrub(self):
        '''
        determine if system uses /etc/default/grub and
        /boot/grub2/grub.cfg - or - /etc/grub.conf
        and run fix actions to ensure
        that either one have the required configuration
        options correctly specified in them

        @return: success
        @rtype: bool
        @author: Breen Malmberg
        '''

        success = True
        owner = [0, 0]
        perms = 0644

        try:

            if os.path.exists('/etc/default/grub'):
    
                grubpath = '/etc/default/grub'
    
                self.logger.log(LogPriority.DEBUG, "Grub configuration file detected as: " + str(grubpath))
    
                self.logger.log(LogPriority.DEBUG, "Reading grub configuration file...")
    
                grubcontents = self.getFileContents(grubpath)
    
                self.logger.log(LogPriority.DEBUG, "Got grub configuration file contents. Looking for required AppArmor kernel config line...")
    
                # if the grub configuration file was empty, or
                # we failed to get the contents, then we will not
                # attempt to recreate the entire file because this
                # could be destructive to the target system
                if not grubcontents:
                    self.logger.log(LogPriority.DEBUG, "Could not retrieve the contents of the grub boot configuration! Giving up...")
                    success = False
                    return success
    
                for line in grubcontents:
                    if re.search('^GRUB_CMDLINE_LINUX_DEFAULT="', line, re.IGNORECASE):
                        if not re.search('apparmor=1 security=apparmor', line):
                            self.logger.log(LogPriority.DEBUG, "Required AppArmor kernel line not found. Adding it...")
                            grubcontents = [c.replace(line, line[:-2] + ' apparmor=1 security=apparmor"\n') for c in grubcontents]
                            self.editedgrub = True
                        else:
                            apparmorfound = True
    
                if not self.editedgrub and not apparmorfound:
                    grubcontents.append('\n# Following line was modified by STONIX\n')
                    grubcontents.append('GRUB_CMDLINE_LINUX_DEFAULT="apparmor=1 security=apparmor"\n')
                    self.editedgrub = True
    
                if self.editedgrub:
                    self.logger.log(LogPriority.DEBUG, "Added AppArmor kernel config line to contents. Writing contents to grub config file...")
                    
                    if not self.writeFileContents(grubcontents, grubpath, owner, perms):
                        success = False
                        self.logger.log(LogPriority.DEBUG, "Failed to write configuration changes to file: " + str(grubpath))
                        return success
                    
                    self.logger.log(LogPriority.DEBUG, "Finished writing AppArmor kernel config line to grub config file")
                    self.needsrestart = True
    
                    self.logger.log(LogPriority.DEBUG, "Running update-grub command to update grub kernel boot configuration...")
                    self.cmdhelper.executeCommand(self.updategrubcmd)
                    retcode = self.cmdhelper.getReturnCode()
                    if retcode != 0:
                        errout = self.cmdhelper.getErrorString()
                        success = False
                        self.detailedresults += '\nError updating grub configuration: ' + str(errout)
                        self.logger.log(LogPriority.DEBUG, "Error executing " + str(self.updategrubcmd) + "\nError was: " + str(errout))
                    self.logger.log(LogPriority.DEBUG, "Finished successfully updating grub kernel boot configuration...")

            else:

                grubpath = '/etc/grub.conf'

                if os.path.exists('/boot/grub/grub.conf'):
                    grubpath = '/boot/grub/grub.conf'

                grubcontents = self.getFileContents(grubpath)
                for line in grubcontents:
                    if re.search('^\s+kernel\s+', line, re.IGNORECASE):
                        if not re.search('apparmor=1', line, re.IGNORECASE):
                            grubcontents = [c.replace(line, line[:-2] + ' apparmor=1\n') for c in grubcontents]
                            self.editedgrub = True
                        if not re.search('security=apparmor', line, re.IGNORECASE):
                            grubcontents = [c.replace(line, line[:-2] + ' security=apparmor\n') for c in grubcontents]
                            self.editedgrub = True
                if self.editedgrub:
                    if not self.writeFileContents(grubcontents, grubpath, owner, perms):
                        success = False
                        self.logger.log(LogPriority.DEBUG, "Failed to write configuration changes to file: " + str(grubpath))
                        return success

        except Exception:
            raise
        return success

    def writeFileContents(self, contents, filepath, owner, perms):
        '''
        write contents to a temporary file, then rename to the
        given filepath, after recording a change event (for undo)
        give the filepath the specified owner and perms and then
        reset the security of the file (resetsecon)

        @param contents: list; string list to write to filepath
        @param filepath: string; full path to file to write to
        @param owner: list; integer list (of exactly len=2) representing
                the owner and group uids to apply to filepath
        @param perms: int; 4 digit octal integer representing the permissions
                to apply to filepath
        @return: success
        @rtype: bool
        @author: Breen Malmberg
        '''

        success = True
        eventtype = 'conf'
        tmpfile = filepath + '.stonixtmp'

        if not filepath:
            self.logger.log(LogPriority.DEBUG, "Parameter: filepath was blank!")
            success = False
        if not os.path.exists(os.path.dirname(filepath)):
            self.logger.log(LogPriority.DEBUG, "Base directory for given filepath does not exist and there is insufficient information to create it.")
            success = False
        if not isinstance(filepath, basestring):
            self.logger.log(LogPriority.DEBUG, "Parameter: filepath must be type: string. Got: " + str(type(filepath)))
            success = False

        if not contents:
            self.logger.log(LogPriority.DEBUG, "Parameter: contents was blank!")
            success = False
        if not isinstance(contents, list):
            self.logger.log(LogPriority.DEBUG, "Parameter: contents must be type: list. Got: " + str(type(contents)))
            success = False

        if not owner:
            self.logger.log(LogPriority.DEBUG, "Parameter: owner was blank!")
            success = False
        if not isinstance(owner, list):
            self.logger.log(LogPriority.DEBUG, "Parameter: owner must be type: list. Got: " + str(type(owner)))
            success = False
        if len(owner) < 2:
            self.logger.log(LogPriority.DEBUG, "Parameter: owner must be a list of exactly 2 integers.")

        if not perms:
            self.logger.log(LogPriority.DEBUG, "Parameter: perms was blank!")
            success = False
        if not isinstance(perms, int):
            self.logger.log(LogPriority.DEBUG, "Parameter: perms must be type: int. Got: " + str(type(perms)))
            success = False

        if not success:
            return success

        tf = open(tmpfile, 'w')
        tf.writelines(contents)
        tf.close()
        
        self.iditerator += 1
        myid = iterate(self.iditerator, self.rulenumber)
        event = {'eventtype': eventtype,
                 'filepath': filepath}
        self.statechglogger.recordchgevent(myid, event)
        self.statechglogger.recordfilechange(tmpfile, filepath, myid)

        os.rename(tmpfile, filepath)
        os.chmod(filepath, perms)
        os.chown(filepath, owner[0], owner[1])
        resetsecon(filepath)

    def fixAAstatus(self):
        '''
        ensure that apparmor is configured correctly and running

        @return: retval
        @rtype: bool
        @author: Breen Malmberg
        '''

        retval = True

        try:

            if self.ubuntu or self.debian:

                self.logger.log(LogPriority.DEBUG, "Detected that this is an apt-get based system. Looking for grub configuration file...")

                if not self.fixGrub():
                    retval = False
                    return retval

                self.logger.log(LogPriority.DEBUG, "Checking if the system needs to be restarted first in order to continue...")

                if not self.needsrestart:

                    self.logger.log(LogPriority.DEBUG, "System does not require restart to continue configuring AppArmor. Proceeding...")

                    self.cmdhelper.executeCommand(self.aadefscmd)
                    errout = self.cmdhelper.getErrorString()
                    if re.search('error|Traceback', errout):
                        retval = False
                        self.detailedresults += '\nThere was an error setting apparmor defaults'

                    self.cmdhelper.executeCommand(self.aaprofcmd)
                    errout = self.cmdhelper.getErrorString()
                    if re.search('error|Traceback', errout):
                        retval = False
                        self.detailedresults += '\nThere was an error setting the apparmor mode'

                    self.cmdhelper.executeCommand(self.aareloadprofscmd)
                    errout = self.cmdhelper.getErrorString()
                    if re.search('error|Traceback', errout):
                        retval = False
                        self.detailedresults += '\nThere was an error updating the apparmor profile'

                    self.cmdhelper.executeCommand(self.aaupdatecmd)
                    errout = self.cmdhelper.getErrorString()
                    if re.search('error|Traceback', errout):

                        self.cmdhelper.executeCommand(self.aastartcmd)
                        errout2 = self.cmdhelper.getErrorString()
                        if re.search('error|Traceback', errout2):
                            retval = False
                            self.detailedresults += '\nThere was an error starting apparmor'

                else:

                    self.logger.log(LogPriority.DEBUG, "System requires a restart before continuing to configure AppArmor. Will NOT restart automatically.")
                    self.detailedresults += '\n\nAppArmor was just installed and/or added to the kernel boot config. You will need to restart your system and run this rule ' + \
                        'fix again before it can finish properly configuring your system.\n\n'
                    retval = False
                    return retval

            elif self.opensuse:

                if not self.fixGrub():
                    retval = False
                    return retval

                self.cmdhelper.executeCommand(self.aaprofcmd)
                errout = self.cmdhelper.getErrorString()
                if re.search('error|Traceback', errout):
                    retval = False
                    self.detailedresults += 'There was an error running command: ' + str(self.aaprofcmd) + '\n'
                    self.detailedresults += 'The error was: ' + str(errout) + '\n'

                self.cmdhelper.executeCommand(self.aareloadprofscmd)
                errout = self.cmdhelper.getErrorString()
                if re.search('error|Traceback', errout):
                    retval = False
                    self.detailedresults += 'There was an error running command: ' + str(self.aareloadprofscmd) + '\n'
                    self.detailedresults += 'The error was: ' + str(errout) + '\n'

                self.cmdhelper.executeCommand(self.aastartcmd)
                errout = self.cmdhelper.getErrorString()
                if re.search('error|Traceback', errout):
                    retval = False
                    self.detailedresults += 'There was an error running command: ' + str(self.aastartcmd) + '\n'
                    self.detailedresults += 'The error was: ' + str(errout) + '\n'

            else:
                self.detailedresults += "\nCould not identify your OS type, or OS not supported!"
                retval = False

        except Exception:
            raise
        return retval

    def fixSELinux(self):
        '''
        enable and configure selinux. self.rulesuccess will be updated if this
        method does not succeed.

        @return: fixresult
        @rtype: bool
        @author Breen Malmberg
        @change: dwalker 4/04/2014 implemented commandhelper, added more
            accurate implementation per system basis for apt-get systems
            especially.
        '''

        fixresult = True

        if not self.kernel:
            return

        try:

            # clear out event history so only the latest fix is recorded
            eventlist = self.statechglogger.findrulechanges(self.rulenumber)
            for event in eventlist:
                self.statechglogger.deleteentry(event)

            if not self.pkghelper.check(self.selinux):
                if self.pkghelper.checkAvailable(self.selinux):
                    if not self.pkghelper.install(self.selinux):
                        fixresult = False
                        self.detailedresults += "SELinux installation failed\n"
                        self.formatDetailedResults("fix", fixresult,
                                                   self.detailedresults)
                        self.logdispatch.log(LogPriority.INFO,
                                             self.detailedresults)
                        return
                    else:
                        self.seinstall = True
                else:
                    self.detailedresults += "SELinux package not available " + \
                        "for installion on this Linux distribution\n"
                    fixresult = False
                    self.formatDetailedResults("fix", fixresult,
                                               self.detailedresults)
                    return
            self.f1 = readFile(self.path1, self.logger)
            self.f2 = readFile(self.path2, self.logger)
            if self.f1:
                if not checkPerms(self.path1, [0, 0, 420], self.logger):
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    setPerms(self.path1, [0, 0, 420], self.logger,
                             self.statechglogger, myid)
                    self.detailedresults += "Corrected permissions on file: " + \
                        self.path1 + "\n"
                val1 = ""
                tempstring = ""
                for line in self.f1:
                    if re.match("^#", line) or re.match("^\s*$", line):
                        tempstring += line
                        continue
                    if re.match("^SELINUX\s{0,1}=", line.strip()):
                        if re.search("=", line.strip()):
                            temp = line.split("=")
                            if temp[1].strip() == "permissive" or \
                               temp[1].strip() == "enforcing":
                                val1 = temp[1].strip()
                            if val1 != self.modeci.getcurrvalue():
                                val1 = self.modeci.getcurrvalue()
                                continue
                    if re.match("^SELINUXTYPE", line.strip()):
                        continue
                    else:
                        tempstring += line
                tempstring += self.universal
                if val1:
                    tempstring += "SELINUX=" + val1 + "\n"
                else:
                    tempstring += "SELINUX=permissive\n"
                tempstring += "SELINUXTYPE=" + self.setype + "\n"

            else:
                tempstring = ""
                tempstring += self.universal
                tempstring += "SELINUX=permissive\n"
                tempstring += "SELINUXTYPE=" + self.setype + "\n"
            if writeFile(self.tpath1, tempstring, self.logger):
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                event = {"eventtype": "conf",
                         "filepath": self.path1}
                self.statechglogger.recordchgevent(myid, event)
                self.statechglogger.recordfilechange(self.path1, self.tpath1,
                                                     myid)
                os.rename(self.tpath1, self.path1)
                os.chown(self.path1, 0, 0)
                os.chmod(self.path1, 420)
                resetsecon(self.path1)
                self.detailedresults += "Corrected the contents of the file: " + \
                    self.path1 + " to be compliant\n"
            else:
                fixresult = False
            if self.f2:
                if not checkPerms(self.path2, self.perms2, self.logger):
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    setPerms(self.path2, self.perms2, self.logger,
                             self.statechglogger, myid)
                    self.detailedresults += "Corrected permissions on file: " + \
                        self.path2 + "\n"
                if self.pkghelper.manager == "apt-get":
                    tempstring = ""
                    for line in self.f2:
                        if re.match("^GRUB_CMDLINE_LINUX_DEFAULT",
                                    line.strip()):
                            newstring = re.sub("security=[a-zA-Z0-9]+", "",
                                               line)
                            newstring = re.sub("selinux=[a-zA-Z0-9]+", "",
                                               newstring)
                            newstring = re.sub("\s+", " ", newstring)
                            tempstring += newstring + "\n"
                        else:
                            tempstring += line
                else:
                    tempstring = ""
                    for line in self.f2:
                        if re.match("^kernel", line):
                            temp = line.strip().split()
                            i = 0
                            for item in temp:
                                if re.search("selinux", item):
                                    temp.pop(i)
                                    i += 1
                                    continue
                                if re.search("enforcing", item):
                                    temp.pop(i)
                                    i += 1
                                    continue
                                i += 1
                            tempstringtemp = ""
                            for item in temp:
                                tempstringtemp += item
                            tempstringtemp += "\n"
                            tempstring += tempstringtemp
                        else:
                            tempstring += line
                if tempstring:
                    if writeFile(self.tpath2, tempstring, self.logger):
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        event = {"eventtype": "conf",
                                 "filepath": self.path2}
                        self.statechglogger.recordchgevent(myid, event)
                        self.statechglogger.recordfilechange(self.path2,
                                                             self.tpath2, myid)
                        os.rename(self.tpath2, self.path2)
                        os.chown(self.path2, self.perms2[0], self.perms2[1])
                        os.chmod(self.path2, self.perms2[2])
                        resetsecon(self.path2)
                        self.detailedresults += "Corrected the contents of " + \
                            "the file: " + self.path2 + " to be compliant\n"
                    else:
                        fixresult = False
                        self.detailedresults += "Failed to write " + \
                            "configuration to file: " + str(self.tpath2)
            if not self.seinstall:
                if self.pkghelper.manager == "apt-get":
                    if re.search("Debian", self.environ.getostype()):
                        cmd = ["/usr/sbin/selinux-activate"]
                    elif re.search("Ubuntu", self.environ.getostype()):
                        cmd = ["/usr/sbin/setenforce", "Enforcing"]
                    if self.cmdhelper.executeCommand(cmd):
                        if not self.cmdhelper.getReturnCode() == 0:
                            errout = self.cmdhelper.getErrorString()
                            fixresult = False
                            self.detailedresults += "The command: " + \
                                str(cmd) + " returned an error"
                            self.logger.log(LogPriority.DEBUG, errout)

        except Exception:
            raise
        return fixresult
