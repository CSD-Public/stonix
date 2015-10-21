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
Created on Jan 30, 2013

The ConfigureMACPolicy class enables and configures SELinux on support OS platforms.

@author: bemalmbe
@change: dwalker 3/10/2014
@change: dkennel 04/18/2014 Replaced old style CI invocation
@change: 2015/04/15 dkennel updated for new isApplicable
@change: 2015/10/07 eball Help text cleanup
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
        self.rulename = 'CONFIGMACPOLICY'
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.helptext = '''The ConfigureMACPolicy rule configures either \
selinux or apparmor, based on the os platform.  on supported platforms.  \
These programs are called Mandatory Access Control programs and are essential \
for enforcing what certain programs are allowed and not allowed to do.'''
        self.guidance = ['NSA(2.1.1.6)(2.4.2)', 'CCE-3977-6', 'CCE-3999-0',
                         'CCE-3624-4']
        self.setype = "targeted"
        self.universal = "#The following lines were added by stonix\n"
        self.iditerator = 0
        self.seinstall = False
        self.kernel = True
        self.applicable = {'type': 'white',
                           'family': ['linux']}
        self.ph = Pkghelper(self.logger, self.environ)
        # configuration item instantiation
        datatype = "bool"
        key = "CONFIGUREMAC"
        instructions = "To prevent the configuration of a mandatory " + \
            "access control policy set the value of CONFIGUREMAC to " + \
            "False."
        default = True
        self.ConfigureMAC = self.initCi(datatype, key, instructions, default)
        if self.ph.manager in ("yum", "portage"):
            datatype2 = "string"
            key2 = "MODE"
            instructions2 = "Please type in permissive or enforcing for the " + \
                "mode of selinux to operate in.  Default value is permissive"
            default2 = "permissive"
            self.modeci = self.initCi(datatype2, key2, instructions2, default2)
        self.statuscfglist = ['SELinux status:(\s)+enabled',
                              'Current mode:(\s)+(permissive|enforcing)',
                              'Mode from config file:(\s)+(permissive|enforcing)',
                              'Policy from config file:(\s)+(targeted|default)|Loaded policy name:(\s)+(targeted|default)']

    def report(self):
        try:
            if self.ph.manager in ("yum", "portage"):
                self.compliant = self.reportSELinux()
            elif self.ph.manager in ("zypper", "apt-get"):
                self.compliant = self.reportAppArmor()
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

    def reportSELinux(self):
        '''
        determine whether SELinux is already enabled and properly configured.
        self.compliant, self.detailed results and self.currstate properties are
        updated to reflect the system status. self.rulesuccess will be updated
        if the rule does not succeed.

        @return bool
        @author bemalmbe
        @change: dwalker 4/04/2014 implemented commandhelper, added more
            accurate implementation per system basis for apt-get systems
            especially.
        '''
        self.detailedresults = ""
        self.mode = self.modeci.getcurrvalue()
        self.ch = CommandHelper(self.logger)
        compliant = True
        # the selinux path is the same for all systems
        self.path1 = "/etc/selinux/config"
        self.tpath1 = "/etc/selinux/config.tmp"
        # set the appropriate name of the selinux package
        if self.ph.manager == "apt-get":
            if re.search("Debian", self.environ.getostype()):
                self.selinux = "selinux-basics"
            else:
                self.selinux = "selinux"
        elif self.ph.manager == "yum":
            self.selinux = "libselinux"
        # set the grub path for each system and certain values to be found
        # inside the file
        if re.search("Red Hat", self.environ.getostype()) or \
                re.search("Fedora", self.environ.getostype()):
            if re.search("^7", str(self.environ.getosver()).strip()) or \
                    re.search("^20", str(self.environ.getosver()).strip()):
                self.setype = "targeted"
                self.path2 = "/etc/default/grub"
                self.tpath2 = "/etc/default/grub.tmp"
                self.perms2 = [0, 0, 420]
            else:
                self.setype = "targeted"
                self.path2 = "/etc/grub.conf"
                self.tpath2 = "/etc/grub.conf.tmp"
                self.perms2 = [0, 0, 384]
        elif self.ph.manager == "apt-get" or self.ph.manager == "zypper":
            self.setype = "default"
            self.path2 = "/etc/default/grub"
            self.tpath2 = "/etc/default/grub.tmp"
            self.perms2 = [0, 0, 420]
        else:
            self.setype = "targeted"
            self.path2 = "/etc/grub.conf"
            self.tpath2 = "/etc/grub.conf.tmp"
            self.perms2 = [0, 0, 384]

        if not self.ph.check(self.selinux):
            compliant = False
            self.detailedresults += "selinux is not even installed\n"
            self.formatDetailedResults("report", self.compliant,
                                       self.detailedresults)
            self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        else:
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
                if self.ph.manager == "apt-get":
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
            if self.ch.executeCommand(["/usr/sbin/sestatus"]):
                output = self.ch.getOutput()
                error = self.ch.getError()
                if output:
                    # self.statuscfglist is a list of regular expressions to match
                    for item in self.statuscfglist:
                        found = False
                        for item2 in output:
                            if re.search(item, item2):
                                found = True
                                break
                        if not found:
                            if self.ph.manager == "apt-get":
                                if self.seinstall:
                                    self.detailedresults += "Since stonix \
just installed selinux, you will need to reboot your system before this rule \
shows compliant.  After stonix is finished running, reboot system, run stonix \
and do a report run on EnableSELinux rule again to verify if fix was \
completed successfully\n"
                            else:
                                self.detailedresults += "contents of \
sestatus output is not what it's supposed to be\n"
                                compliant = False
                elif error:
                    self.detailedresults += "There was an error running \
the sestatus command to see if selinux is configured properly\n"
                    compliant = False
        return compliant

###############################################################################
    def fix(self):
        try:
            if self.ph.manager in ("yum", "portage"):
                self.rulesuccess = self.fixSELinux()
            elif self.ph.manager in ("zypper", "apt-get"):
                self.rulesuccess = self.fixAppArmor()
        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.rulesuccess

    def fixSELinux(self):
        '''
        enable and configure selinux. self.rulesuccess will be updated if this
        method does not succeed.

        @author bemalmbe
        @change: dwalker 4/04/2014 implemented commandhelper, added more
            accurate implementation per system basis for apt-get systems
            especially.
        '''
        if not self.ConfigureMAC.getcurrvalue():
            return
        self.detailedresults = ""
        if not self.kernel:
            return
        #clear out event history so only the latest fix is recorded
        self.iditerator = 0
        eventlist = self.statechglogger.findrulechanges(self.rulenumber)
        for event in eventlist:
            self.statechglogger.deleteentry(event)

        if not self.ph.check(self.selinux):
            if self.ph.checkAvailable(self.selinux):
                if not self.ph.install(self.selinux):
                    self.rulesuccess = False
                    self.detailedresults += "selinux was not able to be \
installed\n"
                    self.formatDetailedResults("report", self.compliant,
                                               self.detailedresults)
                    self.logdispatch.log(LogPriority.INFO, self.detailedresults)
                    return
                else:
                    self.seinstall = True
            else:
                self.detailedresults += "selinux package not available \
for install on this linux distribution\n"
                self.rulesuccess = False
                self.formatDetailedResults("report", self.rulesuccess,
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
                self.detailedresults += "Corrected permissions on file: \
" + self.path1 + "\n"
            val1 = ""
            tempstring = ""
            for line in self.f1:
                if re.match("^#", line) or re.match("^\s*$", line):
                    tempstring += line
                    continue
                if re.match("^SELINUX\s{0,1}=", line.strip()):
                    if re.search("=", line.strip()):
                        temp = line.split("=")
                        if temp[1].strip() == "permissive" or temp[1].strip() == "enforcing":
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
            self.detailedresults += "Corrected the contents of the file: \
" + self.path1 + " to be compliant\n"
        else:
            self.rulesuccess = False
        if self.f2:
            if not checkPerms(self.path2, self.perms2, self.logger):
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                setPerms(self.path2, self.perms2, self.logger,
                         self.statechglogger, myid)
                self.detailedresults += "Corrected permissions on file: \
" + self.path2 + "\n"
            if self.ph.manager == "apt-get":
                tempstring = ""
                for line in self.f2:
                    if re.match("^GRUB_CMDLINE_LINUX_DEFAULT", line.strip()):
                        newstring = re.sub("security=[a-zA-Z0-9]+", "", line)
                        newstring = re.sub("selinux=[a-zA-Z0-9]+", "", newstring)
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
                    self.detailedresults += "Corrected the contents of \
the file: " + self.path2 + " to be compliant\n"
                else:
                    self.rulesuccess = False
        if not self.seinstall:
            if self.ph.manager == "apt-get":
                if re.search("Debian", self.environ.getostype()):
                    cmd = ["/usr/sbin/selinux-activate"]
                elif re.search("Ubuntu", self.environ.getostype()):
                    cmd = ["/usr/sbin/setenforce", "Enforcing"]
                if self.ch.executeCommand(cmd):
                    if not self.ch.getReturnCode() == 0:
                        self.rulesuccess = False
