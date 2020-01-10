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

"""
Created on 2015/08/04
Verify package integrity, correct permissions
@author: Eric Ball
@change: 2015/08/04 eball - Original implementation
@change: 2015/08/24 eball - Improve output, remove .pyc files from output
@change: 2016/04/20 eball - Per RHEL 7 STIG, added a fix to automate correction
    of file permissions
@change: 2018/07/30 Breen Malmberg - re-wrote the report and fix methods entirely
"""



import re
import traceback

from rule import Rule
from logdispatcher import LogPriority
from CommandHelper import CommandHelper


class InstalledSoftwareVerification(Rule):

    def __init__(self, config, environ, logger, statechglogger):
        """Constructor"""
        Rule.__init__(self, config, environ, logger, statechglogger)
        self.config = config
        self.environ = environ
        self.logger = logger
        self.statechglogger = statechglogger
        self.rulenumber = 230
        self.rulename = 'InstalledSoftwareVerification'
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.rootrequired = True
        self.guidance = ['NSA 2.1.3.2', 'CCE 14931-0',
                         'CCE-RHEL7-CCE-TBD 2.1.3.2.1']
        self.applicable = {'type': 'white',
                           'os': {'Red Hat Enterprise Linux': ['6.0', '+'],
                                  'CentOS Linux': ['7.0', '+']}}

        datatype = 'bool'
        key = 'FIXPERMISSIONS'
        instructions = 'If set to True, this rule will fix the permissions \
of the package for any file which has a permission deviation from the vendor \
default.'
        default = True
        self.fixPermsCi = self.initCi(datatype, key, instructions, default)
        self.sethelptext()

    def getInstalledPackages(self):
        """return a list of installed packages (as reported
        by rpm database)


        :returns: installedpackages

        :rtype: list
@author: Breen Malmberg

        """

        installedpackages = []

        listinstalledcmd = "/usr/bin/rpm -qa"

        self.ch.executeCommand(listinstalledcmd)
        outputlist = self.ch.getOutput()
        retcode = self.ch.getReturnCode()
        if retcode == 0:
            installedpackages = outputlist
        else:
            errmsg = self.ch.getErrorString()
            self.logger.log(LogPriority.DEBUG, errmsg)

        return installedpackages

    def report(self):
        """Compile a list of files not conforming to rpm package database permissions (Mode)
        report non-compliant if any are found
        else report compliant


        :returns: self.compliant

        :rtype: bool
@author: Eric Ball
@author: Breen Malmberg
@change: Breen Malmberg - 07/30/2018 - complete re-write of method

        """

        self.detailedresults = ""
        self.compliant = True
        self.ch = CommandHelper(self.logger)
        reportcmd = "/usr/bin/rpm -V --nosignature --nolinkto --nofiledigest --nosize --nomtime --nordev --nocaps "
        self.badpermfiles = []
        self.badpermpkgs = {}
        self.badgroupfiles = []
        self.badownerfiles = []
        self.badhashfiles = []

        try:

            self.logger.log(LogPriority.DEBUG, "Searching for files with incorrect permissions...")

            installedpkgs = self.getInstalledPackages()

            for pkg in installedpkgs:
                self.ch.executeCommand(reportcmd + pkg)
                outputlist = self.ch.getOutput()
                self.badpermpkgs[pkg] = []
                for line in outputlist:
                    # search for bad permissions
                    if re.search("^.*(\.+M|M\.+)", line, re.IGNORECASE):
                        sline = line.split()
                        self.badpermpkgs[pkg].append(sline[len(sline)-1])
                        self.badpermfiles.append(sline[len(sline)-1])
                    # search for bad group ownership
                    if re.search("^.*(\.+G|G\.+)", line, re.IGNORECASE):
                        sline = line.split()
                        self.badgroupfiles.append(sline[len(sline)-1])
                    # search for bad ownership (user)
                    if re.search("^.*(\.+U|U\.+)", line, re.IGNORECASE):
                        sline = line.split()
                        self.badownerfiles.append(sline[len(sline)-1])
                    # search for bad md5 hash
                    if re.search("^.*(\.+5|5\.+)", line, re.IGNORECASE):
                        sline = line.split()
                        self.badhashfiles.append(sline[len(sline)-1])

            if self.badpermfiles:
                self.compliant = False
                self.detailedresults += "\nThe following package files have incorrect permissions:\n" + "\n".join(self.badpermfiles)
            if self.badgroupfiles:
                self.compliant = False
                self.detailedresults += "\n\nThe following package files have bad group ownership:\n" + "\n".join(self.badgroupfiles)
            if self.badownerfiles:
                self.compliant = False
                self.detailedresults += "\n\nThe following package files have bad ownership:\n" + "\n".join(self.badownerfiles)
            if self.badhashfiles:
                self.compliant = False
                self.detailedresults += "\n\nThe following package files have bad MD5 checksums:\n" + "\n".join(self.badhashfiles)

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.detailedresults += traceback.format_exc()
            self.compliant = False
            self.logger.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)

        return self.compliant

    def fix(self):
        """The fix method changes permissions to the package defaults.


        :returns: self.rulesuccess

        :rtype: bool
@author: Eric Ball
@author: Breen Malmberg
@change: Breen Malmberg - 07/30/2018 - re-write of entire method

        """

        self.detailedresults = ""
        self.rulesuccess = True
        fixpermscmd = "/usr/bin/rpm --setperms "

        try:

            if not self.fixPermsCi.getcurrvalue():
                return self.rulesuccess

            for pkg in self.badpermpkgs:
                if self.badpermpkgs[pkg]:
                    self.ch.executeCommand(fixpermscmd + pkg)
                    retcode = self.ch.getReturnCode()
                    if retcode != 0:
                        errstr = self.ch.getErrorString()
                        self.rulesuccess = False
                        self.detailedresults += "\nFailed to set correct permissions on package: " + str(pkg)
                        self.logdispatch.log(LogPriority.DEBUG, errstr)

            self.detailedresults += "\n\nPlease note that we will not attempt to fix ownership, group ownership, or bad md5 checksums. For suggestions on what to do if files are found with these issues, please see the rule's help text."
            self.detailedresults += "\nIt is expected that this rule will still be non-compliant after fix if files are found with incorrect ownership or group ownership."

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)

        return self.rulesuccess
