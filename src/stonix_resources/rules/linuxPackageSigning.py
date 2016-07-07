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
Created on Jun 21, 2016

Package signing should always be enabled. On yum-based systems,
this can be checked by ensuring that all repos have gpgcheck=1 set.

@author: Breen Malmberg
'''

from __future__ import absolute_import

import re
import os
import traceback

from ..ruleKVEditor import RuleKVEditor
from ..KVEditorStonix import KVEditorStonix
from ..logdispatcher import LogPriority
from ..CommandHelper import CommandHelper


class linuxPackageSigning(RuleKVEditor):
    '''
    classdocs
    '''

    def __init__(self, config, environ, logger, statechglogger):
        '''
        Constructor
        '''
        RuleKVEditor.__init__(self, config, environ, logger, statechglogger)
        self.logger = logger
        self.environ = environ
        self.rulenumber = 145
        self.rootrequired = True
        self.mandatory = True
        self.rulename = 'linuxPackageSigning'
        self.formatDetailedResults("initialize")
        self.helptext = 'Package signing should always be enabled. On yum-based systems, this can be checked by ensuring \
that all repos have gpgcheck=1 set.'
        self.guidance = ['CNSSI 1253: cm-5(3)']

        # init CIs
        datatype = 'bool'
        key = 'linuxpackagesigning'
        instructions = 'If you wish to disable this rule, set the value of linuxpackagesigning to False.'
        default = True
        self.applicable = {'type': 'white',
                           'family': ['linux']}
        self.ci = self.initCi(datatype, key, instructions, default)

        self.localize()

    def localize(self):
        '''
        '''

        self.logger.log(LogPriority.DEBUG, "Running localize() method for linuxPackageSigning ...")

        self.ch = CommandHelper(self.logger)
        self.data = {}
        self.path = ""
        self.intent = ""
        self.type = ""
        self.conftype = ""
        self.temppath = ""
        self.rhel = False
        self.debian = False
        self.centos = False
        self.fedora = False
        self.suse = False
        self.ubuntu = False

        os = self.environ.getostype()

        # rhel, fedora, centos, ubuntu, debian, opensuse
        if re.search('red hat', os, re.IGNORECASE):
            self.setRhel()
        elif re.search('fedora', os, re.IGNORECASE):
            self.setFedora()
        elif re.search('centos', os, re.IGNORECASE):
            self.setCentos()
        elif re.search('debian', os, re.IGNORECASE):
            self.setDebian()
        elif re.search('ubuntu', os, re.IGNORECASE):
            self.setUbuntu()
        elif re.search('suse', os, re.IGNORECASE):
            self.setOpensuse()
        else:
            self.logger.log(LogPriority.DEBUG, "Unable to determine OS type.")

        if not self.data:
            self.logger.log(LogPriority.DEBUG, "KV config dictionary not set")
        if not self.path:
            self.logger.log(LogPriority.DEBUG, "KV config path not set")
        if not self.intent:
            self.logger.log(LogPriority.DEBUG, "KV config intent not set")
        if not self.type:
            self.logger.log(LogPriority.DEBUG, "KV config type not set")
        if not self.conftype:
            self.logger.log(LogPriority.DEBUG, "KV operand sign not set")

        if not self.suse:

            if self.path:
                self.temppath = self.path + '.stonixtmp'
            else:
                self.logger.log(LogPriority.DEBUG, "KV temporary path not set")

            self.intent = "present"
            self.type = "tagconf"

            self.kve = KVEditorStonix(self.statechglogger,
                                      self.logger, self.type,
                                      self.path, self.temppath,
                                      self.data, self.intent, self.conftype)

    def setRhel(self):
        '''
        '''

        self.rhel = True
        self.logger.log(LogPriority.DEBUG, "Detected OS as: Red Hat")

        self.data = {"main": {"gpgcheck": "1"}}
        self.path = "/etc/yum.conf"
        self.conftype = "openeq"

    def setFedora(self):
        '''
        '''

        self.fedora = True
        self.logger.log(LogPriority.DEBUG, "Detected OS as: Fedora")

        self.path = "/etc/dnf/dnf.conf"
        self.data = {"main": {"gpgcheck": "1"}}
        if not os.path.exists(self.path):
            self.path = "/etc/yum.conf"
        self.conftype = "openeq"

    def setCentos(self):
        '''
        '''

        self.centos = True
        self.logger.log(LogPriority.DEBUG, "Detected OS as: CentOS")

        self.data = {"main": {"gpgcheck": "1"}}
        self.path = "/etc/yum.conf"
        self.conftype = "openeq"

    def setUbuntu(self):
        '''
        '''

        self.ubuntu = True
        self.logger.log(LogPriority.DEBUG, "Detected OS as: Debian")
        self.logger.log(LogPriority.DEBUG, "Debian and Ubuntu do not sign their packages, thus setting debsig-verify would cause every package install to fail.")
        self.logger.log(LogPriority.DEBUG, "As a result of this, STONIX will not configure this system to enforce package signing.")

#         self.data = {}
#         self.path = ""
#         self.conftype = ""

    def setDebian(self):
        '''
        '''

        self.debian = True
        self.logger.log(LogPriority.DEBUG, "Detected OS as: Ubuntu")
        self.logger.log(LogPriority.DEBUG, "Debian and Ubuntu do not sign their packages, thus setting debsig-verify would cause every package install to fail.")
        self.logger.log(LogPriority.DEBUG, "As a result of this, STONIX will not configure this system to enforce package signing.")

#         self.data = {}
#         self.path = ""
#         self.conftype = ""

    def setOpensuse(self):
        '''
        '''

        self.suse = True
        self.logger.log(LogPriority.DEBUG, "Detected OS as: OpenSuSE")
        self.logger.log(LogPriority.DEBUG, "GPG Check is enabled by default on SuSE and there is no specific ability to enable it.")
        self.logger.log(LogPriority.DEBUG, "As a result of this, STONIX will only audit the status of the GPG check for each repo.")

        self.repolist = []
        cmd1 = "zypper lr -d"

        self.ch.executeCommand(cmd1)
        excode = self.ch.getReturnCode()
        if not excode: # if excode == 0 which means everything went fine..
            output = self.ch.getOutput()
            for line in output:
                sline = line.split("|")
                if re.search("^[0-9]", sline[0]) and re.search("yes", sline[3], re.IGNORECASE):
                    self.repolist.append(str(sline[0]))

    def report(self):
        '''
        '''

        self.detailedresults = ""
        self.compliant = True

        try:

            # STONIX will not enforce, nor check for enforcement
            # of package signing on debian or ubuntu, as they
            # do not sign their packages
            if self.ubuntu | self.debian:
                self.formatDetailedResults("report", self.compliant, self.detailedresults)
                return self.compliant
            if self.suse:
                if not self.reportSUSE():
                    self.compliant = False
                    self.formatDetailedResults("report", self.compliant, self.detailedresults)
                    return self.compliant
            else:
                if not self.kve.report():
                    self.compliant = False
                    self.detailedresults += 'The following required options ' + \
                            'are missing (or incorrect) from ' + \
                            str(self.path) + ':\n' + \
                            '\n'.join(str(f) for f in self.kve.fixables) + '\n'
                else:
                    self.detailedresults += "\nAll repositories have GPG checks enabled."

        except (SystemExit, KeyboardInterrupt):
            raise
        except Exception:
            self.detailedresults += traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant, self.detailedresults)
        return self.compliant

    def reportSUSE(self):
        '''
        '''

        retval = True
        cmd2 = "zypper lr"
        gpgenabled = False
        reponame = ""

        try:

            if self.repolist:
                for num in self.repolist:
                    self.ch.executeCommand(cmd2 + " " + str(num))
                    excode = self.ch.getReturnCode()
                    if not excode:
                        outputlines = self.ch.getOutput()
                        for line in outputlines:
                            if re.search("GPG\s*Check\s*\:\s*On", line, re.IGNORECASE):
                                gpgenabled = True
                            if re.search("Name\s*\:\s*", line, re.IGNORECASE):
                                sline = line.split(":")
                                reponame = str(sline[1]).strip()
                        if not gpgenabled:
                            retval = False
                            self.detailedresults += "GPG check is disabled for repo: " + reponame

            if retval:
                self.detailedresults += "\nAll currently enabled repositories have GPG checks enabled."

        except Exception:
            raise
        return retval

    def fix(self):
        '''
        '''

        self.detailedresults = ""
        success = True

        try:

            if self.ci.getcurrvalue():
                # STONIX will not enforce, nor check for enforcement
                # of package signing on debian or ubuntu, as they
                # do not sign their packages
                if self.ubuntu | self.debian:
                    pass
                elif self.suse:
                    pass
                elif self.kve.fix():
                    if not self.kve.commit():
                        success = False
                        self.logger.log(LogPriority.DEBUG, "There was a problem with kveditor commit()")
                        self.detailedresults += "There was a problem attempting to commit the file changes."
                else:
                    self.detailedresults += "There was a problem attempting to make file changes."
                    self.logger.log(LogPriority.DEBUG, "There was a problem with kveditor fix()")
                    success = False

        except (SystemExit, KeyboardInterrupt):
            raise
        except Exception:
            self.detailedresults += traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", success, self.detailedresults)
        return success
