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
Created on Jun 21, 2016

Package signing should always be enabled. On yum-based systems,
this can be checked by ensuring that all repos have gpgcheck=1 set.

@author: Breen Malmberg
@change: 2016/09/12 eball PEP8 cleanup, changed isapplicable from blacklist
    to whitelist, removed redundant CentOS setup, changed KVEditor from
    openeq to closedeq
@change: 2016/09/13 eball Added undo event to KVEditor, and clearing old events
'''

from __future__ import absolute_import

import re
import os
import traceback

from ..ruleKVEditor import RuleKVEditor
from ..KVEditorStonix import KVEditorStonix
from ..logdispatcher import LogPriority
from ..CommandHelper import CommandHelper
from ..stonixutilityfunctions import iterate, readFile, writeFile, resetsecon


class LinuxPackageSigning(RuleKVEditor):
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
        self.rulename = 'LinuxPackageSigning'
        self.formatDetailedResults("initialize")
        self.sethelptext()
        self.guidance = ['CNSSI 1253: cm-5(3)']

        # init CIs
        datatype = 'bool'
        key = 'LINUXPACKAGESIGNING'
        instructions = 'If you wish to disable this rule, set the value ' + \
            'of LinuxPackageSigning to False.'
        default = True
        self.applicable = self.isapplicable()
        self.ci = self.initCi(datatype, key, instructions, default)

        self.localize()

    def isapplicable(self):
        '''
        override of normal isapplicable()

        @return: retval
        @rtype: bool
        @author: Breen Malmberg
        @change: 2016/09/12 eball Changed from blacklist to whitelist
        '''
        retval = False
        ostype = self.environ.getostype()

        if re.search('centos|fedora|red hat|suse', ostype, re.IGNORECASE):
            retval = True

        return retval

    def localize(self):
        '''
        '''

        self.logger.log(LogPriority.DEBUG, "Running localize() method for " +
                        "LinuxPackageSigning ...")

        self.ch = CommandHelper(self.logger)
        self.rhel = False
        self.fedora = False
        self.suse = False

        os = self.environ.getostype()

        # rhel, fedora, centos, opensuse
        if re.search('red hat|centos', os, re.IGNORECASE):
            self.setRhel()
        elif re.search('fedora', os, re.IGNORECASE):
            self.setFedora()
        elif re.search('suse', os, re.IGNORECASE):
            self.setOpensuse()
        else:
            self.logger.log(LogPriority.DEBUG, "Unable to determine OS type.")

    def setRhel(self):
        '''
        '''
        self.rhel = True
        self.logger.log(LogPriority.DEBUG, "Detected OS as: Red Hat")

        self.repos = ["/etc/yum.conf"]
        repos = os.listdir("/etc/yum.repos.d")
        for repo in repos:
            self.repos.append("/etc/yum.repos.d/" + repo)

    def setFedora(self):
        '''
        '''
        self.fedora = True
        self.logger.log(LogPriority.DEBUG, "Detected OS as: Fedora")

        path = "/etc/dnf/dnf.conf"
        if not os.path.exists(path):
            path = "/etc/yum.conf"

        self.repos = [path]
        repos = os.listdir("/etc/yum.repos.d")
        for repo in repos:
            self.repos.append("/etc/yum.repos.d/" + repo)

    def setOpensuse(self):
        '''
        '''

        self.suse = True
        self.logger.log(LogPriority.DEBUG, "Detected OS as: OpenSuSE")
        self.logger.log(LogPriority.DEBUG, "GPG Check is enabled by default " +
                        "on SuSE and there is no specific ability to " +
                        "enable it.")
        self.logger.log(LogPriority.DEBUG, "As a result of this, STONIX " +
                        "will only audit the status of the GPG check for " +
                        "each repo.")

        self.repolist = []
        cmd1 = "/usr/bin/zypper lr -d"

        self.ch.executeCommand(cmd1)
        excode = self.ch.getReturnCode()
        if not excode:  # if excode == 0 which means everything went fine..
            output = self.ch.getOutput()
            for line in output:
                sline = line.split("|")
                if len(sline) >= 4:
                    if re.search("^\s*[0-9]+", sline[0]) and \
                       re.search("yes", sline[3], re.IGNORECASE):
                        self.logger.log(LogPriority.DEBUG,
                                        "\n\nFound active repo. Tracking " +
                                        "repo number: " + sline[0].strip())
                        self.repolist.append(sline[0].strip())

    def report(self):
        '''
        '''
        self.detailedresults = ""
        self.compliant = True

        try:
            if self.suse:
                if not self.reportSUSE():
                    self.compliant = False
            else:
                if not self.reportYumRepos():
                    self.compliant = False
                if self.compliant:
                    self.detailedresults += "All repositories have GPG " + \
                        "checks enabled.\n"

        except (SystemExit, KeyboardInterrupt):
            raise
        except Exception:
            self.detailedresults += traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

    def reportSUSE(self):
        '''
        '''

        retval = True
        cmd2 = "/usr/bin/zypper lr"
        gpgenabled = False
        reponame = ""

        try:

            if self.repolist:
                self.logger.log(LogPriority.DEBUG, "Found: " +
                                str(len(self.repolist)) +
                                " active repositories on this system.")
                for num in self.repolist:
                    self.ch.executeCommand(cmd2 + " " + str(num))
                    excode = self.ch.getReturnCode()
                    if not excode:
                        outputlines = self.ch.getOutput()
                        for line in outputlines:
                            if re.search("GPG\s*Check\s*\:.*(On|Yes)", line,
                                         re.IGNORECASE):
                                gpgenabled = True
                            if re.search("Name\s*\:\s*", line, re.IGNORECASE):
                                sline = line.split(":")
                                reponame = str(sline[1]).strip()
                        if not gpgenabled:
                            retval = False
                            self.detailedresults += "GPG check is disabled " + \
                                "for repo: " + reponame + "\n"
            else:
                self.detailedresults += "Unable to locate any " + \
                    "repositories on this system!\n"

            if retval:
                self.detailedresults += "All currently enabled " + \
                    "repositories have GPG checks enabled.\n"

        except Exception:
            raise
        return retval

    def reportYumRepos(self):
        compliant = True
        for repo in self.repos:
            repoFile = readFile(repo, self.logger)
            for line in repoFile:
                if re.search("^gpgcheck=0", line):
                    compliant = False
                    self.detailedresults += "gpgcheck=0 found in repo file " + \
                        repo + "\n"
                    break
        return compliant

    def fix(self):
        '''
        '''

        self.detailedresults = ""
        success = True
        self.iditerator = 0

        # Clear event history
        self.iditerator = 0
        eventlist = self.statechglogger.findrulechanges(self.rulenumber)
        for event in eventlist:
            self.statechglogger.deleteentry(event)

        try:
            if self.ci.getcurrvalue():
                if self.suse:
                    self.detailedresults += "GPG Check is enabled by " + \
                        "default on SuSE and there is no specific ability " + \
                        "to enable it.\n"
                    self.detailedresults += "As a result of this, " + \
                        "STONIX will only audit the status of the GPG " + \
                        "check for each repo.\n"
                elif not self.fixYumRepos():
                    success = False
            self.rulesuccess = success

        except (SystemExit, KeyboardInterrupt):
            raise
        except Exception:
            self.detailedresults += traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", success, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.rulesuccess

    def fixYumRepos(self):
        success = True
        for repo in self.repos:
            repoFile = readFile(repo, self.logger)
            tmpFile = []
            changed = False
            for line in repoFile:
                if re.search("^gpgcheck=0", line):
                    gpgLine = re.sub("gpgcheck=0", "gpgcheck=1", line)
                    tmpFile.append(gpgLine)
                    changed = True
                else:
                    tmpFile.append(line)
            if changed:
                tmppath = repo + ".stonixtmp"
                if not writeFile(tmppath, "".join(tmpFile), self.logger):
                    success = False
                    self.detailedresults += "Could not write to " + tmppath + \
                        "\n"
                else:
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    event = {"eventtype": "conf", "filepath": repo}
                    self.statechglogger.recordchgevent(myid, event)
                    self.statechglogger.recordfilechange(repo, tmppath, myid)
                    os.rename(tmppath, repo)
                    resetsecon(repo)
        return success
