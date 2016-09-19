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
from ..stonixutilityfunctions import iterate


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
        self.helptext = 'Package signing should always be enabled. On ' + \
            'yum-based systems, this can be checked by ensuring that all ' + \
            'repos have gpgcheck=1 set.'
        self.guidance = ['CNSSI 1253: cm-5(3)']

        # init CIs
        datatype = 'bool'
        key = 'LinuxPackageSigning'
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
        osfamily = self.environ.getosfamily()

        if re.search('centos|fedora|red hat|suse', osfamily, re.IGNORECASE):
            retval = True

        return retval

    def localize(self):
        '''
        '''

        self.logger.log(LogPriority.DEBUG, "Running localize() method for " +
                        "LinuxPackageSigning ...")

        self.ch = CommandHelper(self.logger)
        self.data = {}
        self.path = ""
        self.intent = ""
        self.type = ""
        self.conftype = ""
        self.temppath = ""
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

        if not self.suse:
            if not self.data:
                self.logger.log(LogPriority.DEBUG,
                                "KV config dictionary not set")
            if not self.path:
                self.logger.log(LogPriority.DEBUG, "KV config path not set")
            if not self.intent:
                self.logger.log(LogPriority.DEBUG, "KV config intent not set")
            if not self.type:
                self.logger.log(LogPriority.DEBUG, "KV config type not set")
            if not self.conftype:
                self.logger.log(LogPriority.DEBUG, "KV operand sign not set")

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
        self.conftype = "closedeq"

    def setFedora(self):
        '''
        '''

        self.fedora = True
        self.logger.log(LogPriority.DEBUG, "Detected OS as: Fedora")

        self.path = "/etc/dnf/dnf.conf"
        self.data = {"main": {"gpgcheck": "1"}}
        if not os.path.exists(self.path):
            self.path = "/etc/yum.conf"
        self.conftype = "closedeq"

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
                    self.formatDetailedResults("report", self.compliant,
                                               self.detailedresults)
                    return self.compliant
            else:
                if not self.kve.report():
                    self.compliant = False
                    self.detailedresults += 'The following required ' + \
                        'options are missing (or incorrect) from ' + \
                        str(self.path) + ':\n' + \
                        '\n'.join(str(f) for f in self.kve.fixables) + '\n'
                else:
                    self.detailedresults += "\nAll repositories have GPG " + \
                        "checks enabled."

        except (SystemExit, KeyboardInterrupt):
            raise
        except Exception:
            self.detailedresults += traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant,
                                   self.detailedresults)
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
                                "for repo: " + reponame
            else:
                self.detailedresults += "\nUnable to locate any " + \
                    "repositories on this system!"

            if retval:
                self.detailedresults += "\nAll currently enabled " + \
                    "repositories have GPG checks enabled."

        except Exception:
            raise
        return retval

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
                    self.detailedresults += "\nGPG Check is enabled by " + \
                        "default on SuSE and there is no specific ability " + \
                        "to enable it."
                    self.detailedresults += "\nAs a result of this, " + \
                        "STONIX will only audit the status of the GPG " + \
                        "check for each repo."
                elif self.kve.fix():
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    self.kve.setEventID(myid)
                    if not self.kve.commit():
                        success = False
                        self.logger.log(LogPriority.DEBUG, "There was a " +
                                        "problem with kveditor commit()")
                        self.detailedresults += "There was a problem " + \
                            "attempting to commit the file changes."
                else:
                    self.detailedresults += "There was a problem " + \
                        "attempting to make file changes."
                    self.logger.log(LogPriority.DEBUG,
                                    "There was a problem with kveditor fix()")
                    success = False

        except (SystemExit, KeyboardInterrupt):
            raise
        except Exception:
            self.detailedresults += traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", success, self.detailedresults)
        return success
