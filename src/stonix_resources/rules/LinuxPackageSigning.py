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
Created on Jun 21, 2016

Package signing should always be enabled. On yum-based systems,
this can be checked by ensuring that all repos have gpgcheck=1 set.

@author: Breen Malmberg
@change: 2016/09/12 eball PEP8 cleanup, changed isapplicable from blacklist
    to whitelist, removed redundant CentOS setup, changed KVEditor from
    openeq to closedeq
@change: 2016/09/13 eball Added undo event to KVEditor, and clearing old events
'''



import re
import os
import traceback

from ruleKVEditor import RuleKVEditor
from KVEditorStonix import KVEditorStonix
from logdispatcher import LogPriority
from CommandHelper import CommandHelper


class LinuxPackageSigning(RuleKVEditor):
    """

    """

    def __init__(self, config, environ, logger, statechglogger):
        """

        :param config: 
        :param environ: 
        :param logger: 
        :param statechglogger: 
        """

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
        self.ci = self.initCi(datatype, key, instructions, default)
        self.ostype = self.environ.getostype()
        self.applicable = self.isapplicable()

        self.localize()

    def isapplicable(self):
        """override of normal isapplicable()


        :return: retval
        :rtype: bool

        """

        retval = False

        if re.search('centos|fedora|red hat|suse', self.ostype.lower(), re.I):
            retval = True

        return retval

    def localize(self):
        """

        :return: 
        """

        self.ch = CommandHelper(self.logger)
        self.rhel = False
        self.fedora = False
        self.suse = False

        # rhel, fedora, centself.ostype, opensuse
        if re.search('red hat|centos', self.ostype.lower(), re.I):
            self.setRhel()
        elif re.search('fedora', self.ostype.lower(), re.I):
            self.setFedora()
        elif re.search('suse', self.ostype.lower(), re.I):
            self.setOpensuse()
        else:
            self.logger.log(LogPriority.DEBUG, "Unable to determine OS type.")

        self.setup_yum()

    def setOpensuse(self):
        """

        :return:
        """

        self.suse = True

        self.repolist = []
        cmd1 = "/usr/bin/zypper lr -d"

        self.ch.executeCommand(cmd1)
        retcode = self.ch.getReturnCode()
        if not retcode:  # if retcode == 0 which means everything went fine..
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

    def setup_yum(self):
        """

        :return:
        """

        self.yum_conf_dict = {"gpgcheck": "1",
                              "localpckg_gpgcheck": "1"}
        self.yum_conf_file = ""
        yum_conf_files = ["/etc/yum.conf", "/etc/dnf/dnf.conf"]
        for f in yum_conf_files:
            if os.path.isfile(f):
                self.yum_conf_file = f
                break

    def report_yum(self):
        """

        :return:
        """

        compliant = True

        tmppath = self.yum_conf_file + ".stonixtmp"
        self.yum_conf_editor = KVEditorStonix(self.statechglogger, self.logger, "conf", self.yum_conf_file, tmppath, self.yum_conf_dict, "present", "closedeq")
        if not self.yum_conf_editor.report():
            compliant = False
            self.detailedresults += "\nThe following configuration options are incorrect in " + str(self.yum_conf_file) + ":\n" + "\n".join(self.yum_conf_editor.fixables)

        return compliant

    def report(self):
        """

        :return:
        """

        self.detailedresults = ""
        self.compliant = True

        try:

            if self.suse:
                if not self.reportSUSE():
                    self.compliant = False
            else:
                if not self.report_yum():
                    self.compliant = False

            if self.compliant:
                self.detailedresults += "\nAll repositories have signing enabled"

        except (SystemExit, KeyboardInterrupt):
            raise
        except Exception:
            self.detailedresults += traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

    def reportSUSE(self):
        """

        :return: 
        """

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
                            if re.search("GPG\s*Check\s*\:.*(On|Yes)", line, re.I):
                                gpgenabled = True
                            if re.search("Name\s*\:\s*", line, re.I):
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

    def fix_yum(self):
        """

        :return:
        """

        success = True

        if not self.yum_conf_editor.fix():
            success = False
            self.logger.log(LogPriority.DEBUG, "yum conf editor fix failed")
        elif not self.yum_conf_editor.commit():
            success = False
            self.logger.log(LogPriority.DEBUG, "yum conf editor commit failed")

        return success

    def fix(self):
        """

        :return: self.rulesuccess
        :rtype: bool
        """

        self.detailedresults = ""
        self.rulesuccess = True
        self.iditerator = 0

        # Clear event history
        eventlist = self.statechglogger.findrulechanges(self.rulenumber)
        for event in eventlist:
            self.statechglogger.deleteentry(event)

        try:
            if self.ci.getcurrvalue():

                if self.suse:
                    self.logger.log(LogPriority.DEBUG, "Fix not applicable to this platform")
                elif not self.fix_yum():
                    self.rulesuccess = False

        except (SystemExit, KeyboardInterrupt):
            raise
        except Exception:
            self.detailedresults += traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)

        return self.rulesuccess
