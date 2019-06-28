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
Created on Nov 21, 2012

The CheckRootPath rule checks the root user's PATH environment variable,
ensuring that it is set to the vendor default and that there are no user or
world-writable files or directories in any of the path directories.

@author: Breen Malmberg
@change: 02/16/2014 Ekkehard Implemented self.detailedresults flow
@change: 02/16/2014 Ekkehard Implemented isapplicable
@change: 04/21/2013 Ekkehard Renamed from SecureRootPath to CheckRootPath
@change: 04/21/2014 Ekkehard remove ci as it is a report only rule
@change: 2015/04/14 Dave Kennel updated to use new isApplicable
@change: 2015/10/07 Eric Ball Help text cleanup
@change: 2016/04/01 Eric Ball Updated rule per RHEL 7 STIG, fixed inaccurate
    documentation and help text
@change: 2017/07/07 Ekkehard - make eligible for macOS High Sierra 10.13
@change: 2017/08/28 Ekkehard - Added self.sethelptext()
@change: 2017/11/13 Ekkehard - make eligible for OS X El Capitan 10.11+
@change: 2018/06/08 Ekkehard - make eligible for macOS Mojave 10.14
@change: 2019/03/12 Ekkehard - make eligible for macOS Sierra 10.12+
"""

from __future__ import absolute_import

import os
import re
import traceback

from ..rule import Rule
from ..KVEditorStonix import KVEditorStonix
from ..logdispatcher import LogPriority


class CheckRootPath(Rule):
    """
    The CheckRootPath rule checks the root user's PATH environment variable,
ensuring that it is set to the vendor default and that there are no user or
world-writable files or directories in any of the path directories.
    """

    def __init__(self, config, environ, logger, statechglogger):
        """
        private method to initialize the module

        :param config: configuration object instance
        :param environ: environment object instance
        :param logger: logdispatcher object instance
        :param statechglogger: statechglogger object instance
        """

        Rule.__init__(self, config, environ, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 44
        self.rulename = 'CheckRootPath'
        self.formatDetailedResults("initialize")
        self.compliant = False
        self.mandatory = True
        self.sethelptext()
        self.rootrequired = True
        self.guidance = ['NSA RHEL 2.3.4.1, 2.3.4.1.1, 2.3.4.1.2',
                         "CCE-RHEL7-CCE-TBD 2.4.1.1.7"]
        self.applicable = {'type': 'white',
                           'family': ['linux', 'solaris', 'freebsd'],
                           'os': {'Mac OS X': ['10.12', 'r', '10.14.10']}}

        # Configuration item instantiation
        datatype = "bool"
        key = "CHECKROOTPATH"
        instructions = "To disable this rule, set the value of " + \
                       "CHECKROOTPATH to false."
        default = True
        self.ci = self.initCi(datatype, key, instructions, default)

        if self.isapplicable():
            myos = self.environ.getostype().lower()
            self.myos = myos
            if re.search("os x", myos):
                defaultPath = "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
            elif re.search("opensuse", myos):
                defaultPath = "/sbin:/usr/sbin:/usr/local/sbin:/root/bin:" + \
                    "/usr/local/bin:/usr/bin:/bin:/usr/bin/X11:/usr/games"
            elif re.search("fedora|centos|red hat", myos):
                defaultPath = "/usr/local/sbin:/usr/local/bin:/sbin:/bin:" + \
                    "/usr/sbin:/usr/bin:/root/bin"
            else:
                defaultPath = "/usr/local/sbin:/usr/local/bin:/sbin:/bin:" + \
                    "/usr/sbin:/usr/bin"
            self.defaultPath = defaultPath

    def report(self):
        """The report method examines the current configuration and determines
        whether or not it is correct. If the config is correct then the
        self.compliant, self.detailedresults and self.currstate properties are
        updated to reflect the system status. self.rulesuccess will be updated
        if the rule does not succeed.

        :return: self.compliant - True if compliant; False if not
        :rtype: bool

        """

        try:
            compliant = True
            self.detailedresults = ""
            self.vendorDefault = True
            wwList = []
            defaultPath = self.defaultPath
            path = os.environ['PATH']

            if not re.search(defaultPath, path):
                compliant = False
                self.vendorDefault = False
                self.detailedresults += "root's PATH variable is not set " + \
                    "to the vendor default\n"

            exPaths = path.split(":")
            self.logger.log(LogPriority.DEBUG,
                            "PATH entries: " + str(exPaths))
            for exPath in exPaths:
                if not os.path.exists(exPath):
                    continue
                pathEntries = os.listdir(exPath)
                for entry in pathEntries:
                    absPath = exPath + "/" + entry
                    if not os.path.exists(absPath):
                        continue
                    entryStat = os.stat(absPath)
                    userMode = oct(entryStat.st_mode)[-1]
                    if userMode == "7" or userMode == "6" or userMode == "2":
                        compliant = False
                        wwList.append(absPath)
                        self.detailedresults += "World-writeable entry " + \
                            "found at: " + absPath + "\n"

            self.compliant = compliant
        except (OSError):
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.DEBUG, self.detailedresults)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception, err:
            self.rulesuccess = False
            self.detailedresults = self.detailedresults + "\n" + str(err) + \
                " - " + str(traceback.format_exc())
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

    def fix(self):
        """set root's default PATH environment variable to vendor default

        :return: self.rulesucces - True if fix succeeds; False if not
        :rtype: bool

        """

        try:
            self.detailedresults = ""
            if not self.ci.getcurrvalue():
                return
            success = True

            if not self.vendorDefault:
                os.environ['PATH'] = self.defaultPath
                if re.search("darwin", self.myos):
                    root = "/var/root/"
                else:
                    root = "/root/"
                checkFiles = [root + ".profile", root + ".bashrc"]
                for checkFile in checkFiles:
                    if not os.path.exists(checkFile):
                        open(checkFile, "w")
                    tmppath = checkFile + ".tmp"
                    data = {"PATH": self.defaultPath}
                    self.editor = KVEditorStonix(self.statechglogger,
                                                 self.logger, "conf",
                                                 checkFile, tmppath, data,
                                                 "present", "closedeq")
                    if not self.editor.report():
                        if self.editor.fix():
                            if not self.editor.commit():
                                success = False
                                self.detailedresults += "Failed to commit " + \
                                    "changes to " + checkFile + "\n"
                        else:
                            success = False
                            self.detailedresults += "Error fixing file " + \
                                checkFile + "\n"

            self.rulesuccess = success

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)

        return self.rulesuccess
