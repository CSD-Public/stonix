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
Created on Nov 21, 2012

The CheckRootPath rule checks the root user's PATH environment variable,
ensuring that it is set to the vendor default and that there are no user or
world-writable files or directories in any of the path directories.

@author: bemalmbe
@change: 02/16/2014 ekkehard Implemented self.detailedresults flow
@change: 02/16/2014 ekkehard Implemented isapplicable
@change: 04/21/2013 ekkehard Renamed from SecureRootPath to CheckRootPath
@change: 04/21/2014 ekkehard remove ci as it is a report only rule
@change: 2015/04/14 dkennel updated to use new isApplicable
@change: 2015/10/07 eball Help text cleanup
@change: 2016/04/01 eball Updated rule per RHEL 7 STIG, fixed inaccurate
    documentation and help text
'''

from __future__ import absolute_import
import os
import re
import traceback

from ..rule import Rule
from ..KVEditorStonix import KVEditorStonix
from ..logdispatcher import LogPriority


class CheckRootPath(Rule):
    '''
    @author bemalmbe
    '''

    def __init__(self, config, environ, logger, statechglogger):
        '''
        Constructor
        '''

        Rule.__init__(self, config, environ, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 44
        self.rulename = 'CheckRootPath'
        self.formatDetailedResults("initialize")
        self.compliant = False
        self.mandatory = True
        self.helptext = '''This rule ensures that the root user's PATH \
environment variable is set to the vendor default, and checks all directories \
in the PATH for user/world-writable entries. If user/world-writable entries \
are found, it is left up to the system administrator to correct these \
entries.'''
        self.rootrequired = True
        self.guidance = ['NSA RHEL 2.3.4.1, 2.3.4.1.1, 2.3.4.1.2',
                         "CCE-RHEL7-CCE-TBD 2.4.1.1.7"]
        self.applicable = {'type': 'white',
                           'family': ['linux', 'solaris', 'freebsd'],
                           'os': {'Mac OS X': ['10.9', 'r', '10.12.10']}}

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
        '''
        The report method examines the current configuration and determines
        whether or not it is correct. If the config is correct then the
        self.compliant, self.detailedresults and self.currstate properties are
        updated to reflect the system status. self.rulesuccess will be updated
        if the rule does not succeed.

        @return: bool
        @author bemalmbe
        '''
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
            # User initiated exit
            raise
        except Exception, err:
            self.rulesuccess = False
            self.detailedresults = self.detailedresults + "\n" + str(err) + \
                " - " + str(traceback.format_exc())
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

    def fix(self):
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
