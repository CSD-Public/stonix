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
Created on 2015/08/04
Report-only rule to verify package integrity
@author: Eric Ball
@change: 2015/08/04 eball - Original implementation
@change: 2015/08/24 eball - Improve output, remove .pyc files from output
'''

from __future__ import absolute_import
import re
import traceback
from ..rule import Rule
from ..logdispatcher import LogPriority
from ..CommandHelper import CommandHelper


class InstalledSoftwareVerification(Rule):

    def __init__(self, config, environ, logger, statechglogger):
        '''
        Constructor
        '''
        Rule.__init__(self, config, environ, logger, statechglogger)
        self.config = config
        self.environ = environ
        self.logger = logger
        self.statechglogger = statechglogger
        self.rulenumber = 230
        self.rulename = 'InstalledSoftwareVerification'
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.helptext = '''This report-only rule will check the integrity of \
the installed software on this system. Since the results of these tests are \
heavily dependent on user configuration, no changes will be made to the system.

PLEASE NOTE: This rule invokes the "rpm -Va" command, which can take several \
minutes to complete.

SUGGESTED CORRECTIVE ACTIONS:
For files with bad user/group ownership:
For each file listed in the report output, run the following command as root:
# rpm --setugids `rpm -qf [filename]`
This will attempt to return the user and group ownership to the package \
defaults.

For files with changed permissions:
To find the expected permissions for the file, begin by running the following \
command as root:
# rpm -qf [filename]
This will output the [package] name. It can also be run in backticks \
(`rpm -qf [filename]`) in place of [package] in the following commands.
Next, run:
# rpm -q --queryformat "[%{FILENAMES} %{FILEMODES:perms}\\n]" [package] | \
grep [filename]
You can then compare the result of this to the current permissions by running:
# ls -alL [filename]
If the current permissions are more permissive, you can correct them by \
running:
# rpm --setperms [package]

For files with changed hashes:
If you believe that the file's hash has changed due to corruption or \
malicious activity, begin by running the following command as root:
# rpm -qf [filename]
This will output the [package] name. It can also be run in backticks \
(`rpm -qf [filename]`) in place of [package] in the following commands.
Next, run:
# rpm -Uvh [package]
OR
# yum reinstall [package]
'''
        self.rootrequired = True
        self.guidance = ['NSA 2.1.3.2', 'CCE 14931-0']
        self.applicable = {'type': 'white',
                           'os': {'Red Hat Enterprise Linux': ['6.0', '+'],
                                  'CentOS Linux': ['7.0', '+'],
                                  'Fedora': ['21', '+']}}
        self.ch = CommandHelper(self.logger)

    def report(self):
        '''
        @author: Eric Ball
        @param self - essential if you override this definition
        @return: bool - True if system is compliant, False if it isn't
        '''
        try:
            cmd = ["rpm", "-Va"]
            self.ch.executeCommand(cmd)
            results = ""
            rpmout = self.ch.getOutputString()
            rpmoutlines = rpmout.split("\n")
            ownerErr = []
            groupErr = []
            permErr = []
            hashErr = []
            for line in rpmoutlines:
                words = line.split()
                if len(words) >= 2:
                    if re.search("^.....U", line):
                        if not re.search(".pyc$", words[-1]):
                            ownerErr.append(words[-1])
                    if re.search("^......G", line):
                        if not re.search(".pyc$", words[-1]):
                            groupErr.append(words[-1])
                    if re.search("^.M", line):
                        if not re.search(".pyc$", words[-1]):
                            permErr.append(words[-1])
                    if re.search("^..5", line):
                        if not re.search(".pyc$", words[-1]) \
                           and words[1] != 'c':
                            hashErr.append(words[-1])

            if len(ownerErr) > 0:
                results += "Files with bad user ownership:\n"
                for line in ownerErr:
                    results += line + "\n"
                results += "\n"
            if len(groupErr) > 0:
                results += "Files with bad group ownership:\n"
                for line in groupErr:
                    results += line + "\n"
                results += "\n"

            if len(permErr) > 0:
                results += "Files with changed permissions:\n"
                for line in permErr:
                    results += line + "\n"
                results += "\n"

            if len(hashErr) > 0:
                results += "Files with changed hashes (excluding those " + \
                    "marked as config files in their RPM):\n"
                for line in hashErr:
                    results += line + "\n"
                results += "\n"

            if len(results) > 0:
                instr = "For suggested corrective actions, see help text.\n"
                results = instr + results
            self.detailedresults = results
            self.rulesuccess = True
        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception:
            self.detailedresults = self.detailedresults + \
                traceback.format_exc()
            self.rulesuccess = False
            self.logger.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant
