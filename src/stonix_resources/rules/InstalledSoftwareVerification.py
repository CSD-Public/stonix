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
Verify package integrity, correct permissions
@author: Eric Ball
@change: 2015/08/04 eball - Original implementation
@change: 2015/08/24 eball - Improve output, remove .pyc files from output
@change: 2016/04/20 eball - Per RHEL 7 STIG, added a fix to automate correction
    of file permissions
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
        self.helptext = '''This rule will check the integrity of \
the installed software on this system. Since the results of these tests are \
heavily dependent on user configuration, the only changes made to the \
system are to correct permissions.

PLEASE NOTE: This rule invokes the "rpm -Va" command, which can take several \
minutes to complete.

SUGGESTED CORRECTIVE ACTIONS:
For files with bad user/group ownership:
For each file listed in the report output, run the following command as root:
# rpm --setugids `rpm -qf [filename]`
This will attempt to return the user and group ownership to the package \
defaults.

For files with changed permissions:
The Fix for this rule will automatically change the permissions for the \
package that each file is a part of back to the vendor defaults.

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
        self.guidance = ['NSA 2.1.3.2', 'CCE 14931-0',
                         'CCE-RHEL7-CCE-TBD 2.1.3.2.1']
        self.applicable = {'type': 'white',
                           'os': {'Red Hat Enterprise Linux': ['6.0', '+'],
                                  'CentOS Linux': ['7.0', '+'],
                                  'Fedora': ['21', '+']}}

        datatype = 'bool'
        key = 'FIXPERMISSIONS'
        instructions = '''If set to True, this rule will fix the permissions \
of the package for any file which has a permission deviation from the vendor \
default.'''
        default = True
        self.fixPermsCi = self.initCi(datatype, key, instructions, default)

        self.ch = CommandHelper(self.logger)
        self.reportRun = False
        self.ownerErr = []
        self.groupErr = []
        self.permErr = []
        self.hashErr = []
        self.packagesFixed = []

    def report(self):
        '''
        @author: Eric Ball
        @param self - essential if you override this definition
        @return: bool - True if system is compliant, False if it isn't
        '''
        try:
            self.detailedresults = ""
            results = ""

            if self.reportRun:
                ownerErr = self.ownerErr
                groupErr = self.groupErr
                # Using the list[:] syntax to force assignment of value rather
                # than reference
                permErr = self.permErr[:]
                hashErr = self.hashErr

                for fileName in permErr:
                    cmd = ["rpm", "-qf", fileName]
                    self.ch.executeCommand(cmd)
                    packageName = self.ch.getOutputString()
                    cmd = ["rpm", "-V", packageName, "--nodigest",
                           "--nosignature", "--nolinkto", "--nofiledigest",
                           "--nosize", "--nouser", "--nogroup", "--nomtime",
                           "--nordev", "--nocaps"]
                    self.ch.executeCommand(cmd)
                    if self.ch.getReturnCode() == 0:
                        # Remove from self.permErr so we don't mess with the
                        # loop index
                        self.permErr.remove(fileName)
                permErr = self.permErr

            else:
                cmd = ["rpm", "-Va"]
                self.ch.executeCommand(cmd)
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

            self.ownerErr = ownerErr
            self.groupErr = groupErr
            self.permErr = permErr
            self.hashErr = hashErr

            self.compliant = not bool(ownerErr + groupErr + permErr + hashErr)
            self.rulesuccess = True
            self.reportRun = True
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

    def fix(self):
        """
        The fix method changes permissions to the package defaults.

        @author: Eric Ball
        @param self - essential if you override this definition
        @return: bool - True if fix is successful, False if it isn't
        """
        try:
            success = True
            self.detailedresults = ""

            if self.fixPermsCi.getcurrvalue():
                permErr = self.permErr
                packagesFixed = []

                for fileName in permErr:
                    cmd = ["rpm", "-qf", fileName]
                    self.ch.executeCommand(cmd)
                    packageName = self.ch.getOutputString()
                    if packageName not in packagesFixed:
                        packagesFixed.append(packageName)
                        cmd = ["rpm", "--setperms", packageName]
                        self.ch.executeCommand(cmd)
                        # Rule succeeds only if all return codes are 0
                        success &= not bool(self.ch.getReturnCode())

            self.rulesuccess = success
        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception, err:
            self.rulesuccess = False
            self.detailedresults = self.detailedresults + "\n" + str(err) + \
                " - " + str(traceback.format_exc())
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.rulesuccess
