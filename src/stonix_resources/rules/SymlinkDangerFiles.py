###############################################################################
#                                                                             #
# Copyright 2015-2017.  Los Alamos National Security, LLC. This material was  #
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
Created on Oct 24, 2012
The Symlink Dangerous Files class checks for the presence of certain files -
namely /root/.rhosts, /root/.shosts, and /etc/hosts.equiv, and symlinks them to
/dev/null in order to prevent a potentially exploitable weak form of access
control.

@author: Breen Malmberg
@change: 02/16/2014 ekkehard Implemented self.detailedresults flow
@change: 02/16/2014 ekkehard Implemented isapplicable
@change: 02/16/2014 ekkehard blacklisted darwin '/dev/null' and /root/.rhosts, /root/.shosts do
@change: 04/18/2014 ekkehard ci updates and ci fix method implementation
@change: 2014/08/11 ekkehard fixed isApplicable
@change: 2015/04/17 dkennel updated for new isApplicable
@change: 2015/10/08 eball Help text cleanup
@change: 2017/07/17 ekkehard - make eligible for macOS High Sierra 10.13
@change: 2017/11/13 ekkehard - make eligible for OS X El Capitan 10.11+
'''

from __future__ import absolute_import

import os
import traceback
import re

from ..rule import Rule
from ..logdispatcher import LogPriority


class SymlinkDangerFiles(Rule):
    '''
    The Symlink Dangerous Files class checks for the presence of certain files
    - namely /root/.rhosts, /root/.shosts, and /etc/hosts.equiv, and symlinks
    them to /dev/null in order to prevent a potentially exploitable weak form
    of access control.

    @author Breen Malmberg
    '''
    # do we need @author section for each method? or is ok for just the class?
    def __init__(self, config, environ, logger, statechglogger):
        '''
        Constructor
        '''
        Rule.__init__(self, config, environ, logger, statechglogger)
        self.config = config
        self.environ = environ
        self.logger = logger
        self.statechglogger = statechglogger
        self.rulenumber = 52
        self.rulename = 'SymlinkDangerFiles'
        self.formatDetailedResults("initialize")
        self.compliant = False
        self.mandatory = True
        self.sethelptext()
        self.rootrequired = True
        self.guidance = ['CIS RHEL 5 Benchmark Appendix A SN.1']
        self.applicable = {'type': 'white',
                           'family': ['linux', 'solaris', 'freebsd'],
                           'os': {'Mac OS X': ['10.11', 'r', '10.13.10']}}

        # init CIs
        self.ci = self.initCi("bool",
                              "SYMLINKDANGERFILES",
                              "Execute Symlink Danger Files fix.",
                              True)
        self.symlinkfiles = ['/root/.rhosts', '/root/.shosts', '/etc/shosts.equiv']
        self.blankfiles = ['/private/etc/hosts.equiv', '/etc/hosts.equiv']

    def fix(self):
        '''
        The fix method will apply the required settings to the system.
        self.rulesuccess will be updated if the rule does not succeed.
        Search for the rhosts, shosts and hosts.equiv and if found, delete
        them and then symlink them to /dev/null

        @author Breen Malmberg
        '''

        # defaults
        self.rulesuccess = True
        self.detailedresults = ""

        try:

            if self.ci.getcurrvalue():

                self.makeHostsBlank()

                for item in self.symlinkfiles:
                    if os.path.exists(item):
                        os.remove(item)
                        os.symlink('/dev/null', item)
                        if self.detailedresults == "":
                            self.detailedresults = "Removed " + str(item) + \
                            " and added symbolic link to '/dev/null'"
                        else:
                            self.detailedresults = self.detailedresults + \
                            "\r" + "Removed " + str(item) + \
                            " and added symbolic link to '/dev/null'"
            else:
                self.detailedresults = str(self.ci.getkey()) + \
                " was disabled. No action was taken."
        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception as err:
            self.rulesuccess = False
            self.detailedresults = self.detailedresults + "\n" + str(err) + \
            " - " + str(traceback.format_exc())
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.rulesuccess

    def makeHostsBlank(self):
        '''
        ensure that there is no content (except for commented lines)
        in hosts.equiv

        @author: Breen Malmberg
        '''

        stonixline = "# This file enforced to be blank, by STONIX"

        try:

            for f in self.blankfiles:
                if os.path.exists(f):

                    tempfile = f + '.stonixtmp'

                    tf = open(f, 'w')
                    tf.write(stonixline)
                    tf.close()

                    os.rename(tempfile, f)
                    os.chmod(f, 0644)

        except Exception:
            raise

    def report(self):
        '''
        Perform a check to see if the files (.rhosts, .shosts) are
        already symlinked to /dev/null or not

        @return bool
        @author Breen Malmberg
        '''

        # defaults
        self.compliant = True
        self.detailedresults = ""

        try:

            if not self.checkHostsBlank():
                self.compliant = False

            for item in self.symlinkfiles:
                message = ""
                if os.path.exists(item):

                    if not os.path.islink(item):
                        self.compliant = False
                        message = str(item) + " is not a link"
                    else:
                        if os.readlink(item) != '/dev/null':
                            self.compliant = False
                            message = str(item) + \
                            " is not a symlink to /dev/null"
                if not message == "":
                    if self.detailedresults == "":
                        self.detailedresults = message
                    else:
                        self.detailedresults = self.detailedresults + "\n" + \
                        message

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

    def checkHostsBlank(self):
        '''
        special check for single file: hosts.equiv
        this check added as a replacement for symlinking this file
        due to a race condition which existed between verifysysfileperms
        and this rule (symlinkdangerfiles)
        the file hosts.equiv will not be symlinked but instead will be
        checked to make sure it remains empty

        @return: retval
        @rtype: bool
        @author: Breen Malmberg
        '''

        retval = True

        try:

            for f in self.blankfiles:
                if os.path.exists(f):
                    blank = True
                    fh = open(f, 'r')
                    contentlines = fh.readlines()
                    fh.close()
                    for line in contentlines:
                        if not re.search("^#", line):
                            if line.strip() != '':
                                blank = False
                    if not blank:
                        retval = False
                        self.detailedresults += "\nThe file: " + str(f) + " should be blank, but is not."

        except Exception:
            raise

        return retval

    def undo(self):
        '''
        no undo operations permitted for this rule due to security reasons

        @author Breen Malmberg
        '''

        self.formatDetailedResults('undo', None, self.detailedresults)
