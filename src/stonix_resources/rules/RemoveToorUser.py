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
Created on Nov 13, 2012

@author: dwalker
@change: 04/21/2014 dkennel Updated CI invocation.
@change: 2015/04/16 dkennel updated for new isApplicable
'''
from __future__ import absolute_import
from ..stonixutilityfunctions import readFile
from ..rule import Rule
from ..logdispatcher import LogPriority
from subprocess import call
import traceback
import re


class RemoveToorUser(Rule):

    def __init__(self, config, environ, logger, statechglogger):
        Rule.__init__(self, config, environ, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 94
        self.rulename = "RemoveToorUser"
        self.mandatory = True
        self.sethelptext()
        self.rootrequired = True
        self.formatDetailedResults("initialize")
        datatype = 'bool'
        key = 'REMOVETOORUSER'
        instructions = '''To disable this rule set the value of \
REMOVETOORUSER to False.'''
        default = True
        self.ci = self.initCi(datatype, key, instructions, default)
        self.guidance = []  # !FIXME!
        self.applicable = {'type': 'white',
                           'family': ['freebsd']}

###############################################################################

    def report(self):
        '''report will traverse through each entry in the /etc/passwd file.
        will set self.compliant = False if toor user is found'''

        try:
            found = False
            fileLocation = "/etc/passwd"
            contents = readFile(fileLocation, self.logger)
            if contents:
                user = "^toor"
                for line in contents:
                    if re.search(user, line):
                        found = True
                        break
                if found:
                    self.compliant = False
                else:
                    self.compliant = True
            else:
                self.compliant = False
                self.detailedresults = "RemoveToorUser report has been run \
and is not compliant, /etc/passwd file doesn't exist"
            self.logger.log(LogPriority.INFO, self.detailedresults)
        except(KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.detailedresults += "\n" + traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant
    
###############################################################################

    def fix(self):
        '''the fix method with remove the user 'toor' if report indicated
        that toor user is present'''

        try:
            if not self.ci.getcurrvalue():
                return True
            retval = call(['/usr/sbin/pw', 'userdel', 'toor'], stdout=None,
                                                      stderr=None, shell=False)
            if retval == 0:
                self.detailedresults = "RemoveToorUser fix seems to have run \
with no issues"
                self.rulesuccess = True
            else:
                self.detailedresults = "RemoveToorUser fix seems to have run \
but had a few problems"
                self.rulesuccess = False
        except(KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.detailedresults += "\n" + traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess,
                                                          self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.rulesuccess

###############################################################################

    def undo(self):
        '''There is no undo method for this rule since we don't ever want a 
        toor user for the system'''
        try:
            self.detailedresults = "no undo available\n"
            self.detailedresults += traceback.format_exc()
            self.logger.log(LogPriority.INFO, self.detailedresults)
            return
        except(KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
