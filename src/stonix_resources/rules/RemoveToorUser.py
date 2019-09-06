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
Created on Nov 13, 2012

@author: dwalker
@change: 04/21/2014 dkennel Updated CI invocation.
@change: 2015/04/16 dkennel updated for new isApplicable
'''

from stonixutilityfunctions import readFile
from rule import Rule
from logdispatcher import LogPriority
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
        will set self.compliant = False if toor user is found


        '''

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
        that toor user is present


        '''

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
        toor user for the system


        '''
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
