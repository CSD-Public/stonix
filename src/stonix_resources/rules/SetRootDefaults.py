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
Created on Aug 1, 2013

Set default group and home directory for root.

@author: Breen Malmberg
@change: 02/16/2014 ekkehard Implemented self.detailedresults flow
@change: 02/16/2014 ekkehard Implemented isapplicable
@change: 04/18/2014 ekkehard ci updates and ci fix method implementation
@change: 2015/04/17 dkennel updated for new isApplicable

'''

from __future__  import absolute_import

from ..rule import Rule
from ..logdispatcher import LogPriority
from ..CommandHelper import CommandHelper

import traceback
import grp
import pwd


class SetRootDefaults(Rule):
    '''Set default group and home directory for root.'''

    def __init__(self, config, environ, logger, statechglogger):
        '''
        Constructor
        '''

        Rule.__init__(self, config, environ, logger, statechglogger)
        self.config = config
        self.environ = environ
        self.logger = logger
        self.statechglogger = statechglogger
        self.rulenumber = 77
        self.rulename = 'SetRootDefaults'
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.sethelptext()
        self.rootrequired = True

        citype = "bool"
        ciname = "SetRootDefaults"
        citext = "To prevent the setting of the root default " + \
                              "home directory and group, set the " + \
                              "value of SetRootDefaults to False."
        cistatus = True
        self.ci = self.initCi(citype, ciname, citext, cistatus)

        self.guidance = ['CIS', 'cce-4834-8']
        self.applicable = {'type': 'white',
                           'family': ['solaris']}

    def report(self):
        '''Retrieve and report the location of root user's home directory,
        and the integer value of root user's gid.


        :returns: self.compliant

        :rtype: bool
@author Breen Malmberg

        '''

        # defaults
        self.compliant = True
        self.detailedresults = ""
        rootgid = 0
        roothome = ""

        try:

            rootgid = grp.getgrnam('root').gr_gid
            roothome = pwd.getpwnam('root').pw_dir

            if rootgid != 0:
                self.compliant = False
                self.detailedresults += "\nRoot user's gid is not 0. It is: " + str(rootgid)

            if roothome != '/root':
                self.compliant = False
                self.detailedresults += "\nRoot user's home directory is not /root. It is: " + str(roothome)

            if self.compliant:
                self.detailedresults += "\nRoot user's home directory is set to /root, and root user's gid is set to 0."

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

    def fix(self):
        '''Set the gid for the root account to 0. Set the home directory for the
        root account to /root.
        
        @author Breen Malmberg


        :returns: success

        :rtype: bool

        '''

        success = True
        self.detailedresults = ""
        setrootgid = "/sbin/usermod -g 0 root"
        setroothome = "/sbin/usermod -m -d /root root"
        self.ch = CommandHelper(self.logger)

        try:

            if self.ci.getcurrvalue():

                self.ch.executeCommand(setrootgid)
                retcode1 = self.ch.getReturnCode()
                if retcode1 != 0:
                    self.logger.log(LogPriority.DEBUG, "groupmod command failed!")
                    self.detailedresults += "\nFailed to set root's gid to 0"
                    success = False
                self.ch.executeCommand(setroothome)
                retcode2 = self.ch.getReturnCode()
                if retcode2 != 0:
                    self.logger.log(LogPriority.DEBUG, "usermod command failed!")
                    self.detailedresults += "\nFailed to set root's home directory to /root"
                    success = False

            else:
                self.logger.log(LogPriority.DEBUG, "The CI for this rule was not enabled when the rule was run. Nothing was done.")
                self.detailedresults += "\nThis rule was not enabled when fix was run. Nothing was done."

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", success, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return success
