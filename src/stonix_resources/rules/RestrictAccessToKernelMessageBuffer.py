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
Created on May 9, 2016

Unprivileged access to the kernel syslog can expose sensitive kernel address information.

@author: Breen Malmberg
'''


from rule import Rule
from CommandHelper import CommandHelper
from logdispatcher import LogPriority

import re
import traceback


class RestrictAccessToKernelMessageBuffer(Rule):
    '''Unprivileged access to the kernel syslog can expose sensitive kernel address information.'''

    def __init__(self, config, environ, logger, statechglogger):
        '''
        Constructor
        '''
        Rule.__init__(self, config, environ, logger, statechglogger)
        self.environ = environ
        self.logger = logger
        self.rulenumber = 86
        self.rulename = "RestrictAccessToKernelMessageBuffer"
        self.mandatory = True
        self.rootrequired = True
        self.rulesuccess = True
        self.formatDetailedResults("initialize")
        self.sethelptext()
        self.guidance = ["CCE-RHEL7-CCE-TBD 2.2.4.5"]
        self.applicable = {"type": "white",
                           "family": "linux"}
        datatype = "bool"
        key = "RESTRICTACCESSTOKERNELMESSAGEBUFFER"
        instructions = "To prevent this rule from running, set the value of RestrictAccessToKernelMessageBuffer to False."
        default = True
        self.ci = self.initCi(datatype, key, instructions, default)

        self.localize()
        self.initobjs()

    def localize(self):
        '''determine system-specific settings
        
        @author: Breen Malmberg


        '''

        # set defaults
        self.fixcommand = "sysctl -w kernel.dmesg_restrict=1"
        self.reportcommand = "sysctl kernel.dmesg_restrict"

    def initobjs(self):
        '''initialize class objects
        
        @author: Breen Malmberg


        '''

        self.ch = CommandHelper(self.logger)

    def report(self):
        '''run report actions for this rule


        :returns: self.compliant

        :rtype: bool
@author: Breen Malmberg

        '''

        self.detailedresults = ""
        self.compliant = True
        kernelopt = False

        try:

            self.ch.executeCommand(self.reportcommand)
            output = self.ch.getOutput()
            retcode = self.ch.getReturnCode()
            if retcode != 0:
                self.detailedresults += "\nError while running command: " + str(self.reportcommand)
            for line in output:
                if re.search("kernel\.dmesg\_restrict", line):
                    kernelopt = True
                    sline = line.split('=')
                    if len(sline) > 1:
                        if str(sline[1]).strip() == '0':
                            self.compliant = False
                            self.detailedresults += "\nKernel message buffer is currently not restricted."
                    else:
                        self.compliant = False
                        self.detailedresults += "\nCould not determine the state of the kernel message buffer access restrictions."
            if not kernelopt:
                self.compliant = False
                self.detailedresults += "\nCould not determine the state of the kernel message buffer access restrictions."

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant, self.detailedresults)
        return self.compliant

    def fix(self):
        '''run fix actions for this rule


        :returns: success

        :rtype: bool
@author: Breen Malmberg

        '''

        success = True
        self.detailedresults = ""

        try:

            self.ch.executeCommand(self.fixcommand)
            rcode = self.ch.getReturnCode()
            errmsg = self.ch.getErrorString()
            if rcode != '0':
                success = False
                self.detailedresults += "\n" + str(errmsg)

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", success, self.detailedresults)
        return success
