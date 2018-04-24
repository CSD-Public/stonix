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
Created on May 9, 2016

Unprivileged access to the kernel syslog can expose sensitive kernel address information.

@author: Breen Malmberg
'''

from __future__ import absolute_import
from ..rule import Rule
from ..CommandHelper import CommandHelper
from ..logdispatcher import LogPriority

import re
import traceback


class RestrictAccessToKernelMessageBuffer(Rule):
    '''
    Unprivileged access to the kernel syslog can expose sensitive kernel address information.
    '''

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
        '''
        determine system-specific settings

        @author: Breen Malmberg
        '''

        # set defaults
        self.fixcommand = "sysctl -w kernel.dmesg_restrict=1"
        self.reportcommand = "sysctl kernel.dmesg_restrict"

    def initobjs(self):
        '''
        initialize class objects

        @author: Breen Malmberg
        '''

        self.ch = CommandHelper(self.logger)

    def report(self):
        '''
        run report actions for this rule

        @return: self.compliant
        @rtype: bool
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
        '''
        run fix actions for this rule

        @return: success
        @rtype: bool
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
