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

The Secure Root Path class checks all directories in the root $PATH variable
for user/world-writable entries and report any found.

@author: bemalmbe
@change: 02/16/2014 ekkehard Implemented self.detailedresults flow
@change: 02/16/2014 ekkehard Implemented isapplicable
@change: 04/21/2013 ekkehard Renamed from SecureRootPath to CheckRootPath
@change: 04/21/2014 ekkehard remove ci as it is a report only rule
@change: 2015/04/14 dkennel updated to use new isApplicable
'''

from __future__ import absolute_import
import os
import re
import traceback

from ..rule import Rule
from ..logdispatcher import LogPriority


class CheckRootPath(Rule):
    '''
    The Secure Root Path class checks all directories in the root
    $PATH variable for user/world-writable entries and report any found.

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
        self.helptext = '''The Secure Root Path class checks all directories in the root $PATH variable 
for user/world-writable entries, and if any are found then remove them from the 
root $PATH.'''
        self.rootrequired = True
        self.guidance = ['NSA RHEL 2.3.4.1, 2.3.4.1.1, 2.3.4.1.2']
        self.applicable = {'type': 'white',
                           'family': ['linux', 'solaris', 'freebsd'],
                           'os': {'Mac OS X': ['10.9', 'r', '10.10.11']}}

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

        #defaults
        retval = True

        try:
            self.detailedresults = ""

            path = os.environ['PATH']

            if re.search('(^:|^\.:|:\.$|:\.:)', path):
                retval = False

            if retval:
                self.compliant = True
            else:
                self.compliant = False
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
