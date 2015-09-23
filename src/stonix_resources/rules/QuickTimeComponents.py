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
@copyright: 2015 Los Alamos National Security, LLC. All rights reserved
@author: ekkehard
@change: 2015/09/23 Original Implementation
'''
from __future__ import absolute_import
import traceback

from ..rule import Rule
from ..logdispatcher import LogPriority
from ..filehelper import FileHelper


class QuickTimeComponents(Rule):
    '''
    This Mac Only rule reports on installed QuickTime Components
    @author: ekkehard j. koch
    '''

###############################################################################

    def __init__(self, config, environ, logdispatcher, statechglogger):
        Rule.__init__(self, config, environ, logdispatcher,
                              statechglogger)
        self.rulenumber = 259
        self.rulename = 'QuickTimeComponents'
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.helptext = "This rules reports on installed QuickTime Components"
        self.rootrequired = False
        self.guidance = []

        self.applicable = {'type': 'white',
                           'os': {'Mac OS X': ['10.9', 'r', '10.11.10']}}
        if environ.getuid() == 0:
            self.QuickTimeComponentDirectory = "/Library/QuickTime/"
        else:
            self.QuickTimeComponentDirectory = "~/Library/QuickTime/"
        self.fh = FileHelper(self.logdispatch)

###############################################################################

    def report(self):
        '''
        Checks to see if any STOM Files are installed
        @author: ekkehard j. koch
        @param self:essential if you override this definition
        @return: boolean - true if applicable false if not
        @change: 01/06/2014 Original Implementation
        '''
        try:
            self.detailedresults = ""
            self.currstate = "notconfigured"
            self.compliant = False
            success = self.fh.loadFilesFromDirectory(self.QuickTimeComponentDirectory)
            if success:
                message = str(self.QuickTimeComponentDirectory) + " QuickTime Components Loaded."
                self.logdispatch.log(LogPriority.DEBUG, message)
                
        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception, err:
            self.rulesuccess = False
            self.compliant = False
            self.detailedresults = self.detailedresults + "\n" + str(err) + \
            " - " + str(traceback.format_exc())
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant
