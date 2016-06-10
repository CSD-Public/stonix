'''
###############################################################################
#                                                                             #
# Copyright 2016.  Los Alamos National Security, LLC. This material was       #
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

@author: ekkehard
@change: 2016/06/10 original implementation
'''

import CommandHelper


class QuitAppmacOS(object):

    def __init__(self, logdispatcher):
        self.logdispatcher = logdispatcher
        self.ch = CommandHelper.CommandHelper(self.logdispatcher)
        self.osascript = "/usr/bin/osascript"
        self.kill = "/bin/kill"
        self.resetApplicationList()

    def appendApplicationToList(self, applicationName=""):
        if not applicationName == "":
            self.applicationlist.append(applicationName)
        return self.applicationlist

    def resetApplicationList(self, applicationName=""):
        self.applicationlist = []
        return self.applicationlist

    def quitAllInList(self, force=False):
        success = True
        for applicationName in self.applicationlist:
            quitapp = self.quitApplication(applicationName, force)
            if not quitapp:
                success = False
        return success

    def quitApplication(self, applicationName="", force=False):
        success = True
        if not applicationName == "":
            if force:
                command = [self.kill, '-9', applicationName]
            else:
                command = [self.osascript, '-e',
                           "'" + 'quit app "' + applicationName + '"' + "'"]
            self.ch.executeCommand(command)
        return success
        