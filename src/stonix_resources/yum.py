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

import traceback
from logdispatcher import LogPriority
from CommandHelper import CommandHelper
import re


class Yum(object):

    '''The template class that provides a framework that must be implemented by
    all platform specific pkgmgr classes.

    @author: Derek T Walker
    @change: 2012/08/06 dwalker - Original Implementation
    @change: 2015/08/20 eball - Added getPackageFromFile
    '''

    def __init__(self, logger):
        self.logger = logger
        self.detailedresults = ""
        self.ch = CommandHelper(self.logger)
        self.install = "/usr/bin/yum install -y "
        self.remove = "/usr/bin/yum remove -y "
        self.search = "/usr/bin/yum search "
        self.rpm = "/bin/rpm -q "
###############################################################################

    def installpackage(self, package):
        '''Install a package. Return a bool indicating success or failure.
        @param string package : Name of the package to be installed, must be
        recognizable to the underlying package manager.
        @return bool :
        @author'''
        try:
            installed = False
            self.ch.executeCommand(self.install + package)
            if self.ch.getReturnCode() == 0:
                installed = True
                self.detailedresults = package + \
                    " pkg installed successfully\n"
            else:
                self.detailedresults = package + " pkg not able to install\n"
            self.logger.log(LogPriority.DEBUG, self.detailedresults)
            return installed
        except(KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
            raise(self.detailedresults)
###############################################################################

    def removepackage(self, package):
        '''Remove a package. Return a bool indicating success or failure.
        @param string package : Name of the package to be removed, must be
        recognizable to the underlying package manager.
        @return bool :
        @author'''
        try:
            removed = False
            self.ch.executeCommand(self.remove + package)
            if self.ch.getReturnCode() == 0:
                removed = True
                self.detailedresults += package + " pkg removed successfully\n"
            else:
                self.detailedresults += package + \
                    " pkg not able to be removed\n"
            self.logger.log(LogPriority.DEBUG, self.detailedresults)
            return removed
        except(KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
            raise(self.detailedresults)
###############################################################################

    def checkInstall(self, package):
        '''Check the installation status of a package. Return a bool; True if
        the package is installed.
        @param string package : Name of the package whose installation status
            is to be checked, must be recognizable to the underlying package
            manager.
        @return bool :
        @author'''
        try:
            found = False
            self.ch.executeCommand(self.rpm + package)
            if self.ch.getReturnCode() == 0:
                found = True
                self.detailedresults += package + " pkg found\n"
            else:
                self.detailedresults += package + " pkg not found\n"
            self.logger.log(LogPriority.DEBUG, self.detailedresults)
            return found
        except(KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
            raise(self.detailedresults)
###############################################################################

    def checkAvailable(self, package):
        try:
            found = False
            self.ch.executeCommand(self.search + package)
            output = self.ch.getOutputString()
            if re.search("no matches found", output.lower()):
                self.detailedresults += package + " pkg is not available " + \
                    " or may be misspelled\n"
            elif re.search("matched", output.lower()):
                self.detailedresults += package + " pkg is available\n"
                found = True
            self.logger.log(LogPriority.DEBUG, self.detailedresults)
            return found
        except(KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
            raise(self.detailedresults)
###############################################################################

    def getPackageFromFile(self, filename):
        '''Returns the name of the package that provides the given
        filename/path.

        @param: string filename : The name or path of the file to resolve
        @return: string name of package if found, None otherwise
        @author: Eric Ball
        '''
        try:
            self.ch.executeCommand(self.rpm + "-f " + filename)
            if self.ch.getReturnCode() == 0:
                return self.ch.getOutputString()
            else:
                return None
        except(KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
            raise(self.detailedresults)
###############################################################################

    def getInstall(self):
        return self.install
###############################################################################

    def getRemove(self):
        return self.remove
