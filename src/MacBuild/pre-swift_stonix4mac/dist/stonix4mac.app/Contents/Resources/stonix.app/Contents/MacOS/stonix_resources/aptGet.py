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

from subprocess import Popen, PIPE, call
from re import search
import traceback
from logdispatcher import LogPriority
from CommandHelper import CommandHelper


class AptGet(object):

    '''Linux specific package manager for distributions that use the apt-get
    command to install packages.

    @author: Derek T Walker
    @change: 2012/08/06 dwalker - Original Implementation
    @change: 2015/08/20 eball - Added getPackageFromFile
    '''

    def __init__(self, logger):
        self.logger = logger
        self.detailedresults = ""
        self.ch = CommandHelper(self.logger)
        self.install = "sudo DEBIAN_FRONTEND=noninteractive /usr/bin/apt-get -y --force-yes install "
        self.remove = "/usr/bin/apt-get -y remove "
###############################################################################

    def installpackage(self, package):
        '''Install a package. Return a bool indicating success or failure.

        @param string package : Name of the package to be installed, must be
            recognizable to the underlying package manager.
        @return bool :
        @author dwalker'''
        try:
            self.ch.executeCommand(self.install + package)
            if self.ch.getReturnCode() == 0:
                self.detailedresults = package + " pkg installed successfully"
                self.logger.log(LogPriority.DEBUG, self.detailedresults)
                return True
            else:
                # try to install for a second time
                self.ch.executeCommand(self.install + package)
                if self.ch.getReturnCode() == 0:
                    self.detailedresults = package + \
                        " pkg installed successfully"
                    self.logger.log(LogPriority.DEBUG, self.detailedresults)
                    return True
                else:
                    self.detailedresults = package + " pkg not able to install"
                    self.logger.log(LogPriority.DEBUG, self.detailedresults)
                    return False
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
            self.ch.executeCommand(self.remove + package)
            if self.ch.getReturnCode() == 0:
                self.detailedresults = package + " pkg removed successfully"
                self.logger.log(LogPriority.INFO, self.detailedresults)
                return True
            else:
                self.detailedresults = package + " pkg not able to be removed"
                self.logger.log(LogPriority.INFO, self.detailedresults)
                return False
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

        @param: string package : Name of the package whose installation status
            is to be checked, must be recognizable to the underlying package
            manager.
        @return: bool :
        @author: dwalker'''

        try:
            stringToMatch = "(.*)" + package + "(.*)"
            self.ch.executeCommand(["/usr/bin/dpkg", "-l", package])
            info = self.ch.getOutput()
            match = False
            for line in info:
                if search(stringToMatch, line):
                    parts = line.split()
                    if parts[0] == "ii":
                        match = True
                        break
                else:
                    continue
            if match:
                self.detailedresults = package + " pkg found and installed\n"
                self.logger.log(LogPriority.INFO, self.detailedresults)
                return True
            else:
                self.detailedresults = package + " pkg not installed\n"
                self.logger.log(LogPriority.INFO, self.detailedresults)
                return False
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
            retval = call(["/usr/bin/apt-cache", "search", package],
                          stdout=PIPE, stderr=PIPE, shell=False)
            if retval == 0:
                message = Popen(["/usr/bin/apt-cache", "search", package],
                                stdout=PIPE, stderr=PIPE, shell=False)
                info = message.stdout.readlines()
                while message.poll() is None:
                    continue
                message.stdout.close()
                for line in info:
                    if search(package, line):
                        found = True
                if found:
                    self.detailedresults = package + " pkg is available"
                else:
                    self.detailedresults = package + " pkg is not available"
            else:
                self.detailedresults = package + " pkg not found or may be \
misspelled"
            self.logger.log(LogPriority.DEBUG, self.detailedresults)
            return found
        except(KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
            raise
###############################################################################

    def getPackageFromFile(self, filename):
        '''Returns the name of the package that provides the given
        filename/path.

        @param: string filename : The name or path of the file to resolve
        @return: string name of package if found, None otherwise
        @author: Eric Ball
        '''
        try:
            self.ch.executeCommand("dpkg -S " + filename)
            if self.ch.getReturnCode() == 0:
                output = self.ch.getOutputString()
                pkgname = output.split(":")[0]
                return pkgname
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
