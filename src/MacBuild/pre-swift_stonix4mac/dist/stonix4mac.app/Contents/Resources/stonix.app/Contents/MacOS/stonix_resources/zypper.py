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
from re import search
from CommandHelper import CommandHelper


class Zypper(object):

    '''The template class that provides a framework that must be implemented by
    all platform specific pkgmgr classes.

    @author: Derek T Walker
    @change: 2012/08/08 dwalker - Original Implementation
    @change: 2014/09/10 dkennel - Added -n option to search command string
    @change: 2014/12/24 bemalmbe - fixed a typo in the old search string
    @change: 2014/12/24 bemalmbe - changed search strings to be match exact and
        search for installed or available separately
    @change: 2014/12/24 bemalmbe - fixed multiple pep8 violations
    @change: 2015/08/20 eball - Added getPackageFromFile and self.rpm var
    @change: 2016/08/02 eball - Moved checkInstall return out of else block
    '''

    def __init__(self, logger):
        self.logger = logger
        self.detailedresults = ""
        self.ch = CommandHelper(self.logger)
        self.install = "/usr/bin/zypper --non-interactive install "
        self.remove = "/usr/bin/zypper --non-interactive remove "
        self.searchi = "/usr/bin/zypper --non-interactive search --match-exact -i "
        self.searchu = "/usr/bin/zypper --non-interactive search --match-exact -u "
        self.rpm = "/bin/rpm -q "

###############################################################################
    def installpackage(self, package):
        '''Install a package. Return a bool indicating success or failure.
        @param string package : Name of the package to be installed, must be
            recognizable to the underlying package manager.
        @return: bool
        @author: dwalker
        @change: 12/24/2014 - bemalmbe - fixed method doc string formatting
        '''
        try:
            installed = False
            self.ch.executeCommand(self.install + package)
            output = self.ch.getOutputString()
            if self.ch.getReturnCode() == 0:
                if search("Abort, retry, ignore", output):
                    self.detailedresults += "There is an error contacting " + \
                        "one or more repos, aborting\n"
                    return False
                self.detailedresults += package + \
                    " pkg installed successfully\n"
                installed = True
            else:
                self.detailedresults += package + " pkg not able to install\n"
            self.logger.log(LogPriority.INFO, self.detailedresults)
            return installed
        except(KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)

###############################################################################
    def removepackage(self, package):
        '''Remove a package. Return a bool indicating success or failure.

        @param string package : Name of the package to be removed, must be
            recognizable to the underlying package manager.
        @return: bool
        @author: dwalker
        @change: 12/24/2014 - bemalmbe - fixed method doc string formatting
        @change: 12/24/2014 - bemalmbe - fixed an issue with var 'removed' not
            being initialized before it was called
        '''
        removed = False
        try:
            self.ch.executeCommand(self.remove + package)
            output = self.ch.getOutputString()
            if self.ch.getReturnCode() == 0:
                if search("Abort, retry, ignore", output):
                    self.detailedresults += "There is an error contacting " + \
                        "one or more repos, aborting\n"
                    return False
                self.detailedresults += package + " pkg removed successfully\n"
                removed = True
            else:
                self.detailedresults += package + \
                    " pkg not able to be removed\n"
            self.logger.log(LogPriority.INFO, self.detailedresults)
            return removed
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)

###############################################################################
    def checkInstall(self, package):
        '''
        Check the installation status of a package. Return a bool; True if
        the package is installed.

        @param string package : Name of the package whose installation status
            is to be checked, must be recognizable to the underlying package
            manager.
        @return: bool
        @author: dwalker
        @change: 12/24/2014 - bemalmbe - fixed method doc string formatting
        @change: 12/24/2014 - bemalmbe - changed var name 'found' to
            'installed'
        @change: 12/24/2014 - bemalmbe - now uses correct search syntax
        @change: 12/24/2014 - bemalmbe - removed detailedresults update on
            'found but not installed' as this no longer applies to this method
        '''

        try:
            installed = False
            self.ch.executeCommand(self.searchi + package)
            if self.ch.getReturnCode() == 0:
                output = self.ch.getOutput()
                outputStr = self.ch.getOutputString()
                if search("Abort, retry, ignore", outputStr):
                    self.detailedresults += "There is an error contacting " + \
                        "one or more repos, aborting\n"
                    return False
                for line in output:
                    if search(package, line):
                        installed = True
                        break
            elif self.ch.getReturnCode() == 106:
                for line in output:
                    if search(package, line):
                        installed = True
                        break
            else:
                installed = False

            if installed:
                self.detailedresults += package + " pkg is installed\n"
            else:
                self.detailedresults += package + " pkg not found or may be \
misspelled\n"
            self.logger.log(LogPriority.DEBUG, self.detailedresults)
            return installed
        except(KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)

###############################################################################
    def checkAvailable(self, package):
        '''
        check if given package is available to install on the current system

        @param: package string name of package to search for
        @return: bool
        @author: dwalker
        @change: 12/24/2014 - bemalmbe - added method documentation
        @change: 12/24/2014 - bemalmbe - changed var name 'found' to
            'available'
        @change: 12/24/2014 - bemalmbe - fixed search syntax and updated search
            variable name
        '''
        try:
            available = False
            self.ch.executeCommand(self.searchu + package)
            if self.ch.getReturnCode() == 0:
                output = self.ch.getOutput()
                for line in output:
                    if search(package, line):
                        available = True
                if available:
                    self.detailedresults += package + " pkg is available\n"
                else:
                    self.detailedresults += package + " pkg is not available\n"
            else:
                self.detailedresults = package + " pkg not found or may be \
misspelled\n"
            self.logger.log(LogPriority.INFO, self.detailedresults)
            return available
        except(KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)

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
        '''
        return the install command string for the zypper pkg manager

        @return: string
        @author: dwalker
        @change: 12/24/2014 - bemalmbe - added method documentation
        '''

        return self.install

###############################################################################
    def getRemove(self):
        '''
        return the uninstall/remove command string for the zypper pkg manager

        @return: string
        @author: dwalker
        @change: 12/24/2014 - bemalmbe - added method documentation
        '''

        return self.remove
