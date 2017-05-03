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
Created on Aug 13, 2015

@author: Derek T. Walker
'''

import re

from logdispatcher import LogPriority
from CommandHelper import CommandHelper
from stonixutilityfunctions import validateParam


class Dnf(object):
    '''
    The template class that provides a framework that must be implemented by
    all platform specific pkgmgr classes.  Specifically for Fedora

    :version:
    @author: Derek T Walker 08-13-2015
    @change: Breen Malmberg - 4/18/2017 - refactor of multiple methods;
            removed detailedresults reset in __init__; added the -q
            (non-interactive) flag to install and remove command var's;
            added a dnf info command var;
            added parameter validation to each method
    '''

    def __init__(self, logger):
        self.logger = logger
        self.ch = CommandHelper(self.logger)
        self.dnfloc = "/usr/bin/dnf"
        self.install = self.dnfloc + " install -yq "
        self.remove = self.dnfloc + " remove -yq "
        self.search = self.dnfloc + " search "
        self.checkinstalled = self.dnfloc + " list installed "
        self.chavailable = self.dnfloc + " list available "
        self.checkupdate = self.dnfloc + " check-update "
        self.rpm = "/bin/rpm -qf "
        self.updatepackage = self.dnfloc + " -yq upgrade " 

###############################################################################
    def installpackage(self, package):
        '''
        Install a package. Return a bool indicating success or failure.

        @param package: string; Name of the package to be installed, must be
                recognizable to the underlying package manager.
        @return installed
        @rtype: bool
        @author: Derek T. Walker
        @change: Breen Malmberg - 4/18/2017
        '''

        installed = False

        try:

            # parameter validation
            if not package:
                self.logger.log(LogPriority.DEBUG, "Parameter: package was blank!")
                return installed
            if not isinstance(package, basestring):
                self.logger.log(LogPriority.DEBUG, "Parameter: package needs to be of type string. Got: " + str(type(package)))
                return installed

            self.ch.executeCommand(self.install + package)

            if self.ch.getReturnCode() == 0:
                installed = True
                self.logger.log(LogPriority.DEBUG, "Successfully installed package " + str(package))
            else:
                self.logger.log(LogPriority.DEBUG, "Failed to install package " + str(package))

        except Exception:
            raise
        return installed

###############################################################################
    def removepackage(self, package):
        '''
        Remove a package. Return a bool indicating success or failure.

        @param package: string; Name of the package to be removed, must be
                recognizable to the underlying package manager.
        @return: removed
        @rtype: bool
        @author: Derek T. Walker
        @change: Breen Malmberg - 4/18/2017
        '''

        removed = False

        try:

            # parameter validation
            if not package:
                self.logger.log(LogPriority.DEBUG, "Parameter: package was blank!")
                return removed
            if not isinstance(package, basestring):
                self.logger.log(LogPriority.DEBUG, "Parameter: package needs to be of type string. Got: " + str(type(package)))
                return removed

            self.ch.executeCommand(self.remove + package)
            if self.ch.getReturnCode() == 0:
                removed = True
                self.logger.log(LogPriority.DEBUG, "Package " + str(package) + " was successfully removed")
            else:
                self.logger.log(LogPriority.DEBUG, "Failed to remove package " + str(package))

        except Exception:
            raise
        return removed

###############################################################################
    def checkInstall(self, package):
        '''
        Check the installation status of a package. Return a bool; True if
        the package is installed.

        @param: package: string; Name of the package whose installation status
                is to be checked, must be recognizable to the underlying package
                manager.
        @return: installed
        @rtype: bool
        @author: Derek T. Walker
        @change: Breen Malmberg - 4/18/2017
        '''

        installed = False

        try:

            # parameter validation
            if not package:
                self.logger.log(LogPriority.DEBUG, "Parameter: package was blank!")
                return installed
            if not isinstance(package, basestring):
                self.logger.log(LogPriority.DEBUG, "Parameter: package needs to be of type string. Got: " + str(type(package)))
                return installed

            self.ch.executeCommand(self.checkinstalled + package)
            if self.ch.getReturnCode() == 0:
                installed = True
                self.logger.log(LogPriority.DEBUG, "Package " + str(package) + " is installed")
            else:
                self.logger.log(LogPriority.DEBUG, "Package " + str(package) + " is NOT installed")

        except Exception:
            raise
        return installed

###############################################################################
    def checkAvailable(self, package):
        '''
        check if the given package is available to install

        @param package: string; name of package to check for
        @return: found
        @rtype: bool
        @author: Derek T. Walker
        @change: Breen Malmberg - 4/18/2017 - added doc string; refactor of method
        '''

        found = False

        try:

            if not validateParam(self.logger, package, basestring, "package"):
                return found

            self.ch.executeCommand(self.chavailable + package)
            retcode = self.ch.getReturnCode()
            if retcode == 0:
                found = True

            if found:
                self.logger.log(LogPriority.DEBUG, "Package " + str(package) + " is available to install")
            else:
                self.logger.log(LogPriority.DEBUG, "No package " + str(package) + " available to install")

        except Exception:
            raise
        return found

    def checkUpdate(self, package=""):
        '''
        check the specified package for updates
        if no package is specified, check for all/any
        updates on the system
        return True if there are updates available
        return False if there are no updates available

        @param package: string; name of package to check
        @return: updatesavail
        @rtype: bool
        @author: Breen Malmberg
        '''

        updatesavail = False

        try:

            # parameter validation
            if not validateParam(self.logger, package, basestring, "package"):
                return updatesavail

            self.ch.executeCommand(self.checkupdate + package)
            retcode = self.ch.getReturnCode()
            if retcode == 100:
                updatesavail = True

            if package:
                if updatesavail:
                    self.logger.log(LogPriority.DEBUG, "Updates are available")
                else:
                    self.logger.log(LogPriority.DEBUG, "No updates are available")
            else:
                if updatesavail:
                    self.logger.log(LogPriority.DEBUG, "Updates are available for package " + str(package))
                else:
                    self.logger.log(LogPriority.DEBUG, "No updates are available for package " + str(package))

            if retcode not in [0, 100]:
                errmsg = self.ch.getErrorString()
                self.logger.log(LogPriority.DEBUG, "dnf encountered an error while checking for updates. Error code: " + str(retcode))
                self.logger.log(LogPriority.DEBUG, "Error message: " + str(errmsg))

        except Exception:
            raise
        return updatesavail

    def Update(self, package=""):
        '''
        update the specified package
        if no package is specified, update
        all packages on the system

        @param package: string; name of package to update
        @return: updated
        @rtype: bool
        @author: Breen Malmberg
        '''

        updated = True

        try:

            # parameter validation
            if not validateParam(self.logger, package, basestring, "package"):
                updated = False
                return updated

            self.ch.executeCommand(self.updatepackage + package)
            retcode = self.ch.getReturnCode()
            if retcode != 0:
                updated = False
                errmsg = self.ch.getErrorString()

            if package:
                if retcode != 0:
                    self.logger.log(LogPriority.DEBUG, "dnf encountered an error while trying to update package " + str(package) + ". Error code: " + str(retcode))
                    self.logger.log(LogPriority.DEBUG, "Error message: " + str(errmsg))
                else:
                    self.logger.log(LogPriority.DEBUG, "Package " + str(package) + " successfully updated")
            else:
                if retcode != 0:
                    self.logger.log(LogPriority.DEBUG, "dnf encountered an error while trying to update packages. Error code: " + str(retcode))
                    self.logger.log(LogPriority.DEBUG, "Error message: " + str(errmsg))
                else:
                    self.logger.log(LogPriority.DEBUG, "All packages updated successfully")

        except Exception:
            raise
        return updated

###############################################################################
    def getPackageFromFile(self, filename):
        '''
        return a string with the name of the parent package
        in it

        @param: filename: string; The name or path of the file to resolve
        @return: packagename
        @rtype: string
        @author: Eric Ball
        @change: Breen Malmberg - 4/18/2017 - fixed doc string; refactored method
        '''

        packagename = ""

        try:

            self.ch.executeCommand(self.rpm + filename)
            if self.ch.getReturnCode() == 0:
                packagename = self.ch.getOutputString()
            else:
                self.logger.log(LogPriority.DEBUG, "Failed to get the package for the given filename")

        except Exception:
            raise
        return packagename

###############################################################################
    def getInstall(self):
        return self.install

###############################################################################
    def getRemove(self):
        return self.remove

    def getSearch(self):
        return self.search

    def getInfo(self):
        return self.info

    def getCheck(self):
        return self.checkupdate
