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
Created on Aug 06, 2012

@author: Derek T. Walker
'''

import re
import os
import time

from stonixutilityfunctions import psRunning
from logdispatcher import LogPriority
from CommandHelper import CommandHelper
from StonixExceptions import repoError


class Yum(object):
    '''
    The template class that provides a framework that must be implemented by
    all platform specific pkgmgr classes.

    @author: Derek T Walker
    @change: 2012/08/06 dwalker - Original Implementation
    @change: 2015/08/20 eball - Added getPackageFromFile
    '''

    def __init__(self, logger):
        self.logger = logger
        self.ch = CommandHelper(self.logger)
        self.yumloc = "/usr/bin/yum"
        self.install = self.yumloc + " install -y "
        self.remove = self.yumloc + " remove -y "
        self.search = self.yumloc + " list "
        self.checkupdates = self.search + "updates "
        self.listavail = self.search + "available "
        self.listinstalled = self.search + "installed "
        self.updatepkg = self.yumloc + " update -y --obsoletes "

        self.rpmloc = "/usr/bin/rpm"
        self.provides = self.rpmloc + " -qf "
        self.query = self.rpmloc + " -qa "

    def installpackage(self, package):
        '''
        Install a package. Return a bool indicating success or failure.

        @param package: string; Name of the package to be installed, must be
                recognizable to the underlying package manager.
        @return: installed
        @rtype: bool
        @author: Derek T. Walker
        @change: Breen Malmberg - 4/24/2017 - refactored method; added logging; replaced
                detailedresults with logging
        @change: Breen Malmberg - 10/1/2018 - added check for package manager lock and retry loop
        '''

        installed = True
        maxtries = 12
        trynum = 0

        while psRunning("yum"):
            trynum += 1
            if trynum == maxtries:
                self.logger.log(LogPriority.DEBUG, "Timed out while attempting to install package due to yum package manager being in-use by another process.")
                installed = False
                return installed
            else:
                self.logger.log(LogPriority.DEBUG, "Yum package manager is in-use by another process. Waiting for it to be freed...")
                time.sleep(5)

        try:

            try:

                self.ch.executeCommand(self.install + package)
                retcode = self.ch.getReturnCode()
                errstr = self.ch.getErrorString()
                if retcode != 0:
                    raise repoError('yum', retcode)
            except repoError as repoerr:
                if not repoerr.success:
                    self.logger.log(LogPriority.WARNING, str(repoerr))
                    installed = False

            if installed:
                self.logger.log(LogPriority.DEBUG, "Package " + str(package) + " was installed successfully")
            else:
                self.logger.log(LogPriority.DEBUG, "Failed to install package " + str(package))

        except Exception:
            raise
        return installed

    def removepackage(self, package):
        '''
        Remove a package. Return a bool indicating success or failure.

        @param package: string; Name of the package to be removed, must be
                recognizable to the underlying package manager.
        @return: removed
        @rtype: bool
        @author: Derek T. Walker
        @change: Breen Malmberg - 4/24/2017 - refactored method; added logging; replaced
                detailedresults with logging
        '''

        removed = True
        maxtries = 12
        trynum = 0

        while psRunning("yum"):
            trynum += 1
            if trynum == maxtries:
                self.logger.log(LogPriority.DEBUG, "Timed out while attempting to remove package, due to yum package manager being in-use by another process.")
                removed = False
                return removed
            else:
                self.logger.log(LogPriority.DEBUG, "Yum package manager is in-use by another process. Waiting for it to be freed...")
                time.sleep(5)

        try:

            try:
                self.ch.executeCommand(self.remove + package)
                retcode = self.ch.getReturnCode()
                errstr = self.ch.getErrorString()
                if retcode != 0:
                    raise repoError('yum', retcode)
            except repoError as repoerr:
                if not repoerr.success:
                    self.logger.log(LogPriority.WARNING, str(repoerr))
                    removed = False

            if removed:
                self.logger.log(LogPriority.DEBUG, "Package " + str(package) + " was successfully installed")
            else:
                self.logger.log(LogPriority.DEBUG, "Failed to remove package " + str(package))

        except Exception:
            raise
        return removed

    def checkInstall(self, package):
        '''
        Check the installation status of a package. Return a bool; True if
        the package is installed.

        @param package: string; Name of the package whose installation status
            is to be checked, must be recognizable to the underlying package
            manager.
        @return: found
        @rtype: bool
        @author: Derek T. Walker
        @change: Breen Malmberg - 4/24/2017 - refactored method; added logging; replaced
                detailedresults with logging
        '''

        installed = True
        errstr = ""
        maxtries = 12
        trynum = 0

        while psRunning("yum"):
            trynum += 1
            if trynum == maxtries:
                self.logger.log(LogPriority.DEBUG, "Timed out while attempting to check status of package, due to yum package manager being in-use by another process.")
                installed = False
                return installed
            else:
                self.logger.log(LogPriority.DEBUG, "Yum package manager is in-use by another process. Waiting for it to be freed...")
                time.sleep(5)

        try:

            try:
                self.ch.executeCommand(self.listinstalled + package)
                retcode = self.ch.getReturnCode()
                errstr = self.ch.getErrorString()
                if retcode != 0:
                    raise repoError('yum', retcode, str(errstr))
            except repoError as repoerr:
                if not repoerr.success:
                    self.logger.log(LogPriority.WARNING, str(repoerr))
                    installed = False

            if installed:
                self.logger.log(LogPriority.DEBUG, "Package " + str(package) + " is installed")
            else:
                self.logger.log(LogPriority.DEBUG, "Package " + str(package) + " is NOT installed")

        except Exception:
            raise
        return installed

    def Update(self, package=""):
        '''
        update specified package if any updates
        are available for it
        if no package is specified, update all
        packages which can be updated on the system

        @param package: string; name of package to update
        @return: updated
        @rtype: bool
        @author: Breen Malmberg
        '''

        updated = True

        try:

            try:
                self.ch.executeCommand(self.updatepkg + package)
                retcode = self.ch.getReturnCode()
                errstr = self.ch.getErrorString()
                if retcode != 0:
                    raise repoError('yum', retcode, str(errstr))
            except repoError as repoerr:
                if not repoerr.success:
                    self.logger.log(LogPriority.WARNING, str(errstr))
                    updated = False

            if package:
                if updated:
                    self.logger.log(LogPriority.DEBUG, "Package " + str(package) + " was successfully updated")
                else:
                    self.logger.log(LogPriority.DEBUG, "No updates were found for package " + str(package))
            else:
                if updated:
                    self.logger.log(LogPriority.DEBUG, "All packages were successfully updated")
                else:
                    self.logger.log(LogPriority.DEBUG, "No updates were found for this system")

        except Exception:
            raise
        return updated

    def checkUpdate(self, package=""):
        '''
        check if there are any updates available for
        specified package
        if no package is specified, check if any updates
        are available for the current system

        @param package: string; name of package to check
        @return: updatesavail
        @rtype: bool
        @author: Breen Malmberg
        '''

        updatesavail = False

        try:

            try:
                self.ch.executeCommand(self.checkupdates + package)
                retcode = self.ch.getReturnCode()
                output = self.ch.getOutputString()
                errstr = self.ch.getErrorString()
                if retcode != 0:
                    raise repoError('yum', retcode, str(errstr))
                else:
                    if re.search("Updated packages", output, re.IGNORECASE):
                        updatesavail = True
            except repoError as repoerr:
                if not repoerr.success:
                    self.logger.log(LogPriority.WARNING, str(errstr))
                else:
                    if re.search("Updated packages", output, re.IGNORECASE):
                        updatesavail = True

            if package:
                if updatesavail:
                    self.logger.log(LogPriority.DEBUG, "Updates are available for package " + str(package))
                else:
                    self.logger.log(LogPriority.DEBUG, "No updates are available for package " + str(package))
            else:
                if updatesavail:
                    self.logger.log(LogPriority.DEBUG, "Updates are available for this system")
                else:
                    self.logger.log(LogPriority.DEBUG, "No updates are available for this system")

        except Exception:
            raise
        return updatesavail

    def checkAvailable(self, package):
        '''
        check if specified package is available to install
        return True if it is
        return False if not

        @param package: string; name of package to check
        @return: available
        @rtype: bool
        @author: Breen Malmberg
        '''

        available = True
        maxtries = 12
        trynum = 0

        while psRunning("yum"):
            trynum += 1
            if trynum == maxtries:
                self.logger.log(LogPriority.DEBUG, "Timed out while attempting to check availability of package, due to yum package manager being in-use by another process.")
                available = False
                return available
            else:
                self.logger.log(LogPriority.DEBUG, "Yum package manager is in-use by another process. Waiting for it to be freed...")
                time.sleep(5)

        try:

            try:
                self.ch.executeCommand(self.listavail + package)
                retcode = self.ch.getReturnCode()
                errstr = self.ch.getErrorString()
                if retcode != 0:
                    raise repoError('yum', retcode, str(errstr))
            except repoError as repoerr:
                if not repoerr.success:
                    self.logger.log(LogPriority.DEBUG, str(repoerr))
                    available = False

            if available:
                self.logger.log(LogPriority.DEBUG, "Package " + str(package) + " is available to install")
            else:
                self.logger.log(LogPriority.DEBUG, "No package " + str(package) + " was found to install")

        except Exception:
            raise
        return available

    def getPackageFromFile(self, filename):
        '''
        Returns the name of the package that provides the given
        filename/path.

        @param filename: string; The name or path of the file to resolve
        @return: packagename
        @rtype: string
        @author: Eric Ball
        @change: Breen Malmberg - 4/24/2017 - refactored method; added logging; replaced
                detailedresults with logging
        '''

        packagename = ""

        try:

            try:
                self.ch.executeCommand(self.provides + filename)
                retcode = self.ch.getReturnCode()
                outputstr = self.ch.getOutputString()
                errstr = self.ch.getErrorString()
                if retcode != 0:
                    raise repoError('yum', retcode, str(errstr))
                else:
                    packagename = outputstr
            except repoError as repoerr:
                if not repoerr.success:
                    self.logger.log(LogPriority.WARNING, str(errstr))

        except Exception:
            raise
        return packagename

    def getInstall(self):
        return self.install

    def getRemove(self):
        return self.remove
