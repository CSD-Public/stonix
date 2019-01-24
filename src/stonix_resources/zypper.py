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
Created on Aug 08, 2012

@author: Derek T. Walker
'''

import re
import os
import time

from stonixutilityfunctions import psRunning
from logdispatcher import LogPriority
from CommandHelper import CommandHelper
from StonixExceptions import repoError


class Zypper(object):
    '''
    The template class that provides a framework that must be implemented by
    all platform specific pkgmgr classes.

    @author: Derek T Walker
    @change: 2012/08/08 Derek Walker - Original Implementation
    @change: 2014/09/10 dkennel - Added -n option to search command string
    @change: 2014/12/24 Breen Malmberg - fixed a typo in the old search string;
            fixed multiple pep8 violations; changed search strings to be match exact and
            search for installed or available separately
    @change: 2015/08/20 eball - Added getPackageFromFile and self.rpm var
    @change: 2016/08/02 eball - Moved checkInstall return out of else block
    @change: 2017/04/19 Breen Malmberg - refactored multiple methods; cleaned up doc
            strings; added logging; added two methods: Update and checkUpdate;
            removed detailedresults reset in __init__ (this should always be handled
            in the calling rule); replaced detailedresults instances with logging;
            added the flag "--quiet" to the install variable
    '''

    def __init__(self, logger):
        self.logger = logger
        self.ch = CommandHelper(self.logger)
        self.zyploc = "/usr/bin/zypper"
        self.install = self.zyploc + " --non-interactive --quiet install "
        self.remove = self.zyploc + " --non-interactive remove "
        self.searchi = self.zyploc + " --non-interactive search --match-exact -i "
        self.searchu = self.zyploc + " --non-interactive search --match-exact -u "
        self.updates = self.zyploc + " lu "
        self.upzypp = self.zyploc + " up "
        self.rpm = "/usr/bin/rpm -q "
        self.pkgtype = "zypper"

    def installpackage(self, package):
        '''
        Install a package. Return a bool indicating success or failure.

        @param package: string; Name of the package to be installed, must be
                recognizable to the underlying package manager.
        @return: installed
        @rtype: bool
        @author: Derek Walker
        @change: Breen Malmberg - 12/24/2014 - fixed method doc string formatting
        @change: Breen Malmberg - 10/1/2018 - added check for package manager lock and retry loop
        '''

        installed = True
        maxtries = 12
        trynum = 0

        while psRunning("zypper"):
            trynum += 1
            if trynum == maxtries:
                self.logger.log(LogPriority.DEBUG, "Timed out while attempting to install package due to zypper package manager being in-use by another process.")
                installed = False
                return installed
            else:
                self.logger.log(LogPriority.DEBUG, "zypper package manager is in-use by another process. Waiting for it to be freed...")
                time.sleep(5)

        try:

            try:
                self.ch.executeCommand(self.install + package)
                retcode = self.ch.getReturnCode()
                if retcode != 0:
                    raise repoError('zypper', retcode)
            except repoError as repoerr:
                if not repoerr.success:
                    installed = False

            if installed:
                self.logger.log(LogPriority.DEBUG, "Package " + str(package) + " installed successfully")
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
        @author: Derek Walker
        @change: 12/24/2014 - Breen Malmberg - fixed method doc string formatting;
                fixed an issue with var 'removed' not
                being initialized before it was called
        '''

        removed = True
        maxtries = 12
        trynum = 0

        while psRunning("zypper"):
            trynum += 1
            if trynum == maxtries:
                self.logger.log(LogPriority.DEBUG, "Timed out while attempting to remove package due to zypper package manager being in-use by another process.")
                removed = False
                return removed
            else:
                self.logger.log(LogPriority.DEBUG, "zypper package manager is in-use by another process. Waiting for it to be freed...")
                time.sleep(5)

        try:

            try:
                self.ch.executeCommand(self.remove + package)
                retcode = self.ch.getReturnCode()
                if retcode != 0:
                    raise repoError('zypper', retcode)
            except repoError as repoerr:
                if not repoerr.success:
                    removed = False

            if removed:
                self.logger.log(LogPriority.DEBUG, "Package " + str(package) + " was removed successfully")
            else:
                self.logger.log(LogPriority.DEBUG, "Failed to remove package " + str(package))

        except Exception:
            raise
        return removed

    def checkInstall(self, package):
        '''
        Check the installation status of a package. Return a bool; True if
        the package is installed.

        @param string package : Name of the package whose installation status
            is to be checked, must be recognizable to the underlying package
            manager.
        @return: bool
        @author: Derek Walker
        @change: 12/24/2014 - Breen Malmberg - fixed method doc string formatting
        @change: 12/24/2014 - Breen Malmberg - changed var name 'found' to
            'installed'
        @change: 12/24/2014 - Breen Malmberg - now uses correct search syntax
        @change: 12/24/2014 - Breen Malmberg - removed detailedresults update on
            'found but not installed' as this no longer applies to this method
        '''

        installed = True
        errstr = ""
        maxtries = 12
        trynum = 0

        while psRunning("zypper"):
            trynum += 1
            if trynum == maxtries:
                self.logger.log(LogPriority.DEBUG, "Timed out while attempting to check status of  package due to zypper package manager being in-use by another process.")
                installed = False
                return installed
            else:
                self.logger.log(LogPriority.DEBUG, "zypper package manager is in-use by another process. Waiting for it to be freed...")
                time.sleep(5)

        try:

            try:
                self.ch.executeCommand(self.searchi + package)
                retcode = self.ch.getReturnCode()
                errstr = self.ch.getErrorString()
                if retcode != 0:
                    raise repoError('zypper', retcode, str(errstr))
            except repoError as repoerr:
                if not repoerr.success:
                    installed = False

            if installed:
                self.logger.log(LogPriority.DEBUG, " Package " + str(package) + " is installed")
            else:
                self.logger.log(LogPriority.DEBUG, " Package " + str(package) + " is NOT installed")

        except Exception:
            raise
        return installed

    def checkAvailable(self, package):
        '''
        check if given package is available to install on the current system

        @param: package string name of package to search for
        @return: bool
        @author: Derek Walker
        @change: 12/24/2014 - Breen Malmberg - added method documentation
        @change: 12/24/2014 - Breen Malmberg - changed var name 'found' to
            'available'
        @change: 12/24/2014 - Breen Malmberg - fixed search syntax and updated search
            variable name
        @change: Breen Malmberg - 5/1/2017 - replaced detailedresults with logging;
                added parameter validation
        '''

        available = True
        maxtries = 12
        trynum = 0

        while psRunning("zypper"):
            trynum += 1
            if trynum == maxtries:
                self.logger.log(LogPriority.DEBUG,
                                "Timed out while attempting to check availability of package, due to zypper package manager being in-use by another process.")
                available = False
                return available
            else:
                self.logger.log(LogPriority.DEBUG,
                                "zypper package manager is in-use by another process. Waiting for it to be freed...")
                time.sleep(5)

        try:

            try:
                self.ch.executeCommand(self.searchu + package)
                retcode = self.ch.getReturnCode()
                errstr = self.ch.getErrorString()
                output = self.ch.getOutput()
                if retcode != 0:
                    raise repoError('zypper', retcode, str(errstr))
                else:
                    for line in output:
                        if re.search(package, line):
                            available = True
            except repoError as repoerr:
                if not repoerr.success:
                    self.logger.log(LogPriority.WARNING, str(repoerr))
                    return False

                if available:
                    self.logger.log(LogPriority.DEBUG, "Package " + str(package) + " is available to install")
                else:
                    self.logger.log(LogPriority.DEBUG, "Package " + str(package) + " is NOT available to install")

        except Exception:
            raise
        return available

    def checkUpdate(self, package=""):
        '''
        check for available updates for specified
        package.
        if no package is specified, then check for
        updates to the entire system.

        @param package: string; name of package to check
        @return: updatesavail
        @rtype: bool
        @author: Breen Malmberg
        '''

        # zypper does not have a package-specific list updates mechanism
        # you have to list all updates or nothing

        updatesavail = True

        try:

            try:
                if package:
                    self.ch.executeCommand(self.updates + " | grep " + package)
                else:
                    self.ch.executeCommand(self.updates)
                retcode = self.ch.getReturnCode()
                errstr = self.ch.getErrorString()
                if retcode != 0:
                    raise repoError('zypper', retcode, str(errstr))
            except repoError as repoerr:
                if not repoerr.success:
                    self.logger.log(LogPriority.WARNING, str(errstr))
                    updatesavail = False

            if package:
                if not updatesavail:
                    self.logger.log(LogPriority.DEBUG, "No updates are available for package " + str(package))
                else:
                    self.logger.log(LogPriority.DEBUG, "Updates are available for package " + str(package))

            else:
                if not updatesavail:
                    self.logger.log(LogPriority.DEBUG, "No updates are available")
                else:
                    self.logger.log(LogPriority.DEBUG, "Updates are available")

        except Exception:
            raise
        return updatesavail

    def Update(self, package=""):
        '''
        update a specified package
        if no package name is specified,
        then update all packages on the system

        @param package: string; name of package to update
        @return: updated
        @rtype: bool
        @author: Breen Malmberg
        '''

        updated = True

        try:

            try:
                self.ch.executeCommand(self.upzypp + package)
                retcode = self.ch.getReturnCode()
                errstr = self.ch.getErrorString()
                if retcode != 0:
                    raise repoError('zypper', retcode, str(errstr))
            except repoError as repoerr:
                if not repoerr.success:
                    self.logger.log(LogPriority.WARNING, str(errstr))
                    updated = False

        except Exception:
            raise
        return updated

    def getPackageFromFile(self, filename):
        '''Returns the name of the package that provides the given
        filename/path.

        @param: string filename : The name or path of the file to resolve
        @return: string name of package if found, None otherwise
        @author: Eric Ball
        '''

        packagename = ""

        try:

            try:
                self.ch.executeCommand(self.rpm + "-f " + filename)
                retcode = self.ch.getReturnCode()
                errstr = self.ch.getErrorString()
                outputstr = self.ch.getOutputString()
                if retcode != 0:
                    raise repoError('zypper', retcode, str(errstr))
                    # return ""
                else:
                    packagename = outputstr
            except repoError as repoerr:
                if not repoerr.success:
                    self.logger.log(LogPriority.WARNING, str(errstr))
                else:
                    packagename = outputstr

        except Exception:
            raise

        return packagename

    def getInstall(self):
        '''
        return the install command string for the zypper pkg manager

        @return: string
        @author: Derek Walker
        @change: 12/24/2014 - Breen Malmberg - added method documentation
        '''

        return self.install

    def getRemove(self):
        '''
        return the uninstall/remove command string for the zypper pkg manager

        @return: string
        @author: Derek Walker
        @change: 12/24/2014 - Breen Malmberg - added method documentation
        '''

        return self.remove
