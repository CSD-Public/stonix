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
from StonixExceptions import repoError


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
        self.checkinstalled = self.dnfloc + " list --installed "
        self.chavailable = self.dnfloc + " list --available "
        self.checkupdate = self.dnfloc + " check-update "
        self.rpm = "/bin/rpm -qf "
        self.updatepackage = self.dnfloc + " -yq upgrade " 

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

        installed = True

        try:

            try:
                self.ch.executeCommand(self.install + package)
                retcode = self.ch.getReturnCode()
                if retcode != 0:
                    raise repoError('dnf', retcode)
            except repoError as repoerr:
                if not repoerr.success:
                    installed = False

            if installed:
                self.logger.log(LogPriority.DEBUG, "Successfully installed package " + str(package))
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
        @change: Breen Malmberg - 4/18/2017
        '''

        removed = True

        try:

            try:
                self.ch.executeCommand(self.remove + package)
                retcode = self.ch.getReturnCode()
                if retcode != 0:
                    raise repoError('dnf', retcode)
            except repoError as repoerr:
                if not repoerr.success:
                    removed = False

            if removed:
                self.logger.log(LogPriority.DEBUG, "Package " + str(package) + " was successfully removed")
            else:
                self.logger.log(LogPriority.DEBUG, "Failed to remove package " + str(package))

        except Exception:
            raise
        return removed

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

            try:
                # There is no dnf search command which will only return an 
                # "installed" result set. Therefore we must parse the output 
                # to determine if the package is installed or just available.
                # The below command string will produce stdout with only the 
                # installed result set of packages 
                self.ch.executeCommand(self.checkinstalled + package + " | grep -iA 1 installed")
                retcode = self.ch.getReturnCode()
                errstr = self.ch.getErrorString()
                outputstr = self.ch.getOutputString()
                # With this command specifically, in this package manager, we 
                # can't count exit code 1 as being an error because the check installed 
                # command (with dnf) will return an error (1) exit code if no results are 
                # returned, even if there is no error. We also can't use error or output strings 
                # to parse because it is possible for this command to also return no output of any 
                # kind, in addition to returning a 1 exit code... Therefore we must exempt exit 
                # code 1 for this command specifically...
                if retcode != 0|1:
                    raise repoError('dnf', retcode, str(errstr))
                else:
                    if re.search(package, outputstr, re.IGNORECASE):
                        installed = True
            except repoError as repoerr:
                if not repoerr.success:
                    self.logger.log(LogPriority.WARNING, str(errstr))
                    installed = False
                else:
                    if re.search(package, outputstr, re.IGNORECASE):
                        installed = True

            if installed:
                self.logger.log(LogPriority.DEBUG, "Package " + str(package) + " is installed")
            else:
                self.logger.log(LogPriority.DEBUG, "Package " + str(package) + " is NOT installed")

        except Exception:
            raise
        return installed

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

            try:
                self.ch.executeCommand(self.chavailable + package)
                retcode = self.ch.getReturnCode()
                outputstr = self.ch.getOutputString()
                errstr = self.ch.getErrorString()
                if retcode != 0:
                    raise repoError('dnf', retcode, str(errstr))
                else:
                    if re.search(package, outputstr, re.IGNORECASE):
                        found = True
            except repoError as repoerr:
                if not repoerr.success:
                    self.logger.log(LogPriority.WARNING, str(errstr))
                else:
                    if re.search(package, outputstr, re.IGNORECASE):
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

            try:
                self.ch.executeCommand(self.checkupdate + package)
                retcode = self.ch.getReturnCode()
                errstr = self.ch.getErrorString()
                if retcode != 0:
                    raise repoError('dnf', retcode)
            except repoError as repoerr:
                if not repoerr.success:
                    self.logger.log(LogPriority.WARNING, str(errstr))
                    return False
                else:
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

            try:
                self.ch.executeCommand(self.updatepackage + package)
                retcode = self.ch.getReturnCode()
                errstr = self.ch.getErrorString()
                if retcode != 0:
                    raise repoError('dnf', retcode)
                else:
                    updated = True
            except repoError as repoerr:
                if not repoerr.success:
                    self.logger.log(LogPriority.WARNING, str(errstr))
                    return False
                else:
                    updated = True

            if package:
                if updated:
                    self.logger.log(LogPriority.DEBUG, "Package " + str(package) + " successfully updated")
                else:
                    self.logger.log(LogPriority.DEBUG, "Package " + str(package) + " was NOT updated")
            else:
                if updated:
                    self.logger.log(LogPriority.DEBUG, "All packages updated successfully")
                else:
                    self.logger.log(LogPriority.DEBUG, "One or more packages failed to update properly")

        except Exception:
            raise
        return updated

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

            try:
                self.ch.executeCommand(self.rpm + filename)
                retcode = self.ch.getReturnCode()
                errstr = self.ch.getErrorString()
                outputstr = self.ch.getOutputString()
                if retcode != 0:
                    raise repoError('dnf', retcode, str(errstr))
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
        return self.install

    def getRemove(self):
        return self.remove

    def getSearch(self):
        return self.search

    def getInfo(self):
        return self.info

    def getCheck(self):
        return self.checkupdate
