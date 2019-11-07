###############################################################################
#                                                                             #
# Copyright 2019. Triad National Security, LLC. All rights reserved.          #
# This program was produced under U.S. Government contract 89233218CNA000001  #
# for Los Alamos National Laboratory (LANL), which is operated by Triad       #
# National Security, LLC for the U.S. Department of Energy/National Nuclear   #
# Security Administration.                                                    #
#                                                                             #
# All rights in the program are reserved by Triad National Security, LLC, and #
# the U.S. Department of Energy/National Nuclear Security Administration. The #
# Government is granted for itself and others acting on its behalf a          #
# nonexclusive, paid-up, irrevocable worldwide license in this material to    #
# reproduce, prepare derivative works, distribute copies to the public,       #
# perform publicly and display publicly, and to permit others to do so.       #
#                                                                             #
###############################################################################

'''
Created on Aug 13, 2015

@author: Derek T. Walker
'''

import re
import os
import time

from stonix_resources.stonixutilityfunctions import psRunning
from stonix_resources.logdispatcher import LogPriority
from stonix_resources.CommandHelper import CommandHelper
from stonix_resources.StonixExceptions import repoError


class Dnf(object):
    '''The template class that provides a framework that must be implemented by
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
        self.lockfiles = ["/var/run/dnf.lock", "/var/run/dnf.pid", "/run/dnf.lock", "/run/dnf.pid"]

    def installpackage(self, package):
        '''Install a package. Return a bool indicating success or failure.

        :param package: string; Name of the package to be installed, must be
                recognizable to the underlying package manager.
        :returns: installed
        :rtype: bool
@author: Derek T. Walker
@change: Breen Malmberg - 4/18/2017 - refactored method; added logging; replaced
        detailedresults with logging
@change: Breen Malmberg - 10/1/2018 - added check for package manager lock and retry loop

        '''

        installed = True
        maxtries = 12
        trynum = 0

        while psRunning("dnf"):
            trynum += 1
            if trynum == maxtries:
                self.logger.log(LogPriority.DEBUG, "Timed out while attempting to install package, due to dnf package manager being in-use by another process.")
                installed = False
                return installed
            else:
                self.logger.log(LogPriority.DEBUG, "dnf package manager is in-use by another process. Waiting for it to be freed...")
                time.sleep(5)

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
        '''Remove a package. Return a bool indicating success or failure.

        :param package: string; Name of the package to be removed, must be
                recognizable to the underlying package manager.
        :returns: removed
        :rtype: bool
@author: Derek T. Walker
@change: Breen Malmberg - 4/18/2017

        '''

        removed = True
        maxtries = 12
        trynum = 0

        while psRunning("dnf"):
            trynum += 1
            if trynum == maxtries:
                self.logger.log(LogPriority.DEBUG, "Timed out while attempting to remove package, due to dnf package manager being in-use by another process.")
                installed = False
                return installed
            else:
                self.logger.log(LogPriority.DEBUG, "dnf package manager is in-use by another process. Waiting for it to be freed...")
                time.sleep(5)

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
        '''Check the installation status of a package. Return a bool; True if
        the package is installed.

        :param package: 
        :returns: installed
        :rtype: bool
@author: Derek T. Walker
@change: Breen Malmberg - 4/18/2017

        '''

        installed = False
        errstr = ""
        outputstr = ""
        maxtries = 12
        trynum = 0

        while psRunning("dnf"):
            trynum += 1
            if trynum == maxtries:
                self.logger.log(LogPriority.DEBUG, "Timed out while attempting to check status of package, due to dnf package manager being in-use by another process.")
                installed = False
                return installed
            else:
                self.logger.log(LogPriority.DEBUG, "dnf package manager is in-use by another process. Waiting for it to be freed...")
                time.sleep(5)

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
        '''check if the given package is available to install

        :param package: string; name of package to check for
        :returns: found
        :rtype: bool
@author: Derek T. Walker
@change: Breen Malmberg - 4/18/2017 - added doc string; refactor of method

        '''

        found = False
        maxtries = 12
        trynum = 0

        while psRunning("dnf"):
            trynum += 1
            if trynum == maxtries:
                self.logger.log(LogPriority.DEBUG,
                                "Timed out while attempting to check availability of package, due to dnf package manager being in-use by another process.")
                found = False
                return found
            else:
                self.logger.log(LogPriority.DEBUG,
                                "dnf package manager is in-use by another process. Waiting for it to be freed...")
                time.sleep(5)

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
        '''check the specified package for updates
        if no package is specified, check for all/any
        updates on the system
        return True if there are updates available
        return False if there are no updates available

        :param package: string; name of package to check (Default value = "")
        :returns: updatesavail
        :rtype: bool
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
        '''update the specified package
        if no package is specified, update
        all packages on the system

        :param package: string; name of package to update (Default value = "")
        :returns: updated
        :rtype: bool
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
        '''return a string with the name of the parent package
        in it

        :param filename: 
        :returns: packagename
        :rtype: string
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
