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

"""
Created on Aug 08, 2012

@author: Derek T. Walker
"""

import re
import time

from .stonixutilityfunctions import psRunning
from .logdispatcher import LogPriority
from .CommandHelper import CommandHelper


class Zypper(object):
    """The template class that provides a framework that must be implemented by
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


    """

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
        self.pkgerrs = [1,2,3,4,5,6]
        self.pkgnotfound = [104]

    def installpackage(self, package):
        """Install a package. Return a bool indicating success or failure.

        :param package: string; Name of the package to be installed, must be
                recognizable to the underlying package manager.
        :returns: installed
        :rtype: bool
@author: Derek Walker
@change: Breen Malmberg - 12/24/2014 - fixed method doc string formatting
@change: Breen Malmberg - 10/1/2018 - added check for package manager lock and retry loop

        """

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

            self.ch.executeCommand(self.install + package)
            retcode = self.ch.getReturnCode()
            if retcode in self.pkgerrs:
                errstr = self.ch.getErrorString()
                self.logger.log(LogPriority.DEBUG, "Package installation because:\n" + errstr)
                installed = False
            elif retcode in self.pkgnotfound:
                self.logger.log(LogPriority.DEBUG, "Package installation failed because zypper could not find a package named: " + str(package))
                installed = False

            if installed:
                self.logger.log(LogPriority.DEBUG, "Package " + str(package) + " installed successfully")
            else:
                self.logger.log(LogPriority.DEBUG, "Failed to install package " + str(package))

        except Exception:
            raise
        return installed

    def removepackage(self, package):
        """Remove a package. Return a bool indicating success or failure.

        :param package: string; Name of the package to be removed, must be
                recognizable to the underlying package manager.
        :returns: removed
        :rtype: bool
@author: Derek Walker
@change: 12/24/2014 - Breen Malmberg - fixed method doc string formatting;
        fixed an issue with var 'removed' not
        being initialized before it was called

        """

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

            self.ch.executeCommand(self.remove + package)
            retcode = self.ch.getReturnCode()
            if retcode in self.pkgerrs:
                errstr = self.ch.getErrorString()
                self.logger.log(LogPriority.DEBUG, "Package removal failed because:\n" + errstr)
                removed = False
            elif retcode in self.pkgnotfound:
                self.logger.log(LogPriority.DEBUG, "No package found matching: " + str(package) + ". Nothing to remove")

            if removed:
                self.logger.log(LogPriority.DEBUG, "Package " + str(package) + " was removed successfully")
            else:
                self.logger.log(LogPriority.DEBUG, "Failed to remove package " + str(package))

        except Exception:
            raise
        return removed

    def checkInstall(self, package):
        """Check the installation status of a package. Return a bool; True if
        the package is installed.

        :param string package: Name of the package whose installation status
            is to be checked, must be recognizable to the underlying package
            manager.
        :param package: 
        :returns: bool
        @author: Derek Walker
        @change: 12/24/2014 - Breen Malmberg - fixed method doc string formatting
        @change: 12/24/2014 - Breen Malmberg - changed var name 'found' to
            'installed'
        @change: 12/24/2014 - Breen Malmberg - now uses correct search syntax
        @change: 12/24/2014 - Breen Malmberg - removed detailedresults update on
            'found but not installed' as this no longer applies to this method

        """

        installed = True
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

            self.ch.executeCommand(self.searchi + package)
            retcode = self.ch.getReturnCode()
            if retcode in self.pkgerrs:
                errstr = self.ch.getErrorString()
                self.logger.log(LogPriority.DEBUG, "Failed to check for package: " + str(package) + " because:\n" + errstr)
                installed = False
            elif retcode in self.pkgnotfound:
                installed = False

            if installed:
                self.logger.log(LogPriority.DEBUG, " Package " + str(package) + " is installed")
            else:
                self.logger.log(LogPriority.DEBUG, " Package " + str(package) + " is NOT installed")

        except Exception:
            raise
        return installed

    def checkAvailable(self, package):
        """check if given package is available to install on the current system

        :param package: 
        :returns: bool
        @author: Derek Walker
        @change: 12/24/2014 - Breen Malmberg - added method documentation
        @change: 12/24/2014 - Breen Malmberg - changed var name 'found' to
            'available'
        @change: 12/24/2014 - Breen Malmberg - fixed search syntax and updated search
            variable name
        @change: Breen Malmberg - 5/1/2017 - replaced detailedresults with logging;
                added parameter validation

        """

        available = True
        found = False
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

            self.ch.executeCommand(self.searchu + package)
            retcode = self.ch.getReturnCode()
            if retcode in self.pkgerrs:
                errstr = self.ch.getErrorString()
                self.logger.log(LogPriority.DEBUG, "Failed to check if package: " + str(package) + " is available, because:\n" + errstr)
                available = False
            elif retcode in self.pkgnotfound:
                available = False
            else:
                output = self.ch.getOutput()
                for line in output:
                    if re.search(package, line):
                        found = True
                if not found:
                    available = False

            if available:
                self.logger.log(LogPriority.DEBUG, "Package " + str(package) + " is available to install")
            else:
                self.logger.log(LogPriority.DEBUG, "Package " + str(package) + " is NOT available to install")

        except Exception:
            raise
        return available

    def checkUpdate(self, package=""):
        """check for available updates for specified
        package.
        if no package is specified, then check for
        updates to the entire system.

        :param package: string; name of package to check (Default value = "")
        :returns: updatesavail
        :rtype: bool
@author: Breen Malmberg

        """

        # zypper does not have a package-specific list updates mechanism
        # you have to list all updates or nothing

        updatesavail = True

        try:

            if package:
                self.ch.executeCommand(self.updates + " | grep " + package)
            else:
                self.ch.executeCommand(self.updates)

            retcode = self.ch.getReturnCode()
            if retcode in [2,3,4,5,6]:
                errstr = self.ch.getErrorString()
                self.logger.log(LogPriority.DEBUG, "Failed to check for updates because:\n" + errstr)
                updatesavail = False
            elif retcode in self.pkgnotfound:
                updatesavail = False

            if not updatesavail:
                self.logger.log(LogPriority.DEBUG, "No updates available")
            else:
                self.logger.log(LogPriority.DEBUG, "Updates available")

        except Exception:
            raise
        return updatesavail

    def Update(self, package=""):
        """update a specified package
        if no package name is specified,
        then update all packages on the system

        :param package: string; name of package to update (Default value = "")
        :returns: updated
        :rtype: bool
@author: Breen Malmberg

        """

        updated = True

        try:

            self.ch.executeCommand(self.upzypp + package)
            retcode = self.ch.getReturnCode()
            if retcode in self.pkgerrs:
                errstr = self.ch.getErrorString()
                self.logger.log(LogPriority.DEBUG, "Failed to update because:\n" + errstr)
                updated = False
            elif retcode in self.pkgnotfound:
                self.logger.log(LogPriority.DEBUG, "Unable to find package named: " + str(package))
                updated = False

            if updated:
                self.logger.log(LogPriority.DEBUG, "Updates applied successfully")
            else:
                self.logger.log(LogPriority.DEBUG, "Failed to apply updates")

        except Exception:
            raise
        return updated

    def getPackageFromFile(self, filename):
        """Returns the name of the package that provides the given
        filename/path.

        :param filename: 
        :returns: string name of package if found, None otherwise
        @author: Eric Ball

        """

        packagename = ""

        try:

            self.ch.executeCommand(self.rpm + "-f " + filename)
            retcode = self.ch.getReturnCode()
            if retcode in self.pkgerrs:
                errstr = self.ch.getErrorString()
                self.logger.log(LogPriority.DEBUG, "Failed to get package name because:\n" + errstr)
            else:
                outputstr = self.ch.getOutputString()
                packagename = outputstr

        except Exception:
            raise

        return packagename

    def getInstall(self):
        """return the install command string for the zypper pkg manager


        :returns: string
        @author: Derek Walker
        @change: 12/24/2014 - Breen Malmberg - added method documentation

        """

        return self.install

    def getRemove(self):
        """return the uninstall/remove command string for the zypper pkg manager


        :returns: string
        @author: Derek Walker
        @change: 12/24/2014 - Breen Malmberg - added method documentation

        """

        return self.remove
