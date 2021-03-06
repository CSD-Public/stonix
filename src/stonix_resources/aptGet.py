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
Created on Aug 06, 2012

@author: Derek T. Walker
"""

import re
import time

from stonix_resources.stonixutilityfunctions import psRunning
from stonix_resources.logdispatcher import LogPriority
from stonix_resources.CommandHelper import CommandHelper
from stonix_resources.StonixExceptions import repoError


class AptGet(object):
    """Linux specific package manager for distributions that use the apt-get
    command to install packages.
    
    @author: Derek T Walker
    @change: 2012/08/06 Derek Walker - Original Implementation
    @change: 2015/08/20 eball - Added getPackageFromFile
    @change: 2017/04/27 Breen Malmberg - added two methods checkUpdate
            and Update; fixed doc string formatting; removed detailedresults
            reset in init; replaced with --force-yes flag with --assume-yes
            (from the man page for apt-get: Force yes. This is a dangerous
            option that will cause apt-get to continue without prompting
            if it is doing something potentially harmful. It should not
            be used except in very special situations. Using --force-yes
            can potentially destroy your system!)
    @change: 2017/08/16 bgonz12 - Added DEBIAN_FRONTEND=noninteractive env var
            to remove function
    @change: 2017/10/18 Breen Malmberg - changed class var names to be more self-explanatory;
            changed command to check whether there are available packages to use the canonical
            debian/ubuntu method; added calls to repoError exception to determine exact nature
            and cause of any errors with querying or calling repositories on the system (this adds
            logging of the nature and cause(s) as well); changed log messaging to be more consistent
            in style/format; removed calls to validateParam due to concerns about the stability and
            reliability of that method


    """

    def __init__(self, logger):

        self.logger = logger
        self.ch = CommandHelper(self.logger)

        self.aptgetloc = "/usr/bin/apt-get"
        self.aptcacheloc = "/usr/bin/apt-cache"
        self.dpkgloc = "/usr/bin/dpkg"

        self.aptinstall = "DEBIAN_FRONTEND=noninteractive " + self.aptgetloc + " -y --assume-yes install "
        self.aptremove = "DEBIAN_FRONTEND=noninteractive " + self.aptgetloc + " -y remove "

        self.aptchkupdates = self.aptgetloc + " list --upgradeable "
        self.aptupgrade = self.aptgetloc + " -u upgrade --assume-yes "
        self.checkinstalled = "/usr/bin/apt list --installed "
        self.checkavailable = "/usr/bin/apt-cache search --names-only "
        self.findpkgforfilename = "/usr/bin/dpkg -S "
        self.pkgerrors = [1,100]

    def installpackage(self, package):
        """Install a package. Return a bool indicating success or failure.

        :param package: string; Name of the package to be installed, must be
                recognizable to the underlying package manager.
        :returns: installed
        :rtype: bool
@author: Derek Walker
@change: Breen Malmberg - 4/27/2017 - fixed doc string formatting;
        method now returns a variable; parameter validation added
        detailedresults replaced with logging
@change: Breen Malmberg - 10/1/2018 - added check for package manager lock and retry loop

        """

        installed = True
        maxtries = 12
        trynum = 0
        pslist = ["apt", "apt-get", "dpkg"]

        if type(package) is bytes:
            package = package.decode('utf-8')

        for ps in pslist:
            while psRunning(ps):
                trynum += 1
                if trynum == maxtries:
                    self.logger.log(LogPriority.DEBUG, "Timed out while attempting to install package, due to Apt package manager being in-use by another process.")
                    installed = False
                    return installed
                else:
                    self.logger.log(LogPriority.DEBUG, "Apt package manager is in-use by another process. Waiting for it to be freed...")
                    time.sleep(5)

        try:

            self.ch.executeCommand(self.aptinstall + package)
            retcode = self.ch.getReturnCode()
            errstr = self.ch.getErrorString()
            # recursive call to this method if package manager is still locked
            if re.search("Could not get lock", errstr, re.I):
                self.logger.log(LogPriority.DEBUG, "Apt package manager is in-use by another process. Waiting for it to be freed...")
                time.sleep(5)
                return self.installpackage(package)
            elif retcode in self.pkgerrors:
                installed = False
                self.logger.log(LogPriority.DEBUG, str(errstr))

            if installed:
                self.logger.log(LogPriority.DEBUG, "Successfully installed package " + str(package))
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
@author: Derek T. Walker

        """

        removed = True
        maxtries = 12
        trynum = 0
        pslist = ["apt", "apt-get", "dpkg"]

        if type(package) is bytes:
            package = package.decode('utf-8')

        for ps in pslist:
            while psRunning(ps):
                trynum += 1
                if trynum == maxtries:
                    self.logger.log(LogPriority.DEBUG, "Timed out while attempting to remove package, due to Apt package manager being in-use by another process.")
                    removed = False
                    return removed
                else:
                    self.logger.log(LogPriority.DEBUG, "Apt package manager is in-use by another process. Waiting for it to be freed...")
                    time.sleep(5)

        try:

            self.ch.executeCommand(self.aptremove + package)
            retcode = self.ch.getReturnCode()
            if retcode in self.pkgerrors:
                errstr = self.ch.getErrorString()
                removed = False
                self.logger.log(LogPriority.DEBUG, str(errstr))

            if removed:
                self.logger.log(LogPriority.DEBUG, "Successfully removed package " + str(package))
            else:
                self.logger.log(LogPriority.DEBUG, "Failed to remove package " + str(package))

        except Exception:
            raise
        return removed

    def checkInstall(self, package):
        """Check the installation status of a package. Return a bool; True if
        the package is installed.

        :param package: 
        :returns: installed
        :rtype: bool
@author: Derek Walker
@change: Breen Malmberg - 4/27/2017 - fixed doc string formatting;
        method now returns a variable; replaced detailedresults with
        logging

        """

        installed = False
        maxtries = 12
        trynum = 0
        pslist = ["apt", "apt-get", "dpkg"]

        if type(package) is bytes:
            package = package.decode('utf-8')

        for ps in pslist:
            while psRunning(ps):
                trynum += 1
                if trynum == maxtries:
                    self.logger.log(LogPriority.DEBUG, "Timed out while attempting to check status of package, due to Apt package manager being in-use by another process.")
                    installed = False
                    return installed
                else:
                    self.logger.log(LogPriority.DEBUG, "Apt package manager is in-use by another process. Waiting for it to be freed...")
                    time.sleep(5)

        try:

            self.ch.executeCommand(self.checkinstalled + package)
            retcode = self.ch.getReturnCode()
            outputstr = self.ch.getOutputString()
            if retcode in self.pkgerrors:
                errstr = self.ch.getErrorString()
                self.logger.log(LogPriority.DEBUG, str(errstr))

            if re.search(package + ".*installed", outputstr, re.I):
                installed = True

            if not installed:
                self.logger.log(LogPriority.DEBUG, "Package " + str(package) + " is NOT installed")
            else:
                self.logger.log(LogPriority.DEBUG, "Package " + str(package) + " is installed")

        except Exception:
            raise
        return installed

    def checkAvailable(self, package):
        """check if a given package is available

        :param package: string; Name of package to check
        :returns: found
        :rtype: bool
@author: Derek T. Walker
@change: Breen Malmberg - 4/27/2017 - created doc string;
        pulled result logging out of conditional

        """

        found = False
        outputstr = ""
        maxtries = 12
        trynum = 0
        pslist = ["apt", "apt-get", "dpkg"]

        if type(package) is bytes:
            package = package.decode('utf-8')

        for ps in pslist:
            while psRunning(ps):
                trynum += 1
                if trynum == maxtries:
                    self.logger.log(LogPriority.DEBUG,
                                    "Timed out while attempting to check availability of package, due to apt package manager being in-use by another process.")
                    available = False
                    return available
                else:
                    self.logger.log(LogPriority.DEBUG,
                                    "apt package manager is in-use by another process. Waiting for it to be freed...")
                    time.sleep(5)

        try:

            self.ch.executeCommand(self.checkavailable + "^" + package + "$")
            retcode = self.ch.getReturnCode()
            if retcode in self.pkgerrors:
                errstr = self.ch.getErrorString()
                self.logger.log(LogPriority.DEBUG, errstr)
            else:
                outputstr = self.ch.getOutputString()
                if re.search("^" + package, outputstr, re.I):
                    found = True

            if found:
                self.logger.log(LogPriority.DEBUG, "Package " + str(package) + " is available to install")
            else:
                self.logger.log(LogPriority.DEBUG, "Package " + str(package) + " is NOT available to install")

        except Exception:
            raise
        return found

    def Update(self, package=""):
        """update the specified package if any
        updates are available for it
        if no package is specified, apply
        all available updates for the system

        :param package: string; (OPTIONAL) name of package to update (Default value = "")
        :returns: updated
        :rtype: bool
@author: Breen Malmberg

        """

        updated = True

        try:

            if type(package) is bytes:
                package = package.decode('utf-8')

            self.ch.executeCommand(self.aptupgrade + package)
            retcode = self.ch.getReturnCode()
            if retcode in self.pkgerrors:
                errstr = self.ch.getErrorString()
                updated = False
                self.logger.log(LogPriority.DEBUG, errstr)

            if package:
                if updated:
                    self.logger.log(LogPriority.DEBUG, "Package " + str(package) + " was updated successfully")
                else:
                    self.logger.log(LogPriority.DEBUG, "Failed to apply updates to package " + str(package))
            else:
                if updated:
                    self.logger.log(LogPriority.DEBUG, "All updates were installed successfully")
                else:
                    self.logger.log(LogPriority.DEBUG, "Failed to apply updates")

        except Exception:
            raise
        return updated

    def checkUpdate(self, package=""):
        """check for updates for specified package
        if no package is specified, then check
        for updates for the entire system

        :param package: string; (OPTIONAL) Name of package to check (Default value = "")
        :returns: updatesavail
        :rtype: bool
@author: Breen Malmberg

        """

        updatesavail = False

        try:

            self.ch.executeCommand(self.aptchkupdates + package)
            retcode = self.ch.getReturnCode()
            if retcode in self.pkgerrors:
                errstr = self.ch.getErrorString()
                self.logger.log(LogPriority.DEBUG, errstr)
            else:
                outputstr = self.ch.getOutputString()
                if re.search("upgradable", outputstr, re.I):
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

    def getPackageFromFile(self, filename):
        """Returns the name of the package that provides the given
        filename/path.

        :param filename: 
        :returns: packagename
        :rtype: string
@author: Eric Ball
@change: Breen Malmberg - 4/17/2017 - fixed doc string formatting;
        method now returns a variable; added param validation

        """

        packagename = ""

        try:

            try:
                self.ch.executeCommand(self.findpkgforfilename + filename)
                retcode = self.ch.getReturnCode()
                errstr = self.ch.getErrorString()
                if retcode != 0:
                    raise repoError('apt', retcode, str(errstr))
                if self.ch.getReturnCode() == 0:
                    output = self.ch.getOutputString()
                    packagename = output.split(":")[0]
            except repoError as repoerr:
                if not repoerr.success:
                    self.logger.log(LogPriority.WARNING, str(errstr))
                    pass

        except Exception:
            raise
        return packagename

    def getInstall(self):
        return self.aptinstall

    def getRemove(self):
        return self.aptremove
