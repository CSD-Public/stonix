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



from .logdispatcher import LogPriority
from .CommandHelper import CommandHelper


class Freebsd(object):
    '''The template class that provides a framework that must be implemented by
    all platform specific pkgmgr classes.
    
    :version:
    @author: Derek T Walker 08-06-2012


    '''

    def __init__(self, logger):
        self.logger = logger
        self.ch = CommandHelper(self.logger)
        self.install = "/usr/sbin/pkg_add -r -f "
        self.remove = "/usr/sbin/pkg_delete "
        self.info = "/usr/sbin/pkg_info "
        self.versioncheck = "/usr/sbin/pkg_version -l < "

###############################################################################
    def installpackage(self, package):
        '''Install a package. Return a bool indicating success or failure.

        :param string: package : Name of the package to be installed, must be
                recognizable to the underlying package manager.
        :param package: 
        :returns: installed
        :rtype: bool
@author: Derek T. Walker
@change: Breen Malmberg - 4/18/2017 - doc string fixes; refactor
        of method; parameter validation

        '''

        installed = False

        try:

            # parameter validation
            if not package:
                self.logger.log(LogPriority.DEBUG, "Parameter: package was blank!")
                return installed
            if not isinstance(package, str):
                self.logger.log(LogPriority.DEBUG, "Parameter: package needs to be of type string. Got: " + str(type(package)))
                return installed

            self.ch.executeCommand(self.install + package)

            if self.ch.getReturnCode() == 0:
                self.logger.log(LogPriority.DEBUG, "Package " + str(package) + " installed successfully")
                installed = True
            else:
                self.logger.log(LogPriority.DEBUG, "Failed to install package " + str(package))

        except Exception:
            raise
        return installed

###############################################################################
    def removepackage(self, package):
        '''Remove a package. Return a bool indicating success or failure.

        :param package: string; Name of the package to be removed, must be
                recognizable to the underlying package manager.
        :returns: removed
        :rtype: bool
@author: Derek T. Walker
@change: Breen Malmberg - 4/18/2017 - refactor of method; doc string fixes;
        parameter validation

        '''

        removed = True

        try:

            # parameter validation
            if not package:
                self.logger.log(LogPriority.DEBUG, "Parameter: package was blank!")
                return removed
            if not isinstance(package, str):
                self.logger.log(LogPriority.DEBUG, "Parameter: package needs to be of type string. Got: " + str(type(package)))
                return removed

            self.ch.executeCommand(self.remove + package)
            retcode = self.ch.getReturnCode()
            if retcode != 0:
                self.logger.log(LogPriority.DEBUG, "Failed to remove package " + str(package))
                removed = False
            else:
                self.logger.log(LogPriority.DEBUG, "Successfully removed package " + str(package))

        except Exception:
            raise
        return removed

###############################################################################
    def checkInstall(self, package):
        '''Check the installation status of a package. Return a bool; True if
        the package is installed.

        :param package: string; Name of the package whose installation status
                is to be checked, must be recognizable to the underlying package
                manager.
        :returns: installed
        :rtype: bool
@author: Derek T. Walker
@change: Breen Malmberg - 4/18/2017 - refactor of method; doc
        string fixes; parameter validation

        '''

        installed = False

        try:

            # parameter validation
            if not package:
                self.logger.log(LogPriority.DEBUG, "Parameter: package was blank!")
                return installed
            if not isinstance(package, str):
                self.logger.log(LogPriority.DEBUG, "Parameter: package needs to be of type string. Got: " + str(type(package)))
                return installed

            self.ch.executeCommand(self.info + package)
            retcode = self.ch.getReturnCode()
            if retcode != 0:
                self.logger.log(LogPriority.DEBUG, "Package " + str(package) + " is NOT installed")
            else:
                self.logger.log(LogPriority.DEBUG, "Package " + str(package) + " is installed")
                installed = True

        except Exception:
            raise
        return installed

    def checkUpdate(self, package=""):
        '''STUB METHOD
        check for updates for the specified package
        if package is not specified, check for all
        package updates
        
        currently unfinished as I have no earthly idea
        how to reliably manage packages on bsd
        (ports? portsmanager? portsmaster? pkg_zzz? pkg?)
        also versioning heavily affects what package manager
        binary(ies) is/are available.

        :param package: string; name of package to check (Default value = "")
        :returns: updatesavail
        :rtype: bool
@author: Breen Malmberg

        '''

        updatesavail = False

        try:

            pass # stub

        except Exception:
            raise
        return updatesavail

    def Update(self, package=""):
        '''STUB METHOD
        update the specified package
        if no package is specified, then update
        all packages on the system
        
        currently unfinished as I have no earthly idea
        how to reliably manage packages on bsd
        (ports? portsmanager? portsmaster? pkg_zzz? pkg?)
        also versioning heavily affects what package manager
        binary(ies) is/are available.

        :param package: string; name of package to update (Default value = "")
        :returns: updated
        :rtype: bool
@author: Breen Malmberg

        '''

        updated = False

        try:

            pass # stub

        except Exception:
            raise
        return updated

    def getPackageFromFile(self, filename):
        '''return a string containing the name of the package
        which provides the specified filename

        :param filename: 
        :returns: packagename
        :rtype: string
@author: Breen Malmberg

        '''

        packagename = ""

        try:

            # parameter validation
            if not filename:
                self.logger.log(LogPriority.DEBUG, "Parameter: filename was blank!")
                return packagename
            if not isinstance(filename, str):
                self.logger.log(LogPriority.DEBUG, "Parameter: filename needs to be of type string. Got: " + str(type(filename)))
                return packagename

            self.ch.executeCommand(self.info + " -W " + filename)
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

    def getInfo(self):
        return self.info
