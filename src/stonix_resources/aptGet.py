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

from logdispatcher import LogPriority
from CommandHelper import CommandHelper
from StonixExceptions import repoError


class AptGet(object):
    '''
    Linux specific package manager for distributions that use the apt-get
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
    '''

    def __init__(self, logger):

        self.logger = logger
        self.ch = CommandHelper(self.logger)

        self.aptgetloc = "/usr/bin/apt-get"
        self.aptcacheloc = "/usr/bin/apt-cache"
        self.dpkgloc = "/usr/bin/dpkg"

        self.aptinstall = "DEBIAN_FRONTEND=noninteractive " + self.aptgetloc + " -y --assume-yes install "
        self.aptremove = "DEBIAN_FRONTEND=noninteractive " + self.aptgetloc + " -y remove "

        self.dpkgsearch = self.dpkgloc + " -S "
        self.dpkgchkinstalled = self.dpkgloc + " -l "
        self.aptchkupdates = self.aptgetloc + " -u upgrade --assume-no "
        self.aptupgrade = self.aptgetloc + " -u upgrade --assume-yes "
        self.aptchkavail = self.aptcacheloc +  " policy "

    def installpackage(self, package):
        '''
        Install a package. Return a bool indicating success or failure.

        @param package: string; Name of the package to be installed, must be
                recognizable to the underlying package manager.
        @return: installed
        @rtype: bool
        @author: Derek Walker
        @change: Breen Malmberg - 4/27/2017 - fixed doc string formatting;
                method now returns a variable; parameter validation added
                detailedresults replaced with logging
        '''

        installed = True

        try:

            try:
                self.ch.executeCommand(self.aptinstall + package)
                retcode = self.ch.getReturnCode()
                errstr = self.ch.getErrorString()
                if retcode != 0:
                    raise repoError('apt', retcode)
            except repoError as repoerr:
                if not repoerr.success:
                    installed = False
                    self.logger.log(LogPriority.WARNING, str(errstr))

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
        '''

        removed = True

        try:

            try:
                self.ch.executeCommand(self.aptremove + package)
                retcode = self.ch.getReturnCode()
                errstr = self.ch.getErrorString()
                if retcode != 0:
                    raise repoError('apt', retcode)
            except repoError as repoerr:
                if not repoerr.success:
                    removed = False
                    self.logger.log(LogPriority.WARNING, str(errstr))

            if removed:
                self.logger.log(LogPriority.DEBUG, "Successfully removed package " + str(package))
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
        @author: Derek Walker
        @change: Breen Malmberg - 4/27/2017 - fixed doc string formatting;
                method now returns a variable; replaced detailedresults with
                logging
        '''

        installed = False
        stringToMatch = "ii\s+" + str(package)

        try:

            try:
                self.ch.executeCommand(self.dpkgchkinstalled + package)
                retcode = self.ch.getReturnCode()
                outputstr = self.ch.getOutputString()
                errstr = self.ch.getErrorString()
                if retcode != 0:
                    raise repoError('apt', retcode, str(errstr))
            except repoError as repoerr:
                if not repoerr.success:
                    self.logger.log(LogPriority.WARNING, str(errstr))
                    return False

            if re.search(stringToMatch, outputstr, re.IGNORECASE):
                installed = True

            if not installed:
                self.logger.log(LogPriority.DEBUG, "Package " + str(package) + " is NOT installed")
            else:
                self.logger.log(LogPriority.DEBUG, "Package " + str(package) + " is installed")

        except Exception:
            raise
        return installed

    def checkAvailable(self, package):
        '''
        check if a given package is available

        @param package: string; Name of package to check
        @return: found
        @rtype: bool
        @author: Derek T. Walker
        @change: Breen Malmberg - 4/27/2017 - created doc string;
                pulled result logging out of conditional 
        '''

        found = False

        try:

            try:
                self.ch.executeCommand(self.aptchkavail + package)
                retcode = self.ch.getReturnCode()
                outputstr = self.ch.getOutputString()
                errstr = self.ch.getErrorString()
                if retcode != 0:
                    raise repoError('apt', retcode, str(errstr))
            except repoError as repoerr:
                if not repoerr.success:
                    self.logger.log(LogPriority.WARNING, str(errstr))
                    return False

            if re.search(package, outputstr, re.IGNORECASE):
                found = True

            if found:
                self.logger.log(LogPriority.DEBUG, "Package " + str(package) + " is available to install")
            else:
                self.logger.log(LogPriority.DEBUG, "Package " + str(package) + " is NOT available to install")

        except Exception:
            raise
        return found

    def Update(self, package=""):
        '''
        update the specified package if any
        updates are available for it
        if no package is specified, apply
        all available updates for the system

        @param package: string; (OPTIONAL) name of package to update
        @return: updated
        @rtype: bool
        @author: Breen Malmberg
        '''

        updated = True

        try:

            try:
                self.ch.executeCommand(self.aptupgrade + package)
                retcode = self.ch.getReturnCode()
                errstr = self.ch.getErrorString()
                if retcode != 0:
                    raise repoError('apt', retcode, str(errstr))
            except repoError as repoerr:
                if not repoerr.success:
                    self.logger.log(LogPriority.WARNING, str(errstr))
                    updated = False

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
        '''
        check for updates for specified package
        if no package is specified, then check
        for updates for the entire system

        @param package: string; (OPTIONAL) Name of package to check
        @return: updatesavail
        @rtype: bool
        @author: Breen Malmberg
        '''

        updatesavail = False

        try:

            try:
                self.ch.executeCommand(self.aptchkupdates + package)
                retcode = self.ch.getReturnCode()
                errstr = self.ch.getErrorString()
                if retcode != 0:
                    raise repoError('apt', retcode, str(errstr))
            except repoError as repoerr:
                if not repoerr.success:
                    self.logger.log(LogPriority.WARNING, str(errstr))
                    return False
                else:
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
        '''
        Returns the name of the package that provides the given
        filename/path.

        @param: filename: string; The name or path of the file to resolve
        @return: packagename
        @rtype: string
        @author: Eric Ball
        @change: Breen Malmberg - 4/17/2017 - fixed doc string formatting;
                method now returns a variable; added param validation
        '''

        packagename = ""

        try:

            try:
                self.ch.executeCommand(self.dpkgsearch + filename)
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
