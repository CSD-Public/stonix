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


import re
#import yum, aptGet, portage, zypper, freebsd, solaris, dnf
from . import yum, aptGet, portage, zypper, freebsd, solaris, dnf
import traceback
from .logdispatcher import LogPriority


class Pkghelper(object):
    """Package helper class that interacts with rules needing to install, remove
     or check the status of software packages. Relies on platform specific
     subclasses to do the heavy lifting.
    
    @author: Derek T Walker  July 2012
    @change: 2015/08/20 eball - Added getPackageFromFile
    @change: 2015/09/04 rsn - Gave default value to self.pckgr for OSs that
                              are not included, specifically OS X.


    """

    def __init__(self, logdispatcher, environment):
        self.enviro = environment
        self.logger = logdispatcher
        self.osDictionary = {'opensuse': 'zypper', 'gentoo': 'portage',
                             'red hat': 'yum', 'ubuntu': 'apt-get',
                             'debian': 'apt-get', 'centos': 'yum',
                             'fedora': 'dnf', 'mint': 'apt-get',
                             'freebsd': 'freebsd', 'solaris': 'solaris'}
        self.manager = self.determineMgr()
        self.detailedresults = ''
        """FOR YUM (RHEL,CENTOS)"""
        if self.manager is "yum":
            self.pckgr = yum.Yum(self.logger)

            """FOR DNF (FEDORA)"""
        elif self.manager is "dnf":
            self.pckgr = dnf.Dnf(self.logger)

            """FOR APT-GET (DEBIAN,UBUNTU,MINT)"""
        elif self.manager is "apt-get":
            self.pckgr = aptGet.AptGet(self.logger)

            """FOR ZYPPER (OPENSUSE)"""
        elif self.manager is "zypper":
            self.pckgr = zypper.Zypper(self.logger)

            """FOR PORTAGE (GENTOO)"""
        elif self.manager is "portage":
            self.pckgr = portage.Portage(self.logger)

            """FOR PKG_ADD (FREEBSD,BSD,OPENBSD)"""
        elif self.manager is "freebsd":
            self.pckgr = freebsd.Freebsd(self.logger)

            """FOR PKGADD (SOLARIS)"""
        elif self.manager is "solaris":
            self.pckgr = solaris.Solaris(self.logger)

        else:
            self.pckgr = None

    def determineMgr(self):
        """determines the package manager for the current os
        
        @author: ???
        @change: Breen Malmberg - Feb 25 2019 - added "packageMgr" return variable
                initialization; added doc string


        """

        packageMgr = None

        try:

            if self.enviro.getosfamily() == "linux":
                currentIterator = 0
                for key in self.osDictionary:
                    stringToMatch = "(.*)" + key + "(.*)"
                    if re.search(stringToMatch,
                                 self.enviro.getostype().lower()):
                        packageMgr = self.osDictionary[key]
                        break
                    elif(currentIterator < (len(self.osDictionary)-1)):
                        currentIterator += 1
                        continue
                    else:
                        return packageMgr
            else:
                currentIterator = 0
                for key in self.osDictionary:
                    stringToMatch = "(.*)" + key + "(.*)"
                    if re.search(stringToMatch,
                                 self.enviro.getosfamily().lower()):
                        packageMgr = self.osDictionary[key]
                        break
                    elif(currentIterator < (len(self.osDictionary)-1)):
                        currentIterator += 1
                        continue
                    else:
                        return None

            return packageMgr

        except(KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            info = traceback.format_exc()
            self.logger.log(LogPriority.ERROR, info)
            raise

    def install(self, package):
        """Install the named package. Return a bool indicating installation
        success or failure.

        :param string package: Name of the package to be installed, must be
            recognizable to the underlying package manager.
        :param package: 
        :returns: bool :
        @author: Derek T Walker July 2012
        @change: Breen Malmberg - Feb 25 2019 - Removed unreachable code line 146

        """

        try:
            if self.enviro.geteuid() is 0 and self.pckgr:
                if self.pckgr.installpackage(package):
                    return True
                else:
                    return False
            else:
                msg = "Not running as root, only root can use the pkghelper \
install command"
                raise Exception(msg)
        except(KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            info = traceback.format_exc()
            self.logger.log(LogPriority.ERROR, info)
            raise

    def remove(self, package):
        """Remove a package. Return a bool indicating success or failure.

        :param string package: Name of the package to be removed, must be
            recognizable to the underlying package manager.
        :param package: 
        :returns: bool :
        @author Derek T Walker July 2012

        """

        try:
            if self.enviro.geteuid() == 0:
                if self.pckgr.removepackage(package):
                    return True
                else:
                    return False
            else:
                msg = "Not running as root, only root can use the pkghelper \
remove command"
                raise Exception(msg)
        except(KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            info = traceback.format_exc()
            self.logger.log(LogPriority.ERROR, info)
            raise

    def check(self, package):
        """Check for the existence of a package in the package manager.
        Return a bool; True if found.

        :param string: package : Name of the package whose installation status
            is to be checked. Must be recognizable to the underlying package
            manager.
        :param package: 
        :returns: bool :
        @author Derek T Walker July 2012

        """

        try:
            if self.pckgr.checkInstall(package):
                return True
            else:
                return False
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            info = traceback.format_exc()
            self.logger.log(LogPriority.ERROR, info)
            raise

    def checkAvailable(self, package):
        """check the reachable repositories to see if the specified package
        is available to install or not

        :param package: string; name of package to check
        :returns: True/False
        :rtype: bool
@author: ???
@change: Breen Malmberg - Feb 25 2019 - added doc string; moved
        unreachable logging call to before call to raise, on line 228

        """

        try:
            if self.pckgr.checkAvailable(package):
                return True
            else:
                return False
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            info = traceback.format_exc()
            self.logger.log(LogPriority.ERROR, info)
            raise

    def checkUpdate(self, package=""):
        """check for updates on the system
        return True if there are updates available
        return False if there are no updates available

        :param package: string; name of package to check for. If
                no package is specified, the rule will check for
                ANY updates available to the system (Default value = "")
        :returns: updatesavail
        :rtype: bool
@author: Breen Malmberg

        """

        updatesavail = False

        try:

            # parameter validation
            if package:
                if not isinstance(package, str):
                    self.logger.log(LogPriority.DEBUG, "Parameter: package must be of type string. Got: " + str(type(package)))
                    return updatesavail

            try:
                if self.pckgr.checkUpdate(package):
                    updatesavail = True
            except AttributeError:
                self.logger.log(LogPriority.DEBUG, "checkUpdate function not supported on this system.")
                return updatesavail

        except Exception:
            raise
        return updatesavail

    def Update(self, package=""):
        """update either the specified package
        or all available updates if no package is specified

        :param package: string; name of package to update
                will update all packages if no package is
                specified (Default value = "")
        :returns: updated
        :rtype: bool
@author: Breen Malmberg

        """

        updated = True
        updatesavail = False

        try:

            updatesavail = self.checkUpdate(package)

            if updatesavail:
                self.logger.log(LogPriority.DEBUG, "Updates are available to install")
                if not self.pckgr.Update(package):
                    self.logger.log(LogPriority.DEBUG, "Failed to install updates")
                    updated = False
                else:
                    self.logger.log(LogPriority.DEBUG, "All updates successfully installed")
            else:
                self.logger.log(LogPriority.DEBUG, "No updates available to install")

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

        try:
            return self.pckgr.getPackageFromFile(filename)
        except(KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
            raise(self.detailedresults)

    def getInstall(self):
        """return the commandline command for installing a package
        with the current, detected package manager


        :returns: rtype: string
        @author: ???
        @change: Breen Malmberg - Feb 25 2019 - added doc string; added try/except;
                added logging

        """

        try:
            return self.pckgr.getInstall()
        except AttributeError:
            self.logger.log(LogPriority.DEBUG, "getInstall function not supported on this system.")
            return ""

    def getRemove(self):
        """return the commandline command for removing a package
        with the current, detected package manager


        :returns: rtype: string
        @author: ???
        @change: Breen Malmberg - Feb 25 2019 - added doc string; added try/except;
                added logging

        """

        try:
            return self.pckgr.getRemove()
        except AttributeError:
            self.logger.log(LogPriority.DEBUG, "getRemove function not supported on this system.")
            return ""
