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

import re
import yum, aptGet, portage, zypper, freebsd, solaris, dnf
import traceback
from logdispatcher import LogPriority


class Pkghelper(object):
    '''
     Package helper class that interacts with rules needing to install, remove
     or check the status of software packages. Relies on platform specific
     subclasses to do the heavy lifting.

    @author: Derek T Walker  July 2012
    @change: 2015/08/20 eball - Added getPackageFromFile
    @change: 2015/09/04 rsn - Gave default value to self.pckgr for OSs that
                              are not included, specifically OS X.
    '''

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
        '''FOR YUM (RHEL,CENTOS)'''
        if self.manager is "yum":
            self.pckgr = yum.Yum(self.logger)

            '''FOR DNF (FEDORA)'''
        elif self.manager is "dnf":
            self.pckgr = dnf.Dnf(self.logger)

            '''FOR APT-GET (DEBIAN,UBUNTU,MINT)'''
        elif self.manager is "apt-get":
            self.pckgr = aptGet.AptGet(self.logger)

            '''FOR ZYPPER (OPENSUSE)'''
        elif self.manager is "zypper":
            self.pckgr = zypper.Zypper(self.logger)

            '''FOR PORTAGE (GENTOO)'''
        elif self.manager is "portage":
            self.pckgr = portage.Portage(self.logger)

            '''FOR PKG_ADD (FREEBSD,BSD,OPENBSD)'''
        elif self.manager is "freebsd":
            self.pckgr = freebsd.Freebsd(self.logger)

            '''FOR PKGADD (SOLARIS)'''
        elif self.manager is "solaris":
            self.pckgr = solaris.Solaris(self.logger)

        else:
            self.pckgr = None

    def determineMgr(self):
        '''determines the package manager for the current os'''
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
                        return None
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
        '''Install the named package. Return a bool indicating installation
        success or failure.

        @param string package : Name of the package to be installed, must be
            recognizable to the underlying package manager.
        @return bool :
        @author: Derek T Walker July 2012'''

        try:
            if self.enviro.geteuid() is 0 and self.pckgr:
                if self.pckgr.installpackage(package):
                    return True
                else:
                    return False
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
        '''Remove a package. Return a bool indicating success or failure.

        @param string package : Name of the package to be removed, must be
            recognizable to the underlying package manager.
        @return bool :
        @author Derek T Walker July 2012'''
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
        '''Check for the existence of a package in the package manager.
        Return a bool; True if found.

        @param string package : Name of the package whose installation status
            is to be checked. Must be recognizable to the underlying package
            manager.
        @return bool :
        @author Derek T Walker July 2012'''
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
        try:
            if self.pckgr.checkAvailable(package):
                return True
            else:
                return False
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            info = traceback.format_exc()
            raise
            self.logger.log(LogPriority.ERROR, info)

    def checkUpdate(self, package=""):
        '''
        check for updates on the system
        return True if there are updates available
        return False if there are no updates available

        @param package: string; name of package to check for. If
                no package is specified, the rule will check for
                ANY updates available to the system
        @return: updatesavail
        @rtype: bool
        @author: Breen Malmberg
        '''

        # defaults
        updatesavail = False

        try:

            # parameter validation
            if package:
                if not isinstance(package, basestring):
                    self.logger.log(LogPriority.DEBUG, "Parameter: package must be of type string. Got: " + str(type(package)))
                    return updatesavail

            if self.pckgr.checkUpdate(package):
                updatesavail = True

        except Exception:
            raise
        return updatesavail

    def Update(self, package=""):
        '''
        update either the specified package
        or all available updates if no package is specified

        @param package: string; name of package to update
                will update all packages if no package is
                specified
        @return: updated
        @rtype: bool
        @author: Breen Malmberg
        '''

        updated = True
        updatesavail = False

        try:

            updatesavail = self.pckgr.checkUpdates(package)
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
        '''Returns the name of the package that provides the given
        filename/path.

        @param: string filename : The name or path of the file to resolve
        @return: string name of package if found, None otherwise
        @author: Eric Ball
        '''
        try:
            return self.pckgr.getPackageFromFile(filename)
        except(KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
            raise(self.detailedresults)

    def getInstall(self):
        return self.pckgr.getInstall()

    def getRemove(self):
        return self.pckgr.getRemove()
