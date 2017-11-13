
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
import traceback
from logdispatcher import LogPriority
from subprocess import PIPE,Popen,call
from CommandHelper import CommandHelper
class Freebsd(object):

    '''The template class that provides a framework that must be implemented by
    all platform specific pkgmgr classes.

    :version:
    :author:Derek T Walker 08-06-2012'''

    def __init__(self,logger):
        self.logger = logger
        self.detailedresults = ""
        self.ch = CommandHelper(self.logger)
        self.install = "/usr/sbin/pkg_add -r -f "
        self.remove = "/usr/sbin/pkg_delete "
###############################################################################
    def installpackage(self, package):
        '''
         Install a package. Return a bool indicating success or failure.

        @param string package : Name of the package to be installed, must be 
            recognizable to the underlying package manager.
        @return bool :
        @author'''
        try:
            installed = False
#             retval = call(self.install + package,stdout=None,shell=True)
            self.ch.executeCommand(self.install + package)
            if self.ch.getReturnCode() == 0:
#             if retval == 0:
                self.detailedresults += package + " pkg installed successfully"
                installed = True
            else:
                self.detailedresults += package + " pkg not able to install"
            self.logger.log(LogPriority.INFO, self.detailedresults)
            return installed
        except(KeyboardInterrupt,SystemExit):
            raise
        except Exception:
            self.detailedresults += traceback.format_exc()
            self.logger.log(LogPriority.INFO, self.detailedresults)
###############################################################################
    def removepackage(self, package):
        '''
         Remove a package. Return a bool indicating success or failure.

        @param string package : Name of the package to be removed, must be 
            recognizable to the underlying package manager.
        @return : bool 
        @author'''
        try:
            self.detailedresults = ""
            removed = False
            stringToMatch = package + "(.*)"
            self.ch.executeCommand(["/usr/sbin/pkg_info"])
            output = self.ch.getOutput()
#             temp = Popen(["/usr/sbin/pkg_info"],stdout=PIPE,shell=True)
#             details = temp.stdout.readlines()
#             temp.stdout.close()
            for cell in output:
                cell2 = cell.split(" ")
                if re.search(stringToMatch,cell2[0]):
                    retval = call(self.remove + cell2[0],stdout=None,shell=True)
                    if retval == 0:
                        self.detailedresults += package + " pkg removed \
successfully"
                        removed = True
                    else:
                        self.detailedresults += package + " pkg not able\
to be removed"
            if not self.detailedresults:
                self.detailedresults += package + " pkg not found to remove"
            self.logger.log(LogPriority.INFO, self.detailedresults)
            return removed
        except(KeyboardInterrupt,SystemExit):
            raise
        except Exception:
            self.detailedresults += traceback.format_exc()
            self.logger.log(LogPriority.INFO, self.detailedresults)
###############################################################################
    def checkInstall(self, package):
        '''Check the installation status of a package. Return a bool; True if 
        the package is installed.

        @param string package : Name of the package whose installation status 
            is to be checked, must be recognizable to the underlying package 
            manager.
        @return : bool
        @author'''
        try:
            self.detailedresults = ""
            present = False
            stringToMatch = package +"(.*)"
            self.ch.executeCommand(["/usr/sbin/pkg_info"])
            output = self.ch.getOutput()
#             temp = Popen(["/usr/sbin/pkg_info"],stdout=PIPE,shell=False)
#             info = temp.stdout.readlines()
#             temp.stdout.close()
            for cell in output:
                cell2 = cell.split(" ")
                if re.search(stringToMatch,cell2[0]):
                    self.detailedresults += package + " pkg found"
                    present = True
            if not self.detailedresults:
                self.detailedresults += package + " pkg not found"
            self.logger.log(LogPriority.INFO, self.detailedresults)
            return present
        except(KeyboardInterrupt,SystemExit):
            raise
        except Exception:
            self.detailedresults += traceback.format_exc()
            self.logger.log(LogPriority.INFO, self.detailedresults)
###############################################################################
    def getInstall(self):
        return self.install
###############################################################################
    def getRemove(self):
        return self.remove