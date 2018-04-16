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
from subprocess import Popen,call,PIPE
from logdispatcher import LogPriority
from CommandHelper import CommandHelper
import glob
class Portage(object):

    '''The template class that provides a framework that must be implemented by
    all platform specific pkgmgr classes.

    :version:
    :author:Derek T Walker 08-06-2012'''
    
    def __init__(self,logger):
        self.logger = logger
        self.detailedresults = ""
        self.ch = CommandHelper(self.logger)
        self.install = "emerge "
        self.remove = self.install + " --unmerge "
        self.search = self.install + " --search "
###############################################################################
    def installpackage(self, package):
        '''Install a package. Return a bool indicating success or failure.

        @param string package : Name of the package to be installed, must be 
            recognizable to the underlying package manager.
        @return bool :
        @author:Derek T Walker 08-06-2012'''
        try:
            installed = False
            self.ch.executeCommand(self.install + package)
#             retval = call(self.install + package,stdout=None,stderr=None,
#                                                                     shell=True)
#             if retval == 0:
            if self.ch.getReturnCode() == 0:
                installed = True
                self.detailedresults += package + " pkg installed successfully\n"
            else:
                self.detailedresults += package + " pkg not able to install\n"
            self.logger.log(LogPriority.INFO, self.detailedresults)
            return installed
        except(KeyboardInterrupt,SystemExit):
            raise
        except Exception:
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
###############################################################################
    def removepackage(self, package):
        '''Remove a package. Return a bool indicating success or failure.

        @param string package : Name of the package to be removed, must be 
            recognizable to the underlying package manager.
        @return bool :
        @author:Derek T Walker 08-6-2012'''
        try:
            removed = False
#             retval = call(self.remove + package,stdout=None,stderr=None,
#                                                                     shell=True)
#             if retval == 0:
            self.ch.executeCommand(self.remove + package)
            if self.ch.getReturnCode() == 0:
                removed = True
                self.detailedresults = package + " pkg removed successfully\n"
            else:
                self.detailedresults = package + " pkg not able to be removed\n"
            self.logger.log(LogPriority.INFO, self.detailedresults)
            return removed
        except(KeyboardInterrupt,SystemExit):
            raise
        except Exception:
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
###############################################################################
    def checkInstall(self, package):
        ''' Check the installation status of a package. Return a bool; 
         True if the packageis installed.

        @param string package : Name of the package whose installation status 
            is to be checked, must be recognizable to the underlying package 
            manager.
        @return bool :
        @author'''
        try:
            stringToMatch = "(.*)"+package+"(.*)"
            match = False
            #fileHandle = open('/var/lib/portage/world','r')
            f = glob.glob('/var/db/pkg')
            for item in f:
                if re.search(stringToMatch,item):
                    match = True
                    break
            if match:
                self.detailedresults += package + " pkg found and installed"
            else:
                self.detailedresults += package + " pkg not found"
            self.logger.log(LogPriority.INFO, self.detailedresults)
            return match   
        except(KeyboardInterrupt,SystemExit):
            raise
        except Exception:
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
###############################################################################
    def checkAvailable(self,package):
        try:
            found = False
#             retval = call ([self.search,package],stdout=None,stderr=None,
#                                                                    shell=False)
#             if  retval == 0:
            self.ch.executeCommand(self.search + package)
            if self.ch.getReturnCode() == 0:
                found = True
                self.detailedresults += package + " pkg is available"
            else:
                self.detailedresults += package + " pkg not found or may be \
misspelled"
            self.logger.log(LogPriority.INFO, self.detailedresults)
            return found
        except(KeyboardInterrupt,SystemExit):
            raise
        except Exception:
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
###############################################################################
    def getInstall(self):
        return self.install
###############################################################################
    def getRemove(self):
        return self.remove