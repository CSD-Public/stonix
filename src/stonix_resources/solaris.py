'''
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
Created on Aug 6, 2012

@author: dwalker
'''
import traceback
from re import search
from logdispatcher import LogPriority
from subprocess import Popen,call,PIPE
from CommandHelper import CommandHelper

class Solaris(object):
    
    def __init__(self,logger):
        '''Remember, for solaris sparc systems, the package names will typically
        begin with SUNW'''
        self.logger = logger
        self.detailedresults = ""
        self.sparc = "(.)*sparc(.)*" 
        self.ch = CommandHelper(self.logger)
        self.install = "/usr/sbin/pkgadd -n -i "
        self.remove = "/usr/sbin/pkgrm -n "
        self.info = "/usr/bin/pkginfo "
###############################################################################
    def installpackage(self, package):
        '''
         Install a package. Return a bool indicating success or failure.

        @param string package : Name of the package to be installed, must be 
            recognizable to the underlying package manager.
        @return bool :
        @author'''
        try:
#             retval = call(self.install + package,stdout=None,shell=True)
#             if retval == 0:
            self.ch.executeCommand(self.install + package)
            if self.ch.getReturnCode() == 0:
                self.detailedresults = package + " pkg installed successfully"
                self.logger.log(LogPriority.INFO,
                                ["Solaris.install",self.detailedresults])
                return True
            else:
                self.detailedresults = package + " pkg not able to install."
                self.detailedresults += "This package may not be available, \
                may be mispelled, or may depend on other packages in which non\
                interactive mode can't be used"
                self.logger.log(LogPriority.INFO,
                                ["Solaris.install",self.detailedresults])
                return False
        except(KeyboardInterrupt,SystemExit):
            raise
        except Exception, err:
            #print err
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.INFO,
                            ['Solaris.install',self.detailedresults])
###############################################################################
    def removepackage(self,package):
        '''Remove a package. Return a bool indicating success or failure.

        @param string package : Name of the package to be removed, must be 
            recognizable to the underlying package manager.
        @return bool :
        @author'''
        
        try:
#             retval = call(self.remove + package,stdout=None,shell=True)
#             if retval == 0:
            self.ch.executeCommand(self.remove + package)
            if self.ch.getReturnCode() == 0:
                self.detailedresults = package + " pkg removed successfully"
                self.logger.log(LogPriority.INFO,
                                ["Solaris.remove",self.detailedresults])
                return True
            else:
                self.detailedresults = package + " pkg not able to be removed."
                self.detailedresults += "This package may not be installed \
                may be mispelled or may depend on other packages in which non \
                interactive mode can't be used"
                self.logger.log(LogPriority.INFO,
                                ["Solaris.remove",self.detailedresults])
                return False
        except(KeyboardInterrupt,SystemExit):
            raise
        except Exception, err:
            #print err
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.INFO,
                            ["Solaris.remove",self.detailedresults])
###############################################################################
    def checkInstall(self, package):
        '''Check the installation status of a package. Return a bool; True if 
        the packageis installed.

        @param string package : Name of the package whose installation status 
            is to be checked, must be recognizable to the underlying package 
            manager.
        @return bool :
        @author'''
        try:
            if search("^SUNW",package):
                retval = call(["/usr/bin/pkginfo",package],stdout=None,
                                                                   shell=False)
            else:
                retval = call("/usr/bin/pkginfo | grep -i " + package,
                                                       stdout=None,shell=True)
            if retval == 0:
                self.detailedresults = package + " pkg found"
                self.logger.log(LogPriority.INFO,
                                ["Solaris.check",self.detailedresults])
                return True
            else:
                self.detailedresults = package + " pkg not found"
                self.logger.log(LogPriority.INFO,
                                ["Solaris.check",self.detailedresults])
                return False
        except(KeyboardInterrupt,SystemExit):
            raise
        except Exception, err:
            #print err
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.INFO,
                            ["Solaris.check",self.detailedresults])   
###############################################################################
    def checkAvailable(self,package):
        pass
###############################################################################
    def getInstall(self):
        return self.install
###############################################################################
    def getRemove(self):
        return self.remove