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
Created on Nov 24, 2015

@author: rsn
'''
import traceback
from re import search
from logdispatcher import LogPriority
from subprocess import Popen,call,PIPE
from CommandHelper import CommandHelper
from IHmac import IHmac
from stonixutilityfunctions import set_no_proxy, \
                                   has_connection_to_server

class MacPkgr(object):
    
    def __init__(self,logger):
        '''
        Uses the IHmac InstallingHelper.  Can install .zip, .tar, .tar.gz, 
        .pkg and .mpkg files via an http or https URL
        
        '''
        self.logger = logger
        self.detailedresults = ""

###############################################################################

    def installpackage(self, package):
        '''
        Install a package. Return a bool indicating success or failure.

        @param string package : Must be the full URL (http or https) to the 
                                package.
        @return bool :
        @author
        '''
        success = False
        try:

            # If there network, install, else no network, log
            hasconnection = has_connection_to_server(self.logdispatch,
                                                     self.puppetpkgserver)
            if hasconnection:
                # Set up the installation
                installing = IHmac(self.environ,
                                   self.puppetdownloadzipdarwin,
                                   self.logdispatch)
                # Install the package
                success = installing.install_package_from_server()

                self.logdispatch.log(LogPriority.DEBUG,
                                     "Connection with server exists, " + \
                                     "can install puppet.")

            if success:
                self.detailedresults = package + " pkg installed successfully"
                self.logger.log(LogPriority.INFO, self.detailedresults)
                return True
            else:
                self.detailedresults = package + " pkg not able to install."
                self.detailedresults += "This package may not be available, \
                may be mispelled, or may depend on other packages in which non\
                interactive mode can't be used"
                self.logger.log(LogPriority.INFO, self.detailedresults)
                return False
        except(KeyboardInterrupt,SystemExit):
            raise
        except Exception, err:
            print err
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.INFO, self.detailedresults)
            
###############################################################################

    def removepackage(self,domain):
        '''
        Remove a package domain. Return a bool indicating success or failure.
        Not yet implemented...
        
        Will use pkgutil to determine domain, then delete files in receipt..
        
        @param string package : Name of the package to be removed, must be 
            recognizable to the underlying package manager.
            
        @return bool :
        @author: rsn
        '''
        try:
            
            
            #####
            # Remove files
            
            #####
            # Remove directories
            
            
            self.logger.log(LogPriority.INFO, "Not yet implemented...")
        except(KeyboardInterrupt,SystemExit):
            raise
        except Exception, err:
            print err
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.INFO, self.detailedresults)

###############################################################################

    def checkInstall(self, package):
        '''
        Check the installation status of a package. Return a bool; True if 
        the package is installed.

        Use pkgutil to determine if package has been installed or not.

        @param string package : Name of the package whose installation status 
            is to be checked, must be recognizable to the underlying package 
            manager.
            
        @return bool :
        @author: rsn
        '''
        try:
            self.logger.log(LogPriority.INFO, "Not yet implemented...")
        except(KeyboardInterrupt,SystemExit):
            raise
        except Exception, err:
            print err
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.INFO, self.detailedresults)   

###############################################################################

    def checkAvailable(self,package):
        pass

###############################################################################

    def getInstall(self):
        return self.install

###############################################################################

    def getRemove(self):
        return self.remove
