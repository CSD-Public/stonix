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
            server = url.split("/")[2]
            protocol = url.split(":")[0]
            
            # If there network, install, else no network, log
            hasconnection = has_connection_to_server(self.logger,
                                                     str(protocol) + "://" + str(server))
            if hasconnection:
                # Set up the installation
                installing = IHmac(self.environ, url, self.logger)
                # Install the package
                success = installing.install_package_from_server()

                self.logger.log(LogPriority.DEBUG,
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
            domain = find_domains(package)[0]

            success = False
            if domain:
                cmd_one = ["/usr/sbin/pkgutil", "--only-files", "--files", domain]
                cmd_two = ["/usr/sbin/pkgutil", "--only-dirs", "--files", domain]
        
                #####
                # Use the pkgutil command to get a list of files in the package 
                # receipt
                count = 0
                self.ch.executeCommand(cmd_one)
                files2remove = self.ch.getOutputString()
                self.logger.log(LogPriority.DEBUG, files2remove)
                if self.ch.getReturnCode() == 0:
                    for file in files2remove:
                        try:
                            #####
                            # Make sure "/" is prepended to the file as pkgutil
                            # does not report the first "/" in the file path
                            os.remove("/" + file)
                            count = count + 1
                        except OSError, err:
                            self.logger.log(LogPriority.DEBUG, "Error trying to remove: " + str(file))
                            self.logger.log(LogPriority.DEBUG, "With Exception: " + str(err))
        
                    #####
                    # Directory list will include directories such as /usr
                    # and /usr/local... Sucess is obtained only if all of the files
                    # (not directories) are deleted.
                    if count == len(list):
                        success = True
        
                #####
                # Use the pkgutil command to get a list of directories in the 
                # package receipt
                self.ch.executeCommand(cmd_two)
                dirs2remove = self.ch.getOutputString()
                #####
                # Reverse list as list is generated with parents first rather than
                # children first.
                dirs2remove.reverse()
                self.logger.log(LogPriority.DEBUG, files2remove)
                if self.ch.getReturnCode() == 0:
                    for dir in dirs2remove:
                        try:
                            #####
                            # Make sure "/" is prepended to the directory tree as 
                            # pkgutil does not report the first "/" in the file path
                            os.rmdir("/" + dir)
                            #####
                            # We don't care if any of the child directories still have 
                            # files, as directories such as /usr/bin, /usr/local/bin are
                            # reported by pkgutil in the directory listing, which is why
                            # we use os.rmdir rather than shutil.rmtree and we don't report
                            # on the success or failure of removing directories.
                        except OSError, err:
                            self.logger.log(LogPriority.DEBUG, "Error trying to remove: " + str(dir))
                            self.logger.log(LogPriority.DEBUG, "With Exception: " + str(err))
            
        except(KeyboardInterrupt,SystemExit):
            raise
        except Exception, err:
            print err
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.INFO, self.detailedresults)

        return success

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
            success = False
            domain = find_domains(package)[0]
            
            if domain:
                success = True
                self.logger.log(LogPriority.INFO, "Domain: " + str(domain) + " found")

        except(KeyboardInterrupt,SystemExit):
            raise
        except Exception, err:
            print err
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.INFO, self.detailedresults)   
        
        return success

###############################################################################

    def checkAvailable(self,package):
        pass

###############################################################################

    def getInstall(self):
        return self.install

###############################################################################

    def getRemove(self):
        return self.remove
