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

@author: rsn, dwalker
'''
import os
import re
import time
import plistlib
import traceback
from re import search
from logdispatcher import LogPriority
from subprocess import Popen, call, PIPE, STDOUT
from CommandHelper import CommandHelper
from IHmac import IHmac
from stonixutilityfunctions import set_no_proxy, has_connection_to_server

def NoRepoException(Exception):
    """
    Custom Exception    
    """
    def __init__(self,*args,**kwargs):
        Exception.__init__(self,*args,**kwargs)

class MacPkgr(object):
    
    def __init__(self, environ, logger, reporoot=""):
        '''
        Mac package manager based on other stonix package managers.
        
        Uses the stonix IHmac and InstallingHelper Libraries.  They can
        install .zip, .tar, .tar.gz, .pkg and .mpkg files via an http or
        https URL
        
        @parameter: Instanciated stonix Environment object
        @parameter: Instanciated stonix LogDispatcher object
        @parameter: Takes an https link as a repository.

        @method: installpackage(package) - install a package
        @method: removepackage(package) - remove a package
        @method: checkInstall(package) - is the package installed?
        @method: checkAvailable(package) - is it available on the repository?
        @method: getInstall(package) - 
        @method: getRemove(package) - 
        
        # Methods specific to Mac.
        @method: findDomain(package) - see docstring
        
        @note: Uses the stonix IHmac and InstallingHelper Libraries.  They can
               install .zip, .tar, .tar.gz, .pkg and .mpkg files via an http or
               https URL
        
        @note: WARNING: To use checkInstall or removepackage, this package 
               manager converts all of the plists in the /var/db/receipts 
               directory to text, then converts they all back to binary when it
               is done performing a reverse lookup to find if a specific package
               is installed. I would love to use Greg Neagle's 
               FoundationPlist.py, but licenses are not compatible.

        '''
        self.environ = environ
        self.logger = logger
        self.detailedresults = ""
        if not reporoot:
            raise NoRepoException
        else:
            self.reporoot = reporoot
        self.dotmd5 = True
        self.logger.log(LogPriority.DEBUG, "Done initializing MacPkgr class...")
        self.ch = CommandHelper(self.logger)

###############################################################################

    def installPackage(self, package):
        '''
        Install a package. Return a bool indicating success or failure.

        @param string package : Must be the full URL (http or https) to the 
                                package.
        @return bool :
        @author
        '''
        success = False
        try:
            self.logger.log(LogPriority.INFO, "Attempting to install: " +\
                            str(package))
            self.logger.log(LogPriority.INFO, "From repo: " + \
                            str(self.reporoot))
            server = self.reporoot.split("/")[2]
            protocol = self.reporoot.split(":")[0]
            
            pkgurl = self.reporoot + "/" + package
            
            # If there network, install, else no network, log
            hasconnection = has_connection_to_server(self.logger,
                                                     server, 443)
            if hasconnection:
                self.logger.log(LogPriority.INFO, "There is a connection to" + \
                                                  " the server...")
                # Set up the installation
                installing = IHmac(self.environ, pkgurl, self.logger)

                # Install the package
                success = installing.install_package_from_server()

                self.logger.log(LogPriority.DEBUG,
                                     "Connection with server exists")

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
        self.fssync()
        return success
            
###############################################################################

    def removePackage(self, package="", install_root="/"):
        '''
        Remove a package domain. Return a bool indicating success or failure.
        Not yet implemented...
        
        Will use pkgutil to determine domain, then delete files in receipt..
        
        @param string package : Name of the package to be removed, must be 
            recognizable to the underlying package manager.
            
        @return bool :
        @author: rsn
        '''
        success = False
        try:
            print "Package: " + str(package)
            domain = None
            domain = self.findDomain(package)
            self.logger.log(LogPriority.DEBUG, "removePackage - Domain: " + domain)
            if domain is not None:
                cmd_one = ["/usr/sbin/pkgutil", 
                           "--only-files", 
                           "--files", 
                           domain]
                cmd_two = ["/usr/sbin/pkgutil", 
                           "--only-dirs", 
                           "--files", 
                           domain]
        
                #####
                # Use the pkgutil command to get a list of files in the package 
                # receipt
                count = 0
                self.ch.executeCommand(cmd_one)
                files2remove = self.ch.getOutputString().split("\n")
                print "Files to remove: " + str(files2remove)
                self.logger.log(LogPriority.DEBUG, files2remove)
                if self.ch.getReturnCode() == 0:
                    for file in files2remove:
                        if file:
                            try:
                                #####
                                # Make sure "/" is prepended to the file as pkgutil
                                # does not report the first "/" in the file path
                                os.remove(install_root + file)
                                count = count + 1
                            except OSError, err:
                                self.logger.log(LogPriority.DEBUG, 
                                                "Error trying to remove: " + \
                                                str(file))
                                self.logger.log(LogPriority.DEBUG, 
                                                "With Exception: " + \
                                                str(err))
                        else:
                            #####
                            # Potentially empty filename in the list, need to
                            # bump the count to match.
                            count = count + 1
        
                    #####
                    # Directory list will include directories such as /usr
                    # and /usr/local... Sucess is obtained only if all of 
                    # the files (not directories) are deleted.
                    if count == len(files2remove):
                        success = True
                    else:
                        self.logger.log(LogPriority.WARNING, "Count: " + str(count))
                        self.logger.log(LogPriority.WARNING, "Files removed: " + str(len(files2remove)))
        
                    #####
                    # Use the pkgutil command to get a list of directories 
                    # in the package receipt
                    self.ch.executeCommand(cmd_two)
                    dirs2remove = self.ch.getOutputString().split("\n")
                    #####
                    # Reverse list as list is generated with parents first 
                    # rather than children first.
                    dirs2remove.reverse()
                    self.logger.log(LogPriority.DEBUG, files2remove)
                    if self.ch.getReturnCode() == 0:
                        for dir in dirs2remove:
                            if dir:
                                try:
                                    #####
                                    # Make sure "/" is prepended to the directory 
                                    # tree as pkgutil does not report the first "/"
                                    # in the file path
                                    os.rmdir(install_root + dir)
                                    #####
                                    # We don't care if any of the child directories
                                    # still have files, as directories such as 
                                    # /usr/bin, /usr/local/bin are reported by 
                                    # pkgutil in the directory listing, which is 
                                    # why we use os.rmdir rather than shutil.rmtree
                                    # and we don't report on the success or failure
                                    # of removing directories.
                                except OSError, err:
                                    self.logger.log(LogPriority.DEBUG, 
                                                    "Error trying to remove: " + \
                                                    str(dir))
                                    self.logger.log(LogPriority.DEBUG, 
                                                    "With Exception: " + str(err))
                                    pass
                    
                        #####
                        # Make the system package database "forget" the package
                        # was installed.
                        cmd_three = ["/usr/sbin/pkgutil", "--forget", domain]
                        self.ch.executeCommand(cmd_three)
                        if not re.match("^%s$"%str(self.ch.getReturnCode()).strip(), str(0)):
                            success = False
                else:
                    self.logger.log(LogPriority.DEBUG, "Page: \"" + \
                                    str(package) + "\" Not found")
                    
        except(KeyboardInterrupt,SystemExit):
            raise
        except Exception, err:
            print err
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.INFO, self.detailedresults)

        self.fssync()
        print "Remove Package success: " + str(success)
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
        success = False
        try:
            #####
            # Perform a reverse lookup to get the domain...
            domain = self.findDomain(package)
            self.logger.log(LogPriority.DEBUG, "Domain: " + str(domain))
            if domain:
                success = True
                self.logger.log(LogPriority.INFO, 
                                "Domain: " + str(domain) + " found")

        except(KeyboardInterrupt,SystemExit):
            raise
        except Exception, err:
            print err
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.INFO, self.detailedresults)   
        
        return success

###############################################################################

    def checkAvailable(self,package):
        """
        Check if a package is available at the "reporoot"
        
        @author: Roy Nielsen
        """
        success = False
        self.logger.log(LogPriority.INFO, "Checking if: " +\
                        str(package)) + " is available on the server..."
        self.logger.log(LogPriority.INFO, "From repo: " + \
                        str(self.reporoot))
        server = self.reporoot.split("/")[2]
        protocol = self.reporoot.split(":")[0]
        
        pkgurl = self.reporoot + "/" + package
        
        # If there network, install, else no network, log
        hasconnection = has_connection_to_server(self.logger,
                                                 server, 443)
        if hasconnection:
            self.logger.log(LogPriority.INFO, "There is a connection to" + \
                                              " the server...")
            # Set up the installation
            installing = IHmac(self.environ, pkgurl, self.logger)

            # Install the package
            success = installing.isAvailable(package)
        return success

###############################################################################

    def getInstall(self):
        return self.install

###############################################################################

    def getRemove(self):
        return self.remove

###############################################################################

    def findDomain(self, pkg=""):
        """
        Go through the package receipts database to find a package, and return
        a domain.  Apple stores package information in "domain" format, rather
        than a package name format. Accessing the package name means we need to
        look through all the ".plist" files in /var/db/receipts to find the
        package name, then we can return the domain so that can be used for 
        package management.
        
        Install package receipts can be found in /var/db/receipts.
        
        A domain is the filename in the receipts database without the ".plist"
        or ".bom".
        
        An example is org.macports.MacPorts
        
        @parameters: pkg - the name of the install package that we need the
                     domain for.
        @returns: domains - the first domain in a possible list of domains.
        
        @author: Roy Nielsen 
        """
        self.logger.log(LogPriority.DEBUG, "Looking for: " + str(pkg))
        path = "/var/db/receipts/"
        files = []
        domain = ""
        for name in os.listdir(path):
            if os.path.isfile(os.path.join(path, name)) and \
               os.path.isfile(os.path.join(path, name)) and \
               name.endswith(".plist"):
                files.append(name)

        unwrap = "/usr/bin/plutil -convert xml1 /var/db/receipts/*.plist"
        wrap = "/usr/bin/plutil -convert binary1 /var/db/receipts/*.plist"

        self.ch.executeCommand(unwrap)
        
        if not re.match("^%s$"%self.ch.getReturnCode(), str(0)):
            #####
            # Unwrap command didn't work... return None
            domain = None
        else:
            self.fssync()
            #####
            # Unwrap command worked, process the receipt plists
            for afile in files:
                #####
                # Get the path without the plist file extension.
                afile_path = os.path.join(path, afile)
                #####
                # Make sure we have a valid file on the filesystem 
                if os.path.isfile(afile_path):
                    try:
                        plist = plistlib.readPlist(afile_path)
                    except Exception, err:
                        self.logger.log(LogPriority.DEBUG, "Exception " + \
                                                           "trying to use" + \
                                                           " plistlib: " + \
                                                           str(err))
                        raise err
                    else:
                        if re.match("^%s$"%plist['PackageFileName'], pkg):
                            #####
                            # Find the first instance of the PackageFileName
                            # ... without the .plist..
                            domain = ".".join(afile.split(".")[:-1])
                            break
            #####
            # Make the plists binary again...
            self.ch.executeCommand(wrap)

            #####
            # Log the domain...
            self.logger.log(LogPriority.DEBUG, "Domain: " + str(domain))
        print "findDomain: " + str(domain)
        return domain
    
    def fssync(self):
        """
        The changes to the plists in findDomain are not being sync'd to the
        filesystem before they are changed back.  PERFORMING A FILESYSTEM
        SYNC before trying to read the plists after converting them to xml1
        IS REQUIRED. (Operating system filesystem write buffers need to be
        flushed to disk before the changed files have the new meaning)
        
        @author: Roy Nielsen
        """
        synccmd = []
        
        self.ch.executeCommand("/bin/sync")
        if self.ch.getReturnCode() != 0:
            self.logger.log(LogPriority.DEBUG, "Problem trying to perform " + \
                                               "filesystem sync...")
            print "Problem Jim............."
        else:
            time.sleep(1)
            self.ch.executeCommand("/bin/sync")
            if self.ch.getReturnCode() != 0:
                self.logger.log(LogPriority.DEBUG, "Problem trying to " + \
                                                   "perform filesystem sync...")
            else:
                time.sleep(1)
                self.ch.executeCommand("/bin/sync")
                if self.ch.getReturnCode() != 0:
                    self.logger.log(LogPriority.DEBUG, "Problem trying to " + \
                                                       "perform filesystem" + \
                                                       " sync...")
                else:
                    time.sleep(1)
