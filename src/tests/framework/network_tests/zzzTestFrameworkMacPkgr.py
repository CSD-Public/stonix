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
import os
import re
import sys
import shutil
import unittest

from src.stonix_resources.macpkgr import MacPkgr
from src.stonix_resources.environment import Environment
from src.tests.lib.logdispatcher_lite import LogDispatcher, LogPriority
from pip.req.req_set import Installed
from Finder.Files import package

class zzzTestFrameworkMacPkgr(unittest.TestCase):
    """
    Class for testing the macpkgr.
    """
    
    def setUp(self):
        """
        """
        self.macPackageName = "testStonixMacPkgr-0.0.3.pkg"
        self.reporoot = "https://jds001.lanl.gov/CasperShare/"        
        self.environ = Environment()
        self.logger = LogDispatcher(self.environ)
        self.pkgr = MacPkgr(self.environ, self.logger, self.reporoot)
        if not self.environ.osfamily=="darwin":
            sys.exit(255)
        self.pkg_dirs = ["/tmp/testStonixMacPkgr-0.0.3/one/two/three/3.5",
                         "/tmp/testStonixMacPkgr-0.0.3/one/two/three",
                         "/tmp/testStonixMacPkgr-0.0.3/one/two",
                         "/tmp/testStonixMacPkgr-0.0.3/one",
                         "/tmp/testStonixMacPkgr-0.0.3/one/two/four/five",
                         "/tmp/testStonixMacPkgr-0.0.3/one/two/four",
                         "/tmp/testStonixMacPkgr-0.0.3/one/two",
                         "/tmp/testStonixMacPkgr-0.0.3/one/six/seven"]
        
        self.pkg_files = ["/tmp/testStonixMacPkgr-0.0.3/one/two/testfile1",
                     "/tmp/testStonixMacPkgr-0.0.3/one/two/four/five/testfile2",
                     "/tmp/testStonixMacPkgr-0.0.3/one/testfile3",
                     "/tmp/testStonixMacPkgr-0.0.3/one/testfile4",
                     "/tmp/testStonixMacPkgr-0.0.3/one/six/seven/testfile"]

        self.post_files = ["/tmp/testStonixMacPkgr-0.0.3/one/postfile2", 
                     "/tmp/testStonixMacPkgr-0.0.3/one/two/three/3.5/postfile3"]
        
        self.post_dirs = ["/tmp/testStonixMacPkgr-0.0.3/one/six/6.5"]
        
        self.all_files = [self.pkg_files, self.post_files]
        self.all_dirs = [self.pkg_dirs, self.post_dirs]
        self.allowed_files_and_dirs = [self.pkg_dirs, 
                                       self.pkg_dirs, 
                                       self.post_dirs]
        
    def tearDown(self):
        """
        Make sure the appropriate files are removed..
        """
        pass
    
    def test_inLinearFlow(self):
        """
        Run methods or functionality that requires order, ie a happens before b
        Like ensure a package is installed before testing if uninstall works.
        
        @author: Roy Nielsen
        """
        #####
        # Remove the package in case it is installed, so we have a sane, 
        # consistent starting point for the test.
        self.removeCompletePackage()

        #####
        # Install the package
        self.assertTrue(self.pkgr.installPackage(self.macPackageName),
                        "Problem with pkgr.installpackage...")        
        #####
        # Use the macpkgr method to check if the package is installed
        self.assertTrue(self.pkgr.checkInstall(self.macPackageName),
                        "Problem with pkgr.checkInstall...")
        
        #####
        # Manual check to see if the package is installed
        self.assertTrue(self.isInstalled(), "Problem with installation...")
        
        #####
        # Make sure it isn't a partial install...
        self.assertTrue(self.isFullInstall(), "Partial install...")

        #####
        # Remove the package, assert that it worked.                
        self.assertTrue(self.pkgr.removePackage(self.macPackageName),
                        "Problem removing package...")
        
        #####
        # Check that checkInstall returns the correct value
        self.assertFalse(self.pkgr.checkInstall(self.macPackageName),
                         "Problem with pkgr.checkinstall...")

        #####
        # Hand verify that self.pkgr.checkInstall worked.
        self.assertTrue(self.isMissing(), "Problem with package removal...")
        
        #####
        # Remove any presence of the package installed.
        self.removeCompletePackage()

        
    def testIsMacPlatform(self):
        """
        Make sure we are on the Mac platform.
        
        @author: Roy Nielsen
        """
        self.assertTrue(self.environ.osfamily=="darwin", "Wrong OS...")
        
    def isFullInstall(self):
        """
        Make sure that all files and directories including those installed from
        the package and the postinstall script exist.
        
        @author: Roy Nielsen
        """

        files = self.doFilesExistTest(self.all_files)
        dirs = self.doDirsExistTest(self.all_dirs)
        
        if files and dirs:
            return True
        return False
    
    def isInstalled(self):
        """
        Test to make sure just the files and directories installed by the
        package are installed. Doesn't care about the files and directories
        installed by the postinstall script. 
        
        @author: Roy Nielsen
        """
        files = self.doFilesExistTest([self.pkg_files])
        dirs = self.doDirsExistTest([self.pkg_dirs])
        
        if files and dirs:
            return True
        return False

    def isMissing(self):
        """
        Test to make sure all the files have been removed that were Installed
        by the package.  Ignore, but note directories installed by the package
        that exist, as well as files and directories installed by the 
        postinstall script.
        
        @author: Roy Nielsen
        """
        removed = []
        exists = []
        
        #####
        # Cycle through each subset of files in the 
        for myfile in self.pkg_files:
           if os.path.isfile(myfile):
               self.logger.log(LogPriority.WARNING, "File: " + \
                               str(myfile) + " exists...")
               removed.append(False)
               exists.append(myfile)
        self.assertFalse(False in removed, "Some files exist: " + str(exists))
        
        #####
        # cycle through each set of directories in all_dirs
        for set in self.allowed_files_and_dirs:
            #####
            # Cycle through each subset of files in the 
            for myfile in set:
               if os.path.isdir(myfile):
                   self.logger.log(LogPriority.INFO, "Item: " + \
                                   str(myfile) + " exists...")
        if False in removed:
            return False
        return True

    def removeCompletePackage(self):
        """
        Remove all files, used to set the stage for install tests.
        
        @author:  Roy Nielsen
        """
        try:
            shutil.rmtree("/tmp/testStonixMacPkgr-0.0.3")
        except:
            self.logger.log(LogPriority.INFO, "Test set already missing...")
        else:
            self.logger.log(LogPriority.INFO, "Removed test package " + \
                                              "install set...")
            
    def doFilesExistTest(self, files=[False]):
        """
        Test the directories in the passed in list to see if they all exist.
        
        @author: Roy Nielsen
        """
        not_installed = []
        exists = []
        #####
        # cycle through each set of files in all_files
        for set in files:
            #####
            # Cycle through each subset of files in the 
            for myfile in set:
               if not os.path.isfile(myfile):
                   self.logger.log(LogPriority.WARNING, "File: " + \
                                   str(myfile) + " does not exist...")
                   exists.append(False)
                   not_installed.append(str(myfile))
            self.assertFalse(False in exists, "Not all files exist: " + \
                                               str(not_installed))
        if False in exists:
            return False
        return True
    
    def doDirsExistTest(self, dirs=[False]):
        """
        Test the directories in the passed in list to see if they all exist.
        
        @author: Roy Nielsen
        """
        not_installed = []
        exists = []
        #####
        # cycle through each set of directories in all_dirs
        for set in dirs:
            #####
            # Cycle through each subset of files in the 
            for mydir in set:
               if not os.path.isdir(mydir):
                   self.logger.log(LogPriority.WARNING, "Directory: " + \
                                   str(mydir) + " does not exist...")
                   exists.append(False)
                   not_installed.append(str(mydir))
            self.assertFalse(False in exists, "Not all files exist: " + \
                                                str(not_installed))
        if False in exists:
            return False
        return True
