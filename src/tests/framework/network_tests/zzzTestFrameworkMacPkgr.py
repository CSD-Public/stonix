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
"""
@note: This test is not set up to use proxies.
@change: 2016/02/10 roy Added sys.path.append for being able to unit test this
                        file as well as with the test harness.
@change: 2016/02/10 roy Added functionality to testInstallPkg test
@change: 2016/08/30 eball Added conditional to SkipTest for Python < 2.7

@author: Roy Nielsen
"""
import os
import re
import sys
import ctypes
import shutil
import unittest

sys.path.append("../../../..")
from src.stonix_resources.localize import MACREPOROOT
from src.stonix_resources.macpkgr import MacPkgr
from src.stonix_resources.environment import Environment
from src.stonix_resources.CommandHelper import CommandHelper
from src.stonix_resources.Connectivity import Connectivity
from src.tests.lib.logdispatcher_lite import LogDispatcher, LogPriority


class NotApplicableToThisOS(Exception):
    """
    Custom Exception
    """
    def __init__(self, *args, **kwargs):
        Exception.__init__(self, *args, **kwargs)


class zzzTestFrameworkMacPkgr(unittest.TestCase):
    """
    Class for testing the macpkgr.
    """
    @classmethod
    def setUpClass(self):
        """
        """
        self.environ = Environment()
        self.logger = LogDispatcher(self.environ)

        self.osfamily = self.environ.getosfamily()

        self.logger.log(LogPriority.DEBUG, "##################################")
        self.logger.log(LogPriority.DEBUG, "### OS Family: " + str(self.osfamily))
        self.logger.log(LogPriority.DEBUG, "##################################")

        if not re.match("^darwin$", self.osfamily.strip()):
            raise unittest.SkipTest("RamDisk does not support this OS" + \
                                    " family: " + str(self.osfamily))
        else:
            self.libc = ctypes.CDLL("/usr/lib/libc.dylib")

        self.logger = LogDispatcher(self.environ)

        self.macPackageName = "testStonixMacPkgr-0.0.3.pkg"
        self.reporoot = MACREPOROOT

        #####
        # Create a class variable that houses the whole URL
        if self.reporoot.endswith("/"):
            self.pkgUrl = self.reporoot + self.macPackageName
        else:
            self.pkgUrl = self.reporoot + "/" + self.macPackageName

        message = "self.pkgUrl: " + str(self.pkgUrl)

        self.pkgr = MacPkgr(self.environ, self.logger)

        self.pkg_dirs = ["/tmp/testStonixMacPkgr-0.0.3/one/two/three/3.5", \
                         "/tmp/testStonixMacPkgr-0.0.3/one/two/three", \
                         "/tmp/testStonixMacPkgr-0.0.3/one/two", \
                         "/tmp/testStonixMacPkgr-0.0.3/one", \
                         "/tmp/testStonixMacPkgr-0.0.3/one/two/four/five", \
                         "/tmp/testStonixMacPkgr-0.0.3/one/two/four", \
                         "/tmp/testStonixMacPkgr-0.0.3/one/two", \
                         "/tmp/testStonixMacPkgr-0.0.3/one/six/seven"]

        self.pkg_files = ["/tmp/testStonixMacPkgr-0.0.3/one/two/testfile1", \
                     "/tmp/testStonixMacPkgr-0.0.3/one/two/four/five/testfile2", \
                     "/tmp/testStonixMacPkgr-0.0.3/one/testfile3", \
                     "/tmp/testStonixMacPkgr-0.0.3/one/testfile4", \
                     "/tmp/testStonixMacPkgr-0.0.3/one/six/seven/testfile"]

        self.post_files = ["/tmp/testStonixMacPkgr-0.0.3/one/postfile2", \
                     "/tmp/testStonixMacPkgr-0.0.3/one/two/three/3.5/postfile3"]

        self.post_dirs = ["/tmp/testStonixMacPkgr-0.0.3/one/six/6.5"]

        self.all_files = [self.pkg_files, self.post_files]
        self.all_dirs = [self.pkg_dirs, self.post_dirs]
        self.allowed_files_and_dirs = [self.pkg_dirs,
                                       self.pkg_dirs,
                                       self.post_dirs]
        self.ch = CommandHelper(self.logger)
        self.connection = Connectivity(self.logger)
        self.testDomain = "gov.lanl.testStonixMacPkgr.0.0.3.testStonixMacPkgr"

    ############################################################################
    
        """
        def setUp(self):

        self.osfamily = self.environ.getosfamily()
        if re.match("^macosx$", self.osfamily.strip()):
            myos = self.environ.getosfamiliy()
            raise unittest.SkipTest("RamDisk does not support this OS" + \
                                " family: " + str(myos))
        """
        
    ############################################################################
    
    @classmethod
    def tearDownClass(self):
        """
        Make sure the appropriate files are removed..
        """
        pass
        
    ############################################################################
    
    def test_inLinearFlow(self):
        """
        Run methods or functionality that requires order, ie a happens before b
        Like ensure a package is installed before testing if uninstall works.
        
        @author: Roy Nielsen
        """
        if sys.version_info < (2, 7):
            return
        if not self.connection.isPageAvailable():
            self.logger.log(LogPriority.INFO, "This test fails without a " + \
                                              "properly configured Mac " + \
                                              "repository, so we are not " + \
                                              "running actual tests...")
        else:
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

    ############################################################################
        
    def testCheckInstall(self):
        """
        Test the checkInstall method.
        
        1 - make sure the test .pkg is NOT installed
        2 - download the package and check the md5
        3 - use custom installer command to install the package
        4 - call the checkInstall method
        
        @author: Roy Nielsen
        """
        if sys.version_info < (2, 7):
            return
        if not self.connection.isPageAvailable():
            self.logger.log(LogPriority.INFO, "This test fails without a " + \
                                              "properly configured Mac " + \
                                              "repository, so we are not " + \
                                              "running actual tests...")
        else:
            #####
            # make sure the test .pkg is NOT installed
            self.pkgr.removePackage(self.macPackageName)
            
            #####
            # Test the checkInstall with the package removed
            self.assertFalse(self.pkgr.checkInstall(self.macPackageName))
            self.assertFalse(self.isInstalled())
            
            #####
            # Install the package
            self.pkgr.installPackage(self.macPackageName)
            
            #####
            # run checkInstall again
            self.assertTrue(self.pkgr.checkInstall(self.macPackageName))
            self.assertTrue(self.isInstalled())
        
    ############################################################################

    def testCheckAvailable(self):
        """
        Check if a package is available on the reporoot.
        
        Must have both the file AND the md5 checksum file on the server of the
        format:
        
        .<filename>.<UPPER-md5sum>
        
        Steps for this test:
        
        1 - set up self.pkgr.pkgUrl
        2 - run self.pkgr.downloadPackage
        3 - Make sure the checksum matches, otherwise there is a bad md5
            for the download, and the package should not be trusted, let alone
            installed.
        
        This covers two test cases -
        checkAvailable
        downloadPackage
        
        @author: Roy Nielsen
        """
        if sys.version_info < (2, 7):
            return
        if not self.connection.isPageAvailable():
            self.logger.log(LogPriority.INFO, "This test fails without a " + \
                                              "properly configured Mac " + \
                                              "repository, so we are not " + \
                                              "running actual tests...")
        else:
            self.assertTrue(self.reporoot + self.macPackageName)
            self.pkgr.setPkgUrl(self.reporoot + self.macPackageName)
            self.pkgr.package = self.macPackageName
            self.assertTrue(self.pkgr.downloadPackage(), "Package: " + \
                            str(self.pkgr.getPkgUrl()) + " FAILED download...")
            
            self.assertTrue(self.pkgr.checkMd5(), "MD5 checksum didn't match - " + \
                       "package: " + str(self.pkgr.hashUrl) + " is NOT " + \
                       "available...")
                
    ############################################################################

    def testFindDomain(self):
        """
        Test the findDomain function.  The domain is required to do a reverse 
        lookup in the local client package receipt database.  It should find
        all the files that have been installed by the PACKAGE, not the 
        postflight.
        
        Will remove the test package if it exists, install the package then
        use the test package to make sure the package file list is accurate.
        
        @author: Roy Nielsen
        """
        if sys.version_info < (2, 7):
            return
        if not self.connection.isPageAvailable():
            self.logger.log(LogPriority.INFO, "This test fails without a " + \
                                              "properly configured Mac " + \
                                              "repository, so we are not " + \
                                              "running actual tests...")
        else:
            #####
            # Make sure the package is installed
            self.pkgr.installPackage("testStonixMacPkgr-0.0.3.pkg")
            
            #####
            # Assert findDomain works properly when the package is installed
            self.assertEqual(self.testDomain, 
                             self.pkgr.findDomain("testStonixMacPkgr-0.0.3.pkg"))
        
    ############################################################################
    
    def testUnArchive(self):
        """
        Download a tar package with the test pkg in it.
        
        Will test doing a download and checksum of the following by downloading
        the file and doing a checksum, then unzipping the file, and check
        the internal filename:
        
        testStonixMacPkgr.zip
        
        @Note: *** Functionality needs approval ***
        
        @author: Roy Nielsen
        """
        pass
        
    ############################################################################
    
    def testCopyInstall(self):
        """
        Tests the copyInstall method.
        
        Will test by:
        
        Downloading the test .tar file with a .app in it, doing a checksum of
        the .tar file then performing a copyInstall.
        
        Will test by checking the existence of the .app being in the right 
        place.
        
        @author: Roy Nielsen
        """ 
        pass
        
    ############################################################################
    
    def testInstallPkg(self):
        """
        Tests the installPkg method.
        
        Will:
        Make sure the test pkg is not installed
        Download and checksum the file.
        install the .pkg with the installPkg method.
        
        @author: Roy Nielsen
        """
        if sys.version_info < (2, 7):
            return
        success = False
        try:
            #####
            # make sure the test .pkg is NOT installed
            self.pkgr.removePackage(self.macPackageName)
        except:
            pass

        #####
        # Check the URL for validity, or make sure we can get there..
        if self.connection.isPageAvailable(self.pkgUrl):
            
            #####
            # Set the pkgurl in the package manager
            self.pkgr.setPkgUrl(self.pkgUrl)
            
            #####
            # Download into a temporary directory
            success = self.pkgr.downloadPackage()
            if success:
                #####
                # Apple operating systems have a lazy attitude towards
                # writing to disk - the package doesn't get fully
                # written to disk until the following method is called.
                # Otherwise when the downloaded package is further 
                # manipulated, (uncompressed or installed) the 
                # downloaded file is not there.  There may be other 
                # ways to get python to do the filesystem sync...
                try:
                    self.libc.sync()
                except:
                    pass
                #####
                # Make sure the md5 of the file matches that of the
                # server
                if self.pkgr.checkMd5():
                    #####
                    # unarchive if necessary
                    compressed = [".tar", ".tar.gz", ".tgz", 
                                  ".tar.bz", ".tbz", ".zip"]
                    for extension in compressed:
                        if self.pkgUrl.endswith(extension):
                            self.pkgr.unArchive()
                        try:
                            self.libc.sync()
                        except:
                            pass
                    #####
                    # install - if extension is a .pkg or .mpkg use the 
                    # installer command
                    if self.pkgUrl.endswith (".pkg") or \
                         self.pkgUrl.endswith (".mpkg"):
                        success = self.pkgr.installPkg()
                        self.assertTrue(success)
                    else:
                        self.assertTrue(False)
                else:
                    self.assertTrue(False)    
            else:
                self.assertTrue(False)
        else:
            self.logger.log(LogPriority.INFO, "Not able to connect to server...")
            self.assertTrue(True)

        if success:
            #####
            # run checkInstall again
            self.assertTrue(self.pkgr.checkInstall(self.macPackageName))
            self.assertTrue(self.isInstalled())

        try:
            #####
            # make sure the test .pkg is NOT installed
            self.pkgr.removePackage(self.macPackageName)
        except:
            pass

    ############################################################################
    
    def testIsMacPlatform(self):
        """
        Make sure we are on the Mac platform.
        
        @author: Roy Nielsen
        """
        if sys.version_info < (2, 7):
            return
        if not self.connection.isPageAvailable():
            self.logger.log(LogPriority.INFO, "This test fails without a " + \
                                              "properly configured Mac " + \
                                              "repository, so we are not " + \
                                              "running actual tests...")
        else:
            self.assertTrue(self.environ.osfamily == "darwin", "Wrong OS...")
        
    ############################################################################
    
    def isFullInstall(self):
        """
        Make sure that all files and directories including those installed from
        the package and the postinstall script exist.
        
        @Note: In future, this should also do a receipt test as well.  This 
               would include getting the files from the receipt and checking
               for their existence and perhaps their permissions.
        
        @author: Roy Nielsen
        """

        files = self.doFilesExistTest(self.all_files)
        dirs = self.doDirsExist(self.all_dirs)
        
        if files and dirs:
            return True
        return False
    
    ############################################################################
    
    def isInstalled(self):
        """
        Test to make sure just the files and directories installed by the
        package are installed. Doesn't care about the files and directories
        installed by the postinstall script. 
        
        @author: Roy Nielsen
        """
        files = self.doFilesExistTest([self.pkg_files])
        dirs = self.doDirsExist([self.pkg_dirs])
        
        if files and dirs:
            return True
        return False

    ############################################################################
    
    def isMissing(self):
        """
        Test to make sure all the files have been removed that were Installed
        by the package.  Ignore, but note directories installed by the package
        that exist, as well as files and directories installed by the 
        postinstall script.
        
        @Note: In future, this test should check for a package receipt, and 
               make sure the files in the package receipt do not exist.  This
               is only valid for this package, as in the case of some software,
               like Adobe products, some of the files are shared libraries 
               between different products.
        
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
        for myset in self.allowed_files_and_dirs:
            #####
            # Cycle through each subset of files in the 
            for myfile in myset:
                if os.path.isdir(myfile):
                    self.logger.log(LogPriority.INFO, "Item: " + \
                                    str(myfile) + " exists...")
        if False in removed:
            return False
        return True

    ############################################################################
    
    def removeCompletePackage(self):
        """
        Remove all files, used to set the stage for install tests.
        
        @author:  Roy Nielsen
        """
        success = False
        try:
            testPath = "/tmp/testStonixMacPkgr-0.0.3"
            if os.path.exists(testPath):
                shutil.rmtree(testPath)
        except Exception, err:
            self.logger.log(LogPriority.INFO, "Test set already missing?")
            raise err
        else:
            self.logger.log(LogPriority.INFO, "Removed test package " + \
                                              "install set...")
            success = True

        #####
        # If the rmtree directive above did not throw an exception, make the
        # system "forget" the package
        if success:
            #####
            # get the domain, so we can "forget" the package
            domain = self.pkgr.findDomain(self.macPackageName)
            
            #####
            # Also need to remove the package receipt...
            # use pkgutil --forget
            cmd = ["/usr/sbin/pkgutil", "--forget", domain]
            
            self.ch.executeCommand(cmd)
            if not self.ch.getReturnCode() == 0:
                success = False
        return success
        
    ############################################################################
    
    def doFilesExistTest(self, files=[False]):
        """
        Test the directories in the passed in list to see if they all exist.
        
        @author: Roy Nielsen
        """
        not_installed = []
        exists = []
        #####
        # cycle through each set of files in all_files
        for myset in files:
            #####
            # Cycle through each subset of files in the 
            for myfile in myset:
                if not os.path.isfile(myfile):
                    self.logger.log(LogPriority.WARNING, "File: " + \
                                    str(myfile) + " does not exist...")
                    exists.append(False)
                    not_installed.append(str(myfile))
        if False in exists:
            message = "Not all files exist: " + str(not_installed)
            self.logger.log(LogPriority.DEBUG, message)
            return False
        return True
    
    ############################################################################
    
    def doDirsExist(self, dirs=[False]):
        """
        Check the directories in the passed in list to see if they all exist.
        
        @author: Roy Nielsen
        """
        not_installed = []
        exists = []
        #####
        # cycle through each set of directories in all_dirs
        for myset in dirs:
            #####
            # Cycle through each subset of files in the 
            for mydir in myset:
                if not os.path.isdir(mydir):
                    self.logger.log(LogPriority.WARNING, "Directory: " + \
                                    str(mydir) + " does not exist...")
                    exists.append(False)
                    not_installed.append(str(mydir))
        if False in exists:
            message = "Not all files exist: " + str(not_installed)
            self.logger.log(LogPriority.DEBUG, message)
            return False
        return True
