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
import sys
import shutil
import unittest

from src.stonix_resources.macpkgr import MacPkgr
from src.stonix_resources.environment import Environment
from src.tests.lib.logdispatcher_lite import LogDispatcher, LogPriority

class zzzTestFrameworkMacPkgr(unittest.TestCase):
    """
    Class for testing the macpkgr.
    """
    
    def setUp(self):
        """
        """
        self.macPackageName = "testStonixMacPkgr-0.0.3.pkg"
        self.reporoot = "https://jss.lanl.gov/CasperShare/"        
        self.environ = Environment()
        self.logger = LogDispatcher(self.environ)
        self.pkgr = MacPkgr(self.environ, self.logger, self.reporoot)
        if not self.environ.osfamily=="darwin":
            sys.exit(255)
        
    def tearDown(self):
        """
        Make sure the appropriate files are removed..
        """
        try:
            print "Will eventually delete /tmp/macpkgrtest"
            #shutil.rmtree("/tmp/macpkgrtest")
        except:
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
        try:
            shutil.rmtree("/tmp/macpkgrtest")
        except:
            self.logger.log(LogPriority.INFO, "Package not installed..." + \
                                              "Moving on...")

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
        # Looks for files and directories that are installed by the package.
        #self.assertTrue(self.isInstalled(), "Problem with installation...")
        """
        #####
        # Make sure it isn't a partial install...
        self.assertFalse(self.isPartialInstall(), "Partial install...")

        #####
        # Make sure that the package isn't missing
        self.assertFalse(self.isMissing(), "Problem, parts still installed...")

        #####
        # Remove the package, assert that it worked.                
        self.assertTrue(self.pkgr.removepackage(self.macPackageName),
                        "Problem removing package...")
        
        #####
        # Check that checkInstall returns the correct value
        self.assertFalse(self.pkgr.checkinstall(self.macPackageName),
                         "Problem with pkgr.checkinstall...")

        #####
        # Hand verify that self.pkgr.checkInstall worked.
        self.assertTrue(self.isMissing, "Problem with package removal...")
        """
        """
    def testIsMacPlatform(self):


        self.assertTrue(self.environ.osfamily=="darwin", "Wrong OS...")
        """