#!/usr/bin/env python
'''
###############################################################################
#                                                                             #
# Copyright 2015-2019.  Los Alamos National Security, LLC. This material was       #
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

Created on 2016/03/14

@author: Eric Ball
'''
from __future__ import absolute_import
import optparse
import os
import re
import sys
import unittest

sys.path.append("../../../..")
from shutil import rmtree
from src.tests.lib.logdispatcher_lite import LogDispatcher
from src.stonix_resources.CommandHelper import CommandHelper
from src.stonix_resources.environment import Environment
from src.MacBuild import build


class zzzTestFrameworkmacbuild(unittest.TestCase):

    def setUp(self):
        self.enviro = Environment()
        self.enviro.setdebugmode(True)
        self.logger = LogDispatcher(self.enviro)
        self.ch = CommandHelper(self.logger)
        self.changedDir = False
        # stonixtest must currently be run from the stonixroot directory, so
        # that is the best bet for the cwd
        if os.path.exists("src/Macbuild"):
            os.chdir("src/Macbuild")
            self.changedDir = True    # Cannot guarantee that test will end in
            self.myDir = os.getcwd()  # this dir, so we record it first
        self.mb = build.SoftwareBuilder(options=optparse.Values({"compileGui":
                                                               True,
                                                               "version": "0.dev-UT",
                                                               "clean": False,
                                                               "test": True}))

    def tearDown(self):
        if self.changedDir:
            os.chdir(self.myDir)
            self.ch.executeCommand(["./build.py", "-c"])
            os.chdir("../..")

    def testSetupAndDetachRamdisk(self):
        path = "/tmp/mount_ramdisk_for_ut"
        if os.path.exists(path):
            rmtree(path)
        os.mkdir(path)
        device = self.mb.setupRamdisk(512, path)
        self.assertRegexpMatches(device, "/dev/disk\d+",
                                 "Unexpected return from setupRamdisk")
        self.assertTrue(self.mb.detachRamdisk(device),
                        "Did not successfully detach ramdisk")

    def testExitMethod(self):
        ramdiskPath = "/tmp/mount_ramdisk_for_ut"
        luggagePath = "/tmp/luggage_ramdisk_for_ut"
        ramdisk = self.mb.setupRamdisk(1024, ramdiskPath)
        luggage = self.mb.setupRamdisk(1024, luggagePath)
        self.assertRaises(SystemExit, self.mb.exit, ramdisk, luggage, 999)

    def testCompileStonix4MacAppUiFilesMethod(self):
        self.mb.compileStonix4MacAppUiFiles("./stonix4mac")
        try:
            adminCred = open("stonix4mac/admin_credentials_ui.py", "r").read()
            stonixWrapper = open("stonix4mac/stonix_wrapper_ui.py", "r").read()
            generalWarning = open("stonix4mac/general_warning_ui.py",
                                  "r").read()
        except OSError:
            self.assertTrue(False, "One or more UI files could not be found")
        else:
            self.assertTrue(adminCred, "admin_credentials_ui.py file is empty")
            self.assertTrue(stonixWrapper,
                            "stonix_wrapper_ui.py file is empty")
            self.assertTrue(generalWarning,
                            "general_warning_ui.py file is empty")
        self.assertRaises(OSError, self.mb.compileStonix4MacAppUiFiles,
                          "thisdirdoesnotexist")

    def testSetProgramArgumentsVersionMethod(self):
        path = "../stonix_resources/localize.py"
        self.mb.setProgramArgumentsVersion(path)
        version = self.mb.APPVERSION
        localizeContents = open(path, "r").read()
        self.assertTrue(re.search(version, localizeContents),
                        "Could not find correct version in localize.py")
        self.assertRaises(IOError, self.mb.setProgramArgumentsVersion,
                          "badpath.py")

    def testPrepStonixBuildMethod(self):
        self.mb.prepStonixBuild(".")
        stonixDirList = os.listdir("stonix")
        self.assertTrue(stonixDirList, "No files found in stonix directory")
        self.assertRaises(OSError, self.mb.prepStonixBuild, "thisdirisfake")

    def testDriverAndBuildMethods(self):
        # Due to issues with dependencies, several methods cannot be easily
        # tested as units. Therefore, the "driver" method is run, and artifacts
        # from each method are checked.
        self.mb.driver()
        # Check compileApp artifacts
        try:
            stonixSpec = open("stonix/stonix.spec", "r").read()
            stonix4macSpec = open("stonix4mac/stonix4mac.spec", "r").read()
        except IOError:
            self.assertTrue(False, "One or more spec files not found")
        else:
            self.assertTrue(stonixSpec, "stonix.spec file is empty")
            self.assertTrue(stonix4macSpec, "stonix4mac.spec file is empty")
        # Check buildStonix4MacAppResources artifacts
        self.assertTrue(os.path.exists("stonix4mac/dist/stonix4mac.app/" +
                                       "Contents/Resources/stonix.conf"),
                        "Could not find stonix.conf file in package")
        self.assertTrue(os.path.exists("stonix4mac/dist/stonix4mac.app/" +
                                       "Contents/Resources/stonix.app"),
                        "Could not find stonix.app in stonix4mac.app Resources")
        # Check buildStonix4MacAppPkg artifacts
        self.assertTrue(os.path.exists("dmgs/stonix4mac-0.dev-UT.pkg"),
                        "Could not find stonix4mac pkg file")

if __name__ == "__main__":
    unittest.main()
