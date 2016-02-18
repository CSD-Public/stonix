#!/usr/bin/python

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
'''
Mac build script for STONIX. Based on original shell script by Roy Nielsen,
with large amounts of original code and comments left intact.

@author: Eric Ball
@change: 2015/03/06 eball - Original implementation
@change: 2015/03/31 rsn - Removed mkdtemp calls when working in ramdisk
@change: 2015/08/05 eball - Beautification, improving PEP8 compliance
@change: 2015/08/18 rsn - removed make self update method
@change: 2015/08/31 eball- Refactor
@change: 2015/10/13 eball - Completed code and comments refactoring
@change: 2015/10/14 eball - Added exit() method to gracefully detach ramdisk
    and exit, plus try/except blocks where appropriate
@change: 2015/10/14 eball - Added -c flag to clean artifacts
@change: 2016/01/26 ekkehard version 0.9.4
@change: 2016/02/03 ekkehard version 0.9.5
@change: 2016/02/03 ekkehard converted from log_message to print
@change: 2016/02/03 rsn - removing stale luggage build before building new
                          package with luggage.
@change: 2016/02/08 rsn - managing relative paths for libraries better.
@change: 2016/02/09 eball Added removal of /tmp/the_luggage, removed logging
    arguments from ramdisk calls.
'''
from __future__ import absolute_import
import sys
sys.path.append("../..")

import os
import stat
import optparse
import macbuildlib as mbl
import re
import traceback
from glob import glob
from tempfile import mkdtemp
from time import time
from subprocess import call
from shutil import rmtree, copy2
# For setupRamdisk() and detachRamdisk()
from macRamdisk import RamDisk, detach
from src.stonix_resources.environment import Environment
from src.tests.lib.logdispatcher_lite import LogDispatcher, LogPriority


class MacBuilder():

    def __init__(self):
        '''
        Build .pkg and .dmg for stonix4mac
        '''
        parser = optparse.OptionParser()
        parser.add_option("-v", "--version", action="store", dest="version",
                          type="string", default="0",
                          help="Set the STONIX build version number",
                          metavar="version")
        parser.add_option("-g", "--gui", action="store_true",
                          dest="compileGui",
                          default=False,
                          help="If set, the PyQt files will be recompiled")
        parser.add_option("-c", "--clean", action="store_true", dest="clean",
                          default=False, help="Clean all artifacts from " +
                          "previous builds and exit")
        options, __ = parser.parse_args()

        # This script needs to be run from [stonixroot]/src/MacBuild; make sure
        # that is our current operating location
        cwd = os.getcwd()
        if not re.search("src/MacBuild$", cwd):
            print "This script needs to be run from src/MacBuild. Exiting..."
            exit(1)

        try:
            rmtree("/tmp/the_luggage")
        except OSError as e:
            if not e.errno == 2:
                raise
        if options.clean:
            self.clean()

        # If version was not included at command line, use hardcoded version
        # number
        if options.version == "0":
            self.APPVERSION = "0.9.5.0"
        else:
            self.APPVERSION = options.version

        self.compileGui = options.compileGui

        self.RSYNC = "/usr/bin/rsync"
        self.PYUIC = mbl.getpyuicpath()
        self.DEFAULT_RAMDISK_SIZE = 2 * 1024 * 500

        # This script should be run from [stonixroot]/src/MacBuild. We must
        # record the [stonixroot] directory in a variable.
        os.chdir("../..")
        self.STONIX_ROOT = os.getcwd()
        os.chdir("src/MacBuild")

        print " "
        print " "
        print "   ************************************************************"
        print "   ************************************************************"
        print "   ***** App Version: " + self.APPVERSION
        print "   ************************************************************"
        print "   ************************************************************"
        print " "
        print " "

        self.STONIX = "stonix"
        self.STONIXICON = "stonix_icon"
        self.STONIXVERSION = self.APPVERSION
        self.STONIX4MAC = "stonix4mac"
        self.STONIX4MACICON = "stonix_icon"
        self.STONIX4MACVERSION = self.APPVERSION

        self.driver()

    def driver(self):
        '''
        The driver orchestrates the build process.
        '''

        # Check that user building stonix has uid 0
        current_user, _ = mbl.checkBuildUser()

        # Create temp home directory for building with pyinstaller
        directory = os.environ["HOME"]
        tmphome = mkdtemp(prefix=current_user + ".")
        os.environ["HOME"] = tmphome
        os.chmod(tmphome, 0755)

        # Create a ramdisk and mount it to the tmphome
        ramdisk = self.setupRamdisk(self.DEFAULT_RAMDISK_SIZE, tmphome)
        print "Device for tmp ramdisk is: " + ramdisk

        # After creation of the ramdisk, all further calls need to be wrapped
        # in a try/except block so that the ramdisk will be detached before
        # exit
        try:
            # Copy src dir to /tmp/<username> so shutil doesn't freak about
            # long filenames.
            # ONLY seems to be a problem on Mavericks
            call([self.RSYNC, "-aqp", "--exclude=\".svn\"",
                  "--exclude=\"*.tar.gz\"", "--exclude=\"*.dmg\"",
                  self.STONIX_ROOT + "/src", tmphome])

            # Compile .ui files to .py files
            if self.compileGui:
                self.compileStonix4MacAppUiFiles(tmphome +
                                                 "/src/MacBuild/stonix4mac")

            # Change the versions in the program_arguments.py in both stonix
            # and stonix4mac
            self.setProgramArgumentsVersion(tmphome +
                                            "/src/stonix_resources/" +
                                            "localize.py")

            # Copy stonix source to scratch build directory
            self.prepStonixBuild(tmphome + "/src/MacBuild")

            # Compile the two apps...
            self.compileApp(self.STONIX, self.STONIXVERSION, self.STONIXICON,
                            tmphome + "/src/MacBuild/" + self.STONIX)
            self.compileApp(self.STONIX4MAC, self.STONIX4MACVERSION,
                            self.STONIX4MACICON, tmphome + "/src/MacBuild/" +
                            self.STONIX4MAC)

            # Restore the HOME environment variable
            os.environ["HOME"] = directory

            # Copy and create all necessary resources to app resources dir.
            # This only gets called for stonix4mac
            self.buildStonix4MacAppResources(self.STONIX4MAC, tmphome +
                                             "/src/MacBuild", tmphome + "/src")

            # Create dmg and pkg with luggage
            self.buildStonix4MacAppPkg(self.STONIX4MAC, self.STONIX4MACVERSION,
                                       tmphome + "/src/MacBuild")

            # Copy back to pseudo-build directory
            call([self.RSYNC, "-aqp", tmphome + "/src", self.STONIX_ROOT])

            os.chdir(self.STONIX_ROOT)
            mbl.chownR(current_user, "src")

            # chmod so it's readable by everyone, writable by the group
            mbl.chmodR(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH |
                       stat.S_IWGRP, "src", "append")

            # Return to the start dir
            os.chdir(self.STONIX_ROOT + "/src/MacBuild")
        except (KeyboardInterrupt, SystemExit):
            self.exit(ramdisk, 130)
        except Exception:
            self.exit(ramdisk, 1)

        # Eject the ramdisk
        self.detachRamdisk(ramdisk)

        print " "
        print " "
        print "    Done building stonix4mac.app..."
        print " "
        print " "

    def setupRamdisk(self, size, mntpnt=""):
        ramdisk = RamDisk(str(size), mntpnt)

        if not ramdisk.success:
            print("Ramdisk setup failed...")
            raise Exception("Ramdisk setup failed...")

        return ramdisk.getDevice()

    def detachRamdisk(self, device):
        if detach(device):
            print("Successfully detached disk: " + str(device).strip())
        else:
            print("Couldn't detach disk: " + str(device).strip())
            raise Exception("Cannot eject disk: " + str(device).strip())

    def exit(self, ramdisk, exitcode=0):
        os.chdir(self.STONIX_ROOT)
        self.detachRamdisk(ramdisk)
        print traceback.format_exc()
        exit(exitcode)

    def clean(self):
        '''
        Clean all artifacts from previous builds.
        @author: Eric Ball
        '''

        folders = (["dmgs", "stonix", "stonix4mac/dist", "stonix4mac/private"]
                   + glob("stonix.*") + glob("dmgs.*"))
        files = (glob("*.pyc") + glob("stonix4mac/*.pyc") +
                 glob("stonix4mac/*_ui.py") + glob("stonix4mac/*.spec"))
        for folder in folders:
            try:
                rmtree(folder)
            except OSError as e:
                if not e.errno == 2:
                    raise
        for rmfile in files:
            os.remove(rmfile)
        exit(0)

    def compileStonix4MacAppUiFiles(self, stonix4macDir):
        '''
        Compile the .ui files to .py files for stonix4mac.app. Works within the
        MacBuild/stonix4mac directory

        @author: Roy Nielsen, Eric Ball
        @param stonix4macDir: Path to the [stonixroot]/src/MacBuild/stonix4mac
            directory where this method should work
        '''
        try:
            returnDir = os.getcwd()
            os.chdir(stonix4macDir)

            print "Starting compileStonix4MacAppUiFiles in " + os.getcwd()

            # to compile the .ui files to .py files:
            print "Compiling Qt ui files to python files for stonix4mac.app..."
            call([self.PYUIC, "admin_credentials.ui"],
                 stdout=open("admin_credentials_ui.py", "w"))
            call([self.PYUIC, "stonix_wrapper.ui"],
                 stdout=open("stonix_wrapper_ui.py", "w"))
            call([self.PYUIC, "general_warning.ui"],
                 stdout=open("general_warning_ui.py", "w"))

            os.chdir(returnDir)
        except Exception:
            raise

        print "compileStonix4MacAppUiFiles Finished..."

    def setProgramArgumentsVersion(self, localizePath):
        '''
        Change the STONIX version to the version specified within the build
        script
        @author: Roy Nielsen, Eric Ball
        @param localizePath: Path to the [stonixroot]/src/stonix_resources/
            localize.py file that this method should modify
        '''
        print "Changing versions in localize.py..."
        try:
            mbl.regexReplace(localizePath,
                             r"^STONIXVERSION =.*$",
                             r"STONIXVERSION = '" + self.APPVERSION + "'",
                             backupname="../stonix_resources/localize.py.bak")
        except Exception:
            raise

        print "Finished changing versions in localize.py..."

    def prepStonixBuild(self, MacBuildDir):
        '''
        Copy stonix source to app build directory
        @author: Roy Nielsen, Eric Ball
        @param MacBuildDir: Path to the [stonixroot]/src/MacBuild directory
            where this method should work
        '''
        print "Starting prepStonixBuild..."
        try:
            returnDir = os.getcwd()
            os.chdir(MacBuildDir)

            # Make sure the "stonix" directory exists, so we can put
            # together and create the stonix.app
            if os.path.islink("stonix"):
                os.unlink("stonix")
            if not os.path.isdir("stonix"):
                os.mkdir("stonix")
            else:
                # Cannot use mkdtmp here because it will make the directory on
                # the root filesystem instead of the ramdisk, then it will try
                # to link across filesystems which won't work
                tmpdir = "stonix." + str(time())
                os.rename("stonix", tmpdir)
                os.mkdir("stonix")

            copy2("../stonix.py", "stonix")
            call([self.RSYNC, "-ap", "--exclude=\".svn\"",
                  "--exclude=\"*.tar.gz\"", "--exclude=\"*.dmg\"",
                  "--exclude=\".git*\"", "../stonix_resources", "./stonix"])

            os.chdir(returnDir)
        except Exception:
            raise
        print "prepStonixBuild Finished..."

    def compileApp(self, appName, appVersion, appIcon, appPath):
        '''
        Compiles stonix4mac.app
        @author: Roy Nielsen, Eric Ball
        @param appName: Name of application as it should appear on OS X systems
        @param appVersion: Version of app being built
        @param appIcon: File name of icon for OS X app
        @param appPath: Path to [stonixroot]/src/MacBuild/[appName]
        '''
        print "Started compileApp with " + appName + ", " + appVersion + \
            ", " + appIcon
        try:
            returnDir = os.getcwd()
            os.chdir(appPath)

            if os.path.isdir("build"):
                rmtree("build")
            if os.path.isdir("dist"):
                rmtree("dist")

            # to compile a pyinstaller spec file for app creation:
            print "Creating a pyinstaller spec file for the project..."
            print mbl.pyinstMakespec([appName + ".py"], True, True, False,
                                     "../" + appIcon + ".icns",
                                     pathex=["stonix_resources/rules:" +
                                             "stonix_resources"],
                                     specpath=os.getcwd())

            # to build:
            print "Building the app..."
            mbl.pyinstBuild(appName + ".spec", "private/tmp",
                            appPath + "/dist", True, True)

            plist = appPath + "/dist/" + appName + ".app/Contents/Info.plist"

            # Change version string of the app
            print "Changing .app version string..."
            mbl.modplist(plist, "CFBundleShortVersionString", appVersion)

            # Change icon name in the app
            print "Changing .app icon..."
            mbl.modplist(plist, "CFBundleIconFile", appIcon + ".icns")

            # Copy icons to the resources directory
            copy2("../" + appIcon + ".icns",
                  "./dist/" + appName + ".app/Contents/Resources")

            # Change mode of Info.plist to 0755
            os.chmod(plist, 0755)

            os.chdir(returnDir)
        except Exception:
            raise

        print "compileApp with " + appName + ", " + appVersion + " Finished..."

    def buildStonix4MacAppResources(self, appName, appPath, appPathParent):
        '''
        Copy and/or create all necessary files to the Resources directory
        of stonix4mac.app
        @author: Roy Nielsen, Eric Ball
        @param appName: Name of application as it should appear on OS X systems
        @param appPath: Path to [stonixroot]/src/MacBuild/[appName]
        '''
        print "Started buildStonix4MacAppResources with \"" + appName + \
            "\" in " + appPath + "..."
        try:
            returnDir = os.getcwd()
            os.chdir(appPath)
            # Copy source to app dir
            call([self.RSYNC, "-aqp", "--exclude=\".svn\"",
                  "--exclude=\"*.tar.gz\"", "--exclude=\"*.dmg\"",
                  "--exclude=\".git*\"", appPathParent + "/stonix_resources",
                  appPath + "/stonix/dist/stonix.app/Contents/MacOS"])

            # Copy stonix.app to the stonix4mac Resources directory
            call([self.RSYNC, "-aqp", "--exclude=\".svn\"",
                  "--exclude=\"*.tar.gz\"", "--exclude=\"*.dmg\"",
                  "--exclude=\".git*\"", appPath + "/stonix/dist/stonix.app",
                  "./" + appName + "/dist/" + appName +
                  ".app/Contents/Resources"])

            # Create an empty stonix.conf file
            open(appPath + "/" + appName + "/dist/" + appName +
                 ".app/Contents/Resources/stonix.conf", "w")

            copy2(appPath + "/stonix/dist/stonix.app/Contents/MacOS/" +
                  "stonix_resources/localize.py", appPath + "/" + appName +
                  "/dist/" + appName + ".app/Contents/MacOS")

            os.chdir(returnDir)
        except Exception:
            raise
        print "buildStonix4MacAppResources Finished..."

    def buildStonix4MacAppPkg(self, appName, appVersion, appPath):
        '''
        Build installer package and wrap into a dmg
        @author: Roy Nielsen, Eric Ball
        @param appName: Name of application as it should appear on OS X systems
        @param appVersion: Version of app being built
        @param appPath: Path to [stonixroot]/src/MacBuild
        '''

        print "Started buildStonix4MacAppPkg..."
        try:
            # 2/3/2015 - rsn adding this to make sure the luggage build does 
            # not go stale
            l_tmp_dir = "/tmp/the_luggage"
            if os.path.exists(l_tmp_dir):
                rmtree(l_tmp_dir)

            returnDir = os.getcwd()
            os.chdir(appPath + "/" + appName)

            print "Putting new version into Makefile..."
            mbl.regexReplace("Makefile", r"PACKAGE_VERSION=",
                             "PACKAGE_VERSION=" + appVersion)

            if not os.path.isdir(appPath + "/dmgs"):
                os.mkdir(appPath + "/dmgs")
            else:
                # Cannot use mkdtmp here because it will make the directory on
                # the root filesystem instead of the ramdisk, then it will try
                # to link across filesystems which won't work
                tmpdir = appPath + "/dmgs." + str(time())
                os.rename(appPath + "/dmgs", tmpdir)
                os.mkdir(appPath + "/dmgs")

            print "Creating a .dmg file with a .pkg file inside for " + \
                "installation purposes..."
            call(["make", "dmg", "PACKAGE_VERSION=" + appVersion,
                  "USE_PKGBUILD=1"])
            call(["make", "pkg", "PACKAGE_VERSION=" + appVersion,
                  "USE_PKGBUILD=1"])

            print "Moving dmg and pkg to the dmgs directory."
            dmgname = appName + "-" + appVersion + ".dmg"
            pkgname = appName + "-" + appVersion + ".pkg"
            os.rename(dmgname, appPath + "/dmgs/" + dmgname)
            os.rename(pkgname, appPath + "/dmgs/" + pkgname)

            os.chdir(returnDir)
        except Exception:
            raise
        print "buildStonix4MacAppPkg... Finished"

if __name__ == '__main__':
    stonix4mac = MacBuilder()
