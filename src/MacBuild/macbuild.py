#!/usr/bin/env python3
###############################################################################
#                                                                             #
# Copyright 2019. Triad National Security, LLC. All rights reserved.          #
# This program was produced under U.S. Government contract 89233218CNA000001  #
# for Los Alamos National Laboratory (LANL), which is operated by Triad       #
# National Security, LLC for the U.S. Department of Energy/National Nuclear   #
# Security Administration.                                                    #
#                                                                             #
# All rights in the program are reserved by Triad National Security, LLC, and #
# the U.S. Department of Energy/National Nuclear Security Administration. The #
# Government is granted for itself and others acting on its behalf a          #
# nonexclusive, paid-up, irrevocable worldwide license in this material to    #
# reproduce, prepare derivative works, distribute copies to the public,       #
# perform publicly and display publicly, and to permit others to do so.       #
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
@change: 2016/04/04 rsn - changing logger to ramdisk's logger
@change: 2016/04/04 rsn - changing ramdisk to public repo of ramdisk (without git history)
@change: 2016/10/17 rsn - upgrading to pyinstaller 3.3 & PyQt5
'''
#--- Python specific libraries
import os
import re
import sys
import stat
import optparse
import traceback
import getpass
from glob import glob
from tempfile import mkdtemp
from time import time
from subprocess import call
from shutil import rmtree, copy2
from configparser import SafeConfigParser


# For setupRamdisk() and detachRamdisk()
sys.path.append("./ramdisk/")
from .ramdisk.macRamdisk import RamDisk, detach
from .ramdisk.lib.loggers import CyLogger
from .ramdisk.lib.loggers import LogPriority as lp
from .ramdisk.lib.get_libc import getLibc


class ConfusingConfigurationError(Exception):
    '''Meant for being thrown when the MacBuilder can't determine configuration
    information.
    
    @author: Roy Nielsen


    '''
    def __init__(self, *args, **kwargs):
        Exception.__init__(self, *args, **kwargs)


class MacBuilder():

    def __init__(self,
                 options=optparse.Values({"compileGui": False, "version": "0",
                                          "clean": False, "test": False, "debug":False, "sig":False}),
                 ramdisk_size=1024):
        '''
        Build .pkg and .dmg for stonix4mac
        @param ramdisk_size: int that defines ramdisk size in MB
        @param debug: to print debug messages
        '''
        if isinstance(options.debug, bool) and options.debug:
            debug = 20
        else:
            debug = 40
        self.logger = CyLogger(level=debug)
        self.logger.initializeLogs()
        self.ramdisk_size = ramdisk_size

        self.libc = getLibc()

        if options.sig:
            self.codesignSignature = options.sig

        self.mbl = None
        # This script needs to be run from [stonixroot]/src/MacBuild; make sure
        # that is our current operating location
        cwd = os.getcwd()
        if not re.search("src/MacBuild$", cwd):
            print("This script needs to be run from src/MacBuild. Exiting...")
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

        if not self.confParser():
            raise ConfusingConfigurationError("Cannot determine the correct configuration...")

        self.RSYNC = "/usr/bin/rsync"

        print(" ")
        print(" ")
        print("   ************************************************************")
        print("   ************************************************************")
        print(("   ***** App Version: " + self.APPVERSION))
        print("   ************************************************************")
        print("   ************************************************************")
        print(" ")
        print(" ")

        self.keyuser = eval(input("Keychain User: "))
        self.keypass = getpass.getpass("Keychain Password: ") 

        if not options.test:
            self.driver()

    def driver(self):
        '''The driver orchestrates the build process.'''

        # Check that user building stonix has uid 0
        current_user, _ = self.mbl.checkBuildUser()

        # Create temp home directory for building with pyinstaller
        directory = os.environ["HOME"]
        tmphome = mkdtemp(prefix=current_user + ".")
        os.environ["HOME"] = tmphome
        os.chmod(tmphome, 0o755)

        # Create a ramdisk and mount it to the tmphome
        ramdisk = self.setupRamdisk(self.ramdisk_size, tmphome)
        os.mkdir("/tmp/the_luggage")
        luggage = self.setupRamdisk(self.ramdisk_size,
                                    "/tmp/the_luggage")
        print(("Device for tmp ramdisk is: " + ramdisk))

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
            self.mbl.chownR(current_user, "src")

            # chmod so it's readable by everyone, writable by the group
            self.mbl.chmodR(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH |
                            stat.S_IWGRP, "src", "append")

            # Return to the start dir
            os.chdir(self.STONIX_ROOT + "/src/MacBuild")
        except (KeyboardInterrupt, SystemExit):
            self.exit(ramdisk, luggage, 130)
        except Exception:
            self.exit(ramdisk, luggage, 1)

        # Eject the ramdisk
        self.detachRamdisk(ramdisk)
        self.detachRamdisk(luggage)

        print(" ")
        print(" ")
        print("    Done building stonix4mac.app...")
        print(" ")
        print(" ")

    def setupRamdisk(self, size, mntpnt=""):
        ramdisk = RamDisk(str(size), mntpnt)

        if not ramdisk.success:
            print("Ramdisk setup failed...")
            raise Exception("Ramdisk setup failed...")

        return ramdisk.getDevice()

    def detachRamdisk(self, device):
        if detach(device):
            print(("Successfully detached disk: " + str(device).strip()))
            return True
        else:
            print(("Couldn't detach disk: " + str(device).strip()))
            raise Exception("Cannot eject disk: " + str(device).strip())

    def exit(self, ramdisk, luggage, exitcode=0):
        os.chdir(self.STONIX_ROOT)
        self.detachRamdisk(ramdisk)
        self.detachRamdisk(luggage)
        print((traceback.format_exc()))
        exit(exitcode)

    def clean(self):
        '''Clean all artifacts from previous builds.
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
        '''Compile the .ui files to .py files for stonix4mac.app. Works within the
        MacBuild/stonix4mac directory
        
        @author: Roy Nielsen, Eric Ball

        :param stonix4macDir: Path to the [stonixroot]/src/MacBuild/stonix4mac
            directory where this method should work

        '''
        try:
            returnDir = os.getcwd()
            os.chdir(stonix4macDir)

            print(("Starting compileStonix4MacAppUiFiles in " + os.getcwd()))

            # to compile the .ui files to .py files:
            print("Compiling Qt ui files to python files for stonix4mac.app...")
            call([self.PYUIC, "admin_credentials.ui"],
                 stdout=open("admin_credentials_ui.py", "w"))
            call([self.PYUIC, "stonix_wrapper.ui"],
                 stdout=open("stonix_wrapper_ui.py", "w"))
            call([self.PYUIC, "general_warning.ui"],
                 stdout=open("general_warning_ui.py", "w"))

            os.chdir(returnDir)
        except Exception:
            raise

        print("compileStonix4MacAppUiFiles Finished...")

    def setProgramArgumentsVersion(self, localizePath):
        '''Change the STONIX version to the version specified within the build
        script
        @author: Roy Nielsen, Eric Ball

        :param localizePath: Path to the [stonixroot]/src/stonix_resources/
            localize.py file that this method should modify

        '''
        print("Changing versions in localize.py...")
        try:
            self.mbl.regexReplace(localizePath,
                                  r"^STONIXVERSION =.*$",
                                  r"STONIXVERSION = '" + self.APPVERSION + "'",
                                  backupname="../stonix_resources/localize.py.bak")
        except Exception:
            raise

        print("Finished changing versions in localize.py...")

    def prepStonixBuild(self, MacBuildDir):
        '''Copy stonix source to app build directory
        @author: Roy Nielsen, Eric Ball

        :param MacBuildDir: Path to the [stonixroot]/src/MacBuild directory
            where this method should work

        '''
        print("Starting prepStonixBuild...")
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
        print("prepStonixBuild Finished...")

    def compileApp(self, appName, appVersion, appIcon, appPath):
        '''Compiles stonix4mac.app
        @author: Roy Nielsen, Eric Ball

        :param appName: Name of application as it should appear on OS X systems
        :param appVersion: Version of app being built
        :param appIcon: File name of icon for OS X app
        :param appPath: Path to [stonixroot]/src/MacBuild/[appName]

        '''
        print(("Started compileApp with " + appName + ", " + appVersion + \
            ", " + appIcon))
        try:
            returnDir = os.getcwd()
            os.chdir(appPath)

            self.logger.log(lp.DEBUG, "...")
            self.logger.log(lp.DEBUG, "...")
            self.logger.log(lp.DEBUG, "...")
            self.logger.log(lp.DEBUG, "\n\n\tPWD: " + appPath + " \n\n")
            myfiles = os.listdir('.')
            self.logger.log(lp.DEBUG, "\n\tDIRS: " + str(myfiles))
            self.logger.log(lp.DEBUG, "...")
            self.logger.log(lp.DEBUG, "...")
            self.logger.log(lp.DEBUG, "...")

            if os.path.isdir("build"):
                rmtree("build")
            if os.path.isdir("dist"):
                rmtree("dist")

            self.logger.log(lp.DEBUG, "Hidden imports: " + str(self.hiddenimports))

            hdnimports = self.hiddenimports + ['ctypes', '_ctypes', 'ctypes._endian', 'decimal', 'numbers']

            # to compile a pyinstaller spec file for app creation:
            print("Creating a pyinstaller spec file for the project...")
            print((self.mbl.pyinstMakespec([appName + ".py"], True, True, False,
                                          "../" + appIcon + ".icns",
                                         pathex=["stonix_resources/rules",
                                                  "stonix_resources", "/usr/lib"] + self.PYPATHS,
                                          specpath=os.getcwd(), hiddenimports=hdnimports)))
            '''
            if appName == "stonix":
                fo = open(appName + ".spec", "r")
                spectext = fo.read()
                fo.close()
                spectext = spectext.replace("hiddenimports=[]",
                                            "hiddenimports=['ctypes', " +
                                            "'_ctypes', 'ctypes._endian', " +
                                            "'decimal', 'numbers']")
                fo = open(appName + ".spec", "w")
                fo.write(spectext)
                fo.close()
            '''
            # to build:
            print("Building the app...")
            self.mbl.pyinstBuild(appName + ".spec", "private/tmp",
                                 appPath + "/dist", True, True)

            plist = appPath + "/dist/" + appName + ".app/Contents/Info.plist"

            # Change version string of the app
            print("Changing .app version string...")
            self.mbl.modplist(plist, "CFBundleShortVersionString", appVersion)

            # Change icon name in the app
            print("Changing .app icon...")
            self.mbl.modplist(plist, "CFBundleIconFile", appIcon + ".icns")

            # Copy icons to the resources directory
            copy2("../" + appIcon + ".icns",
                  "./dist/" + appName + ".app/Contents/Resources")

            # Change mode of Info.plist to 0755
            os.chmod(plist, 0o755)
            os.chdir('dist')

        except Exception:
            raise

        print(("compileApp with " + appName + ", " + appVersion + " Finished..."))

    def buildStonix4MacAppResources(self, appName, appPath, appPathParent):
        '''Copy and/or create all necessary files to the Resources directory
        of stonix4mac.app
        @author: Roy Nielsen, Eric Ball

        :param appName: Name of application as it should appear on OS X systems
        :param appPath: Path to [stonixroot]/src/MacBuild/[appName]
        :param appPathParent: 

        '''
        print(("Started buildStonix4MacAppResources with \"" + appName + \
            "\" in " + appPath + "..."))
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

            # Copy the stonix.conf file
            copy2(appPath + "/../etc/stonix.conf", appPath + "/" + appName +
                  "/dist/" + appName + ".app/Contents/Resources/stonix.conf")

            copy2(appPath + "/stonix/dist/stonix.app/Contents/MacOS/" +
                  "stonix_resources/localize.py", appPath + "/" + appName +
                  "/dist/" + appName + ".app/Contents/MacOS")

            #####
            # Copy helper files to the resources directory
            call([self.RSYNC, "-aqp", appPath + '/' + appName + '/Resources/',
                              appPath + "/" + appName + "/dist/" + appName + \
                              ".app/Contents/Resources"])

            #####
            # Need a disk checkpoint here to make sure all files are flushed
            # to disk, ie perform a filesystem sync.
            self.libc.sync()
            self.libc.sync()
            
            self.mbl.codeSign(self.keyuser, self.keypass, 
                              self.codesignSignature,
                              self.codesignVerbose,
                              self.codesignDeep,
                              "./" + appName + "/dist/" + appName + ".app")

            self.mbl.codeSign(self.keyuser, self.keypass, 
                              self.codesignSignature,
                              self.codesignVerbose,
                              self.codesignDeep,
                              "./" + appName + "/dist/" + appName +
                              ".app/Contents/Resources/stonix.app")

            os.chdir(returnDir)
        except Exception:
            raise
        print("buildStonix4MacAppResources Finished...")

    def buildStonix4MacAppPkg(self, appName, appVersion, appPath):
        '''Build installer package and wrap into a dmg
        @author: Roy Nielsen, Eric Ball

        :param appName: Name of application as it should appear on OS X systems
        :param appVersion: Version of app being built
        :param appPath: Path to [stonixroot]/src/MacBuild

        '''

        print("Started buildStonix4MacAppPkg...")
        try:
            returnDir = os.getcwd()
            os.chdir(appPath + "/" + appName)

            print("Putting new version into Makefile...")
            self.mbl.regexReplace("Makefile", r"PACKAGE_VERSION=",
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

            print(("Creating a .dmg file with a .pkg file inside for " + \
                "installation purposes..."))
            #call(["make", "dmg", "PACKAGE_VERSION=" + appVersion,
            #      "USE_PKGBUILD=1"])
            call(["make", "pkg", "PACKAGE_VERSION=" + appVersion,
                  "USE_PKGBUILD=1"])

            print("Moving dmg and pkg to the dmgs directory.")
            #dmgname = appName + "-" + appVersion + ".dmg"
            pkgname = appName + "-" + appVersion + ".pkg"
            #os.rename(dmgname, appPath + "/dmgs/" + dmgname)
            os.rename(pkgname, appPath + "/dmgs/" + pkgname)

            os.chdir(returnDir)
        except Exception:
            raise
        print("buildStonix4MacAppPkg... Finished")

    def configSectionMap(self, section):
        '''Acquire values from the config file and store in a dictionary.
        
        @author: rsn

        :param section: 

        '''
        dict1 = {}
        options = self.parser.options(section)
        for option in options:
            try:
                dict1[option] = self.parser.get(section, option)
                if dict1[option] == -1:
                    self.logger.log(lp.DEBUG, "skip: %s" % option)
            except:
                print(("exception on %s!" % option))
                dict1[option] = None
        print(dict1)
        return dict1

    def confParser(self):
        '''Parse a config file to find potential conf file settings.
        
        @author: rsn


        '''
        success = False
        # This script should be run from [stonixroot]/src/MacBuild. We must
        os.chdir("../..")
        self.STONIX_ROOT = os.getcwd()
        os.chdir("src/MacBuild")
        macbuild_root = os.getcwd()
        myconf = os.path.join(macbuild_root, 'macbuild.conf')
        print(myconf)
        if os.path.isfile(myconf):
            self.parser = SafeConfigParser()
            candidates =  [myconf, 'not_a_real_conf.conf']
            found = self.parser.read(candidates)
            missing = set(candidates) - set(found)

            try:
                dict1 = {}
                for section in self.parser.sections():
                    dict1[section] = self.configSectionMap(section)
                print(dict1)
            except:
                #####
                # happens if there was a problem attempting to read the config
                # file, Initializing class variables.
                self.STONIX = "stonix"
                self.STONIXICON = "stonix_icon"
                self.STONIXVERSION = self.APPVERSION
                self.STONIX4MAC = "stonix4mac"
                self.STONIX4MACICON = "stonix_icon"
                self.STONIX4MACVERSION = self.APPVERSION                
                #-- Internal libraries
                from .macbuildlib import macbuildlib
                self.mbl = macbuildlib(self.logger)
                self.PYUIC = self.mbl.getpyuicpath()
                self.codesignVerbose = 'vvvv'
                self.codesignDeep = True
            else:
                #####
                # Config file read, initializing class variables.
                self.STONIX = dict1['stonix']['app']
                self.STONIXICON = dict1['stonix']['app_icon']
                self.STONIXVERSION = dict1['stonix']['app_version']
                self.STONIX4MAC = dict1['stonix']['wrapper']
                self.STONIX4MACICON = dict1['stonix']['wrapper_icon']
                self.STONIX4MACVERSION = dict1['stonix']['wrapper_version']
                self.PYUIC = dict1['libpaths']['pyuic']
                self.PYPATHS = dict1['libpaths']['pythonpath'].split(':')
                self.logger.log(lp.INFO, 'attempting to get codesigning information...')
                self.codesignVerbose = dict1['codesign']['verbose']
                if re.match('^True$', dict1['codesign']['deep']):
                    self.codesignDeep = True
                else:
                    self.codesignDeep = False
                self.logger.log(lp.INFO, "Grabbed codesign info...")
                for path in self.PYPATHS:
                    sys.path.append(path)
                #-- Internal libraries
                try:
                    from .macbuildlib import macbuildlib
                    self.mbl = macbuildlib(self.logger, self.PYPATHS)
                except Exception as err:
                    raise
                self.logger.log(lp.INFO, "... macbuildlib loaded ...")
            finally:
                self.hiddenimports = self.mbl.getHiddenImports()
                self.logger.log(lp.DEBUG, "Hidden imports: " + str(self.hiddenimports))
                success = True

        return success

if __name__ == '__main__':
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
    parser.add_option("-t", "--test", action="store_true", dest="test",
                      default=False, help="If run in testing mode, " +
                      "the driver method does not execute, allowing for " +
                      "unit testing of functions")
    parser.add_option("-d", "--debug", action="store_true", dest="debug",
                      default=False, help="debug mode, on or off.  Default off.")
    parser.add_option("-s", "--signature", action="store", dest="sig",
                      type="string", default="",
                      help="Codesign signature to sign with.",
                      metavar="sig")
    options, __ = parser.parse_args()
    stonix4mac = MacBuilder(options)
