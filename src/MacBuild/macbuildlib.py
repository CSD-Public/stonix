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

from _ast import With
from pip._vendor.lockfile import UnlockError
'''
Created 02/23/2015

Library of functions used to build Mac applications
@author: Eric Ball
@change: 2015/03/06 eball - Original implementation
@change: 2015/08/05 eball - Beautification, improving PEP8 compliance
@change: 2015/08/06 eball - Removed static paths from getpyuicpath()
'''

import re
import os
import sys
import tarfile
import pwd
import zipfile
import plistlib as pl
from glob import glob
from subprocess import Popen, STDOUT, PIPE
from PyInstaller.building import makespec, build_main

sys.path.append('./ramdisk')

from .ramdisk.lib.loggers import LogPriority as lp
from .ramdisk.lib.manage_user.manage_user import ManageUser
from .ramdisk.lib.manage_keychain.manage_keychain import ManageKeychain


class macbuildlib(object):
    def __init__(self, logger, pypaths=None):
        self.pypaths = pypaths
        self.logger = logger
        self.manage_user = ManageUser(self.logger)
        self.manage_keychain = ManageKeychain(self.logger)

    def regexReplace(self, filename, findPattern, replacePattern, outputFile="",
                     backupname=""):
        '''Find and replace text in a file using regular expression patterns.
        
        @author: Eric Ball

        :param filename: name of origin file
        :param findPattern: string containing the regex to find in the file
        :param replacePattern: string containing the text to replace the
                               findPattern with
        :param outputFile: name of file to output new text to. If not supplied,
                           output will be written back to the origin file (Default value = "")
        :param backupname: optional name of backup for origin file (Default value = "")

        '''
        try:
            if backupname != "":
                open(backupname, "w").write(open(filename, "r").read())

            fileText = open(filename, "r").read()
            find = re.compile(findPattern, re.M)  # re.M = multiline flag
            result = find.sub(replacePattern, fileText)

            if outputFile == "":
                open(filename, "w").write(result)
            else:
                open(outputFile, "w").write(result)
        except Exception:
            raise

    def makeTarball(self, source, dest):
        '''A quick and easy method to create a .tar.gz out of a single file or folder

        :param source: 
        :param dest: 

        '''
        try:
            with tarfile.open(dest, "w:gz") as tar:
                tar.add(source)
        except Exception:
            raise

    def makeZip(self, source, dest):
        '''A quick and easy method to create a .zip out of a single file or folder

        :param source: 
        :param dest: 

        '''
        try:
            with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as myzip:
                myzip.write(source)
        except Exception:
            raise

    def pyinstMakespec(self, scripts, noupx=False, strip=False, console=True,
                       icon_file=None, pathex=[], specpath=None, hiddenimports=None):
        '''An interface for direct access to PyInstaller's makespec function
        
        @author: Eric Ball

        :param scripts: A list of python scripts to make a specfile for
        :param noupx: Do not use UPX even if it is available (Default value = False)
        :param strip: Apply a symbol-table strip to the executable and shared libs (Default value = False)
        :param console: Open a console window for standard i/o (Default value = True)
        :param icon_file: icon to be used for the completed program (Default value = None)
        :param pathex: A path to search for imports (like using PYTHONPATH) (Default value = [])
        :param specpath: Folder to store the generated spec file (default: CWD)
        :param hiddenimports:  (Default value = None)
        :returns: Output of PyInstaller.makespec
        @note: PyInstaller.makespec accepts further options,
               which may need to be added in future versions

        '''
        # specpath default cannot be reliably set here; os.getcwd() will return dir
        # of macbuildlib, not necessarily the current working dir of the calling
        # script. Therefore, if it is not specified, leave blank and let
        # PyInstaller set default.
        try:
            if specpath:
                return makespec.main(scripts, noupx=noupx, strip=strip,
                                     console=console, icon_file=icon_file,
                                     pathex=pathex, specpath=specpath, hiddenimports=hiddenimports)
            else:
                return makespec.main(scripts, noupx=noupx, strip=strip,
                                     console=console, icon_file=icon_file,
                                     pathex=pathex, hiddenimports=hiddenimports)
        except Exception:
            raise

    def pyinstBuild(self, specfile, workpath, distpath, clean_build=False,
                    noconfirm=False):
        '''An interface for direct access to PyInstaller's build function
        
        @author: Eric Ball

        :param specfile: The specfile to be built
        :param workpath: Where to put all the temporary work files
        :param distpath: Where to put the bundled app
        :param clean_build: Clean PyInstaller cache and remove temporary files
                            before building (Default value = False)
        :param noconfirm: Replace output directory without asking for confirmation (Default value = False)
        :returns: Output of PyInstaller.build
        @note: PyInstaller.build accepts further options,
               which may need to be added in future versions

        '''
        try:
            kwargs = {'workpath': workpath, 'loglevel': 'INFO', 'distpath':
                      distpath, 'upx_dir': None, 'ascii': None, 'clean_build':
                      clean_build}
        except Exception:
            raise

        return build_main.main(None, specfile, noconfirm, **kwargs)

    def chownR(self, user, target):
        '''Recursively apply chown to a directory

        :param user: 
        :param target: 

        '''
        try:
            if not os.path.isdir(target):
                raise TypeError(target)
            else:
                uid = pwd.getpwnam(user)[2]
                for root, dirs, files in os.walk(target):
                    os.chown(root, uid, -1)
                    for mydir in dirs:
                        os.chown(os.path.join(root, mydir), uid, -1)
                    for myfile in files:
                        os.chown(os.path.join(root, myfile), uid, -1)
        except TypeError:
            print("Error: Cannot chownR, target must be a directory")
            raise
        except Exception:
            raise

    def chmodR(self, perm, target, writemode):
        '''Recursively apply chmod to a directory
        
        @author: Eric Ball

        :param perm: Permissions to be applied. For information on available
                     permissions/modes, see os.chmod documentation at
                     https://docs.python.org/2/library/os.html#os.chmod
        :param target: Target directory
        :param writemode: a]ppend or [o]verwrite

        '''
        try:
            if not os.path.isdir(target):
                raise TypeError(target)
            else:
                try:
                    if writemode[0] == "a":
                        for root, dirs, files in os.walk(target):
                            # Change permissions for root directory
                            currentPerm = os.stat(root)[0]
                            newPerm = currentPerm | perm
                            os.chmod(root, newPerm)
                            # Change permissions for child directories
                            for mydir in dirs:
                                currentPerm = os.stat(os.path.join(root, mydir))[0]
                                newPerm = currentPerm | perm
                                os.chmod(os.path.join(root, mydir), newPerm)
                            # Change permissions for all files
                            for myfile in files:
                                currentPerm = os.stat(os.path.join(root,
                                                                   myfile))[0]
                                newPerm = currentPerm | perm
                                os.chmod(os.path.join(root, myfile), newPerm)
                    elif writemode[0] == "o":
                        for root, dirs, files in os.walk(target):
                            # Change permissions for root directory
                            os.chmod(root, perm)
                            # Change permissions for child directories
                            for mydir in dirs:
                                os.chmod(os.path.join(root, mydir), perm)
                            # Change permissions for all files
                            for myfile in files:
                                os.chmod(os.path.join(root, myfile), perm)
                    else:
                        raise NameError(writemode)
                except NameError:
                    raise
        except TypeError:
            print("Error: Cannot chmodR target, must be a directory")
            raise
        except NameError:
            print("Error: Invalid writemode specified. Please use [a]ppend " + \
                "or [o]verwrite")
            raise
        except Exception:
            raise

    def modplist(self, targetFile, targetKey, newValue):
        '''Modify the value of a particular key in a Mac OS X property list file
        
        @author: Eric Ball

        :param targetFile: Path to the plist to be modified
        :param targetKey: The particular key within the plist to be modified
        :param newValue: The new value for the targetKey within the targetFile

        '''
        try:
            mypl = pl.readPlist(targetFile)
            mypl[targetKey] = newValue
            pl.writePlist(mypl, targetFile)
        except Exception:
            raise

    def getHiddenImports(self):
        '''Acquire a list of all '*.py' files in the stonix_resources directory,
        replace '/' with '.' for a module name that can be imported.
        
        @author: Roy Nielsen


        '''
        try:
            origdir = os.getcwd()
            
            os.chdir("..")
            hiddenimports = []
            for root, dirs, files in os.walk("stonix_resources"):
                for myfile in files:
                    if myfile.endswith(".py"):
                         #print(os.path.join(root, file)) 
                         #####
                         # Create an 'import' name based on the file found.
                         myfile = re.sub(".py", "", myfile)
                         hiddenimportfile = os.path.join(root, myfile)
                         # Create a list out of the name, removing '/''s to
                         # set up for concatinating with '.'s
                         hiddenimportlist = hiddenimportfile.split('/')
                         # Concatinating the list with '.'s to add to the 
                         # hiddenimports list.
                         hiddenimport = ".".join(hiddenimportlist)
                         hiddenimports.append(hiddenimport)
        except OSError:
            self.logger.log(lp.DEBUG, "Error trying to acquire python files...")
        finally:
            os.chdir(origdir)
        
        return hiddenimports
        
    def getpyuicpath(self):
        '''Attempt to find PyQt4
        
        @author: Eric Ball


        :returns: Path to PyQt4 executable pyuic4

        '''
        # This method is called before ramdisk creation, so it does not use the
        # try/except block that most methods do
        fwpath = "/Users/Shared/Frameworks/"
        pathend1 = "/pyuic/pyuic4"
        pathend2 = "/pyuic4"
        if os.path.exists(fwpath):
            cwd = os.getcwd()
            os.chdir(fwpath)
            pyqtdirs = glob("PyQt-*")
            if len(pyqtdirs) == 1:
                fullpath = fwpath + pyqtdirs[0] + pathend1
                if os.path.exists(fullpath):
                    os.chdir(cwd)
                    return fullpath
                else:
                    fullpath = fwpath + pyqtdirs[0] + pathend2
                    if os.path.exists(fullpath):
                        os.chdir(cwd)
                        return fullpath
            elif len(pyqtdirs) == 0:
                pyqtdirs = glob("PyQt/PyQt-*")
                if len(pyqtdirs) == 1:
                    fullpath = fwpath + pyqtdirs[0] + pathend1
                    if os.path.exists(fullpath):
                        os.chdir(cwd)
                        return fullpath
                    else:
                        fullpath = fwpath + pyqtdirs[0] + pathend2
                        if os.path.exists(fullpath):
                            os.chdir(cwd)
                            return fullpath
        print("PyQt4 path not found. Exiting.")
        exit(1)

    def checkBuildUser(self):
        '''Checks if the build user has UID of 0
        
        @author: Roy Nielsen, Eric Ball


        :returns: Tuple containing the current user's login name and UID

        '''
        # This method is called before ramdisk creation, so it does not use the
        # try/except block that most methods do
        print("Starting checkBuildUser...")

        CURRENT_USER = os.getlogin()

        RUNNING_ID = str(os.geteuid())
        print("UID: " + RUNNING_ID)

        if RUNNING_ID != "0":
            print(" ")
            print("****************************************")
            print("***** Current logged in user: " + CURRENT_USER)
            print("***** Please run with SUDO ")
            print("****************************************")
            print(" ")
            exit(1)
        else:
            print("***** Current logged in user: " + CURRENT_USER)

        print("checkBuildUser Finished...")
        return CURRENT_USER, RUNNING_ID

    def codeSign(self, username, password, sig='', verbose='', deep='', appName=''):
        '''For codesigning on the Mac.

        :param username: 
        :param password: 
        :param sig:  (Default value = '')
        :param verbose:  (Default value = '')
        :param deep:  (Default value = '')
        :param appName:  (Default value = '')
        :returns: s: True for success, False otherwise.

        '''
        success = False
        requirementMet = False
        if sig:
            #####
            # Make sure the keychain is unlocked
            userHome = self.manage_user.getUserHomeDir(username)
            loginKeychain = userHome + "/Library/Keychains/login.keychain"
            self.manage_keychain.setUser(username)
            self.manage_keychain.unlockKeychain(password, loginKeychain)

            if verbose:
                if re.match('^v+$', verbose) and len(verbose) <= 4:
                    verbose = '-' + verbose
                    requirementMet = True
                elif re.match('^-v+$', verbose) and len(verbose) <= 5:
                    requriementMet = True
                elif not verbose:
                    requirementMet = True
            cmd = []
            if requirementMet and deep is True and verbose:
                cmd = ['/usr/bin/codesign', verbose, '--deep', '-f', '-s', sig, "--keychain", loginKeychain, appName]
            elif requirementMet and not deep and verbose:
                cmd = ['/usr/bin/codesign', verbose, '-f', '-s', sig, "--keychain", loginKeychain,  appName]
            elif requirementMet and deep and not verbose:
                cmd = ['/usr/bin/codesign', '--deep', '-f', '-s', sig, "--keychain", loginKeychain,  appName]
            elif requirementMet and not deep and not verbose:
                cmd = ['/usr/bin/codesign', '-f', '-s', sig, "--keychain", loginKeychain,  appName]
            if cmd:
                output = Popen(cmd, stdout=PIPE, stderr=STDOUT).communicate()
                self.logger.log(lp.INFO, "Output from trying to codesign: " + str(output))
        return success

    def unlockKeychain(self, username, password):
        '''Unlock the appropriate keychain for signing purposes

        :param username: 
        :param password: 

        '''
        success = False
        userHome = self.manage_user.getUserHomeDir(username)
        loginKeychain = userHome + "/Library/Keychains/login.keychain"
        success = self.manage_keychain.setUser(username)
        success = self.manage_keychain.unlockKeychain(password, loginKeychain)
        self.logger.log(lp.DEBUG, "Unlock Keychain success: " + str(success))
        return success
