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
import pwd
import tarfile
import zipfile
import traceback
import plistlib as pl
from glob import glob
from subprocess import Popen, STDOUT, PIPE

sys.path.append("/usr/local/lib/python2.7/site-packages/PyInstaller.egg")

from PyInstaller.building import makespec, build_main

sys.path.append('./ramdisk')

from ramdisk.lib.loggers import LogPriority as lp
from ramdisk.lib.manage_user.manage_user import ManageUser
from ramdisk.lib.manage_keychain.manage_keychain import ManageKeychain
from ramdisk.lib.run_commands import RunWith


class MacBuildLib(object):
    def __init__(self, logger, pypaths=None):
        self.pypaths = pypaths
        self.logger = logger
        self.rw = RunWith(logger)
        self.manage_user = ManageUser(self.logger)
        self.manage_keychain = ManageKeychain(self.logger)

    def regexReplace(self, filename, findPattern, replacePattern, outputFile="",
                     backupname=""):
        '''
        Find and replace text in a file using regular expression patterns.

        @author: Eric Ball
        @param filename: name of origin file
        @param findPattern: string containing the regex to find in the file
        @param replacePattern: string containing the text to replace the
                               findPattern with
        @param outputFile: name of file to output new text to. If not supplied,
                           output will be written back to the origin file
        @param backupname: optional name of backup for origin file
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
        '''
        A quick and easy method to create a .tar.gz out of a single file or folder
        '''
        try:
            with tarfile.open(dest, "w:gz") as tar:
                tar.add(source)
        except Exception:
            raise

    def makeZip(self, source, dest):
        '''
        A quick and easy method to create a .zip out of a single file or folder
        '''
        try:
            with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as myzip:
                myzip.write(source)
        except Exception:
            raise

    def pyinstMakespec(self, scripts, noupx=False, strip=False, console=True,
                       icon_file=None, pathex=[], specpath=None,
                       hiddenImports=[], hookspath='', runtime_hooks=[],
                       bundle_identifier='gov.lanl.stonix'):
        '''
        An interface for direct access to PyInstaller's makespec function

        @author: Eric Ball
        @param scripts: A list of python scripts to make a specfile for
        @param noupx: Do not use UPX even if it is available
        @param strip: Apply a symbol-table strip to the executable and shared libs
        @param console: Open a console window for standard i/o
        @param icon_file: icon to be used for the completed program
        @param pathex: A path to search for imports (like using PYTHONPATH)
        @param specpath: Folder to store the generated spec file (default: CWD)
        @return: Output of PyInstaller.makespec
        @note: PyInstaller.makespec accepts further options,
               which may need to be added in future versions

            makespec.main(scripts, name=None, onefile=None,
                         console=True, debug=False, strip=False, noupx=False,
                         pathex=None, version_file=None, specpath=None,
                         datas=None, binaries=None, icon_file=None, manifest=None,
                         resources=None, bundle_identifier=None,
                         hiddenimports=None, hookspath=None, key=None, runtime_hooks=None,
                         excludes=None, uac_admin=False, uac_uiaccess=False,
                         win_no_prefer_redirects=False, win_private_assemblies=False,
                         **kwargs):

        '''
        # specpath default cannot be reliably set here; os.getcwd() will return dir
        # of macbuildlib, not necessarily the current working dir of the calling
        # script. Therefore, if it is not specified, leave blank and let
        # PyInstaller set default.
        try:
            if specpath:
                return makespec.main(scripts, noupx=noupx, strip=strip,
                                     console=console, icon_file=icon_file,
                                     pathex=pathex, specpath=specpath, 
                                     hiddenmports=hiddenImports,
                                     runtime_hooks=runtime_hooks,
                                     bundle_identifier=bundle_identifier)
            else:
                return makespec.main(scripts, noupx=noupx, strip=strip,
                                     console=console, icon_file=icon_file,
                                     pathex=pathex, hiddenimports=hiddenImports,
                                     runtime_hooks=runtime_hooks,
                                     bundle_identifier=bundle_identifier)
        except Exception:
            raise

    def pyinstBuild(self, specfile, workpath, distpath, clean_build=False,
                    noconfirm=False):
        '''
        An interface for direct access to PyInstaller's build function

        @author: Eric Ball
        @param specfile: The specfile to be built
        @param workpath: Where to put all the temporary work files
        @param distpath: Where to put the bundled app
        @param clean_build: Clean PyInstaller cache and remove temporary files
                            before building
        @param noconfirm: Replace output directory without asking for confirmation
        @return: Output of PyInstaller.build
        @note: PyInstaller.build accepts further options,
               which may need to be added in future versions

        '''
        try:
            kwargs = {'workpath': workpath, 
                      'loglevel': 'INFO', 
                      'distpath': distpath,
                      'upx_dir': None,
                      'clean_build': clean_build}
        except Exception:
            raise

        return build_main.main(None, specfile, noconfirm, False, **kwargs)

    def chownR(self, user, target):
        '''Recursively apply chown to a directory'''
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
            print "Error: Cannot chownR, target must be a directory"
            raise
        except Exception:
            raise

    def chmodR(self, perm, target, writemode):
        '''
        Recursively apply chmod to a directory

        @author: Eric Ball
        @param perm: Permissions to be applied. For information on available
                     permissions/modes, see os.chmod documentation at
                     https://docs.python.org/2/library/os.html#os.chmod
        @param target: Target directory
        @param writemode: [a]ppend or [o]verwrite
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
            print "Error: Cannot chmodR target, must be a directory"
            raise
        except NameError:
            print "Error: Invalid writemode specified. Please use [a]ppend " + \
                "or [o]verwrite"
            raise
        except Exception:
            raise

    def modplist(self, targetFile, targetKey, newValue):
        '''
        Modify the value of a particular key in a Mac OS X property list file

        @author: Eric Ball
        @param targetFile: Path to the plist to be modified
        @param targetKey: The particular key within the plist to be modified
        @param newValue: The new value for the targetKey within the targetFile
        '''
        try:
            mypl = pl.readPlist(targetFile)
            mypl[targetKey] = newValue
            pl.writePlist(mypl, targetFile)
        except Exception:
            raise

    def getHiddenImports(self, buildRoot='', treeRoot=''):
        '''
        Acquire a list of all '*.py' files in the stonix_resources directory,
        replace '/' with '.' for a module name that can be imported. 

        @param: buildroot

        @author: Roy Nielsen
        '''
        try:

            returnDir = os.getcwd()
            os.chdir(buildRoot)
            hiddenimports = []
            for root, dirs, files in os.walk(treeRoot):
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
                        self.logger.log(lp.DEBUG, "Attepting import of: " + \
                                        hiddenimportfile)
                        hiddenimports.append(hiddenimportfile)
                
        except OSError:
            self.logger.log(lp.DEBUG, "Error trying to acquire python files...")
        finally:
            os.chdir(returnDir)
        
        return hiddenimports
        
    def getpyuicpath(self):
        '''
        Attempt to find PyQt5

        @author: Eric Ball
        @return: Path to PyQt5 executable pyuic5
        '''
        return "/opt/tools/bin/pyuic5"
        '''
        # This method is called before ramdisk creation, so it does not use the
        # try/except block that most methods do
        fwpath = "/Users/Shared/Frameworks/"
        pathend1 = "/pyuic/pyuic5"
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
        print "PyQt4 path not found. Exiting."
        exit(1)
        '''

    def checkBuildUser(self):
        '''
        Checks if the build user has UID of 0

        @author: Roy Nielsen, Eric Ball
        @return: Tuple containing the current user's login name and UID
        '''
        # This method is called before ramdisk creation, so it does not use the
        # try/except block that most methods do
        print "Starting checkBuildUser..."

        CURRENT_USER = os.getlogin()

        RUNNING_ID = str(os.geteuid())
        print "UID: " + RUNNING_ID

        if RUNNING_ID != "0":
            print " "
            print "****************************************"
            print "***** Current logged in user: " + CURRENT_USER
            print "***** Please run with SUDO "
            print "****************************************"
            print " "
            exit(1)
        else:
            print "***** Current logged in user: " + CURRENT_USER

        print "checkBuildUser Finished..."
        return CURRENT_USER, RUNNING_ID

    def codeSign(self, parentDirOfItemToSign, username, password, sig='', verbose='', deep='', itemName='', keychain=''):
        '''
        For codesigning on the Mac.
        
        @param: Signature to sign with (string)
        @param: How verbose to be: 'v', 'vv', 'vvv' or 'vvvv' (string)
        @param: Whether or not to do a 'deep' codesign or not. (bool)
        @param: App name (ending in .app)

        @returns: True for success, False otherwise.
        '''
        success = False
        requirementMet = False
        returncode = ""

        if os.path.isdir(parentDirOfItemToSign) and sig:
            #####
            # Get the directory we need to return to after signing is complete
            returnDir = os.getcwd()
            #####
            # Change to directory where the item to sign resides
            os.chdir(parentDirOfItemToSign)
            
            #####
            # if the keychain to sign with is empty, default to the login
            # keychain of the username passed in.
            if not keychain:
                userHome = self.manage_user.getUserHomeDir(username)
                signingKeychain = userHome + "/Library/Keychains/login.keychain-db"
            else:
                signingKeychain = keychain

            self.logger.log(lp.DEBUG, "keychain: " + str(keychain))
            #####
            # Make sure the keychain is unlocked
            self.manage_keychain.setUser(username)
            self.manage_keychain.unlockKeychain(password, keychain)
            self.logger.log(lp.DEBUG, "Keychain unlocked...")
            #####
            # Build the codesign command
            cmd = ['/usr/bin/codesign']
            options = []
            if verbose:
                re.sub("\s+", "", verbose)
                cmd += ['-' + verbose.rstrip()]
            if deep:
                cmd += ['--deep']
            cmd += ['-f', '-s', "\\'" + sig + "\\'", '--keychain', signingKeychain, parentDirOfItemToSign + "/" + itemName]
            self.logger.log(lp.DEBUG, "cmd: " + str(cmd))
            self.rw.setCommand(cmd)

            #####
            # Check the UID and run the command appropriately
            output, error, retcode = self.rw.communicate()

            #####
            # Return to the working directory
            os.chdir(returnDir)

            self.logger.log(lp.INFO, "Output from trying to codesign: " + str(output))

        return success

    def unlockKeychain(self, username, password, keychain=''):
        '''
        Unlock the appropriate keychain for signing purposes

        @param: Username of the login.keychain-db to unlock
        @param: Password for the user

        @author: Roy Nielsen
        '''
        success = False
        if not username or not password:
            return success
        elif not keychain:
            userHome = self.manage_user.getUserHomeDir(username)
            keychain = userHome + "/Library/Keychains/login.keychain-db"
        success = self.manage_keychain.setUser(username)
        success = self.manage_keychain.unlockKeychain(password, keychain)
        self.logger.log(lp.DEBUG, "Unlock Keychain success: " + str(success))
        return success

    def setUpForSigning(self, username='', password='', keychain=''):
        '''
        Make sure there signing is set up such that xcodebuild can find the
        cert required for signing.

        @author: Roy Nielsen
        '''
        success = False
        output = ''
        loginKeychain = False
        self.logger.log(lp.DEBUG, keychain)

        if not username or not password:
            return success
        if not keychain:
            userHome = self.manage_user.getUserHomeDir(username)
            keychain = userHome + "/Library/Keychains/login.keychain-db"
            loginKeychain = True

        self.logger.log(lp.DEBUG, keychain)

        self.manage_keychain.setUser(username.strip())
        try:
            #####
            # Unlock the keychain so we can sign
            success, output = self.manage_keychain.unlockKeychain(password, keychain=keychain)
        except Exception, err:
            self.logger.log(lp.DEBUG, traceback.format_exc())
            raise err
        return success
        '''
        #####
        # Check open keychain search list first
        success, output = self.manage_keychain.findIdentity(policy='codesigning')
        
        if not success:
            #####
            # Check the specific keychain for the cert
            success, output = self.manage_keychain.findIdentity(policy='codesigning', keychain=keychain)
            
            if not success:
                #####
                # Acquire the login keychain and look in there, if not already
                # done.
                success, output = self.manage_keychain.loginKeychain()
                
                if not re.match("^%s$"%output.strip(), keychain) or not success:
                    #####
                    # If the keychain we already processed is the keychain,
                    # return a failure.
                    return success
                else:
                    #####
                    # Set the keychain to be the login keychain
                    loginKeychain = True
                    keychain = output.strip()
                    #####
                    # Check the login keychain for the cert
                    success, output = self.manage_keychain.findIdentity(policy='codesigning', keychain=keychain)
            
            #####
            # Set the keychain to be in the signing search list
            success, output = self.manage_keychain.listKeychains(setList=True, keychain=keychain)
            
            #####
            # Set the keychain to be in the default keychain
            success, output = self.manage_keychain.defaultKeychain(setList=True, keychain=keychain)
            
        if success:
            #####
            # Unlock the keychain so we can sign
            success, output = self.manage_keychain.unlockKeychain(keychainPass, keychain=keychain)

        return success
        '''
    def buildWrapper(self, username, appName, buildDir, keychain=False):
        success = False
        error = ""
        
        if not os.path.isdir(buildDir):
            return success
        #####
        # Get the directory we need to return to after signing is complete
        returnDir = os.getcwd()
        #####
        # Change to directory where the item to sign resides
        os.chdir(buildDir)
        cfds = False
        os.environ['DEVELOPER_DIR'] = '/Applications/Xcode.app/Contents/Developer'
        if not keychain:
            cmd = ['/usr/bin/xcodebuild', 'clean', 'build', 'CODE_SIGN_IDENTITY=""',
                   'CODE_SIGNING_REQUIRED=NO', 'CODE_SIGN_ENTITLEMENTS=""', 'CODE_SIGNING_ALLOWED="NO"',
                   '-sdk', 'macosx', '-project', appName + '.xcodeproj']
            cfds = True
        else:
            targetKeychain = keychain
            cmd = ['/usr/bin/xcodebuild', 'CODE_SIGNING_ALLOWED="Yes"', 'CODE_SIGNING_REQUIRED=YES', '-sdk', 'macosx', '-project', appName + '.xcodeproj']
            cfds = False
            #####
            # Alternate commands for building with xcodebuild and signing
            #cmd = ['/usr/bin/xcodebuild', '-workspace', appPath + '/' + appName + '.xcodeproj' + "/" + appName + '.xcworkspace', '-scheme', appName, '-configuration', 'RELEASE', 'DEVELOPENT_TEAM', 'Los Alamos National Security, LLC', 'CODE_SIGN_IDENTITY', '"' + str(self.codesignSignature) + '"']
            # - works with waring: cmd = ['/usr/bin/xcodebuild', '-project', appName + '.xcodeproj', '-configuration', 'RELEASE', 'CODE_SIGN_IDENTITY="Mac Developer"']
            #cmd = ['/usr/bin/xcodebuild', '-sdk', 'macosx', '-project', buildDir + "/" + appName + '.xcodeproj', 'DEVELOPENT_TEAM="Los Alamos National Security, LLC"', 'OTHER_CODE_SIGN_FLAGS="-keychain ' + keychain + '"']
            #cmd = ['/usr/bin/xcodebuild', '-sdk', 'macosx', '-project', buildDir + "/src/Macbuild/" + appName + "/" + appName + '.xcodeproj', 'DEVELOPENT_TEAM="Los Alamos National Security, LLC"', "ALWAYS_EMBED_SWIFT_STANDARD_LIBRARIES='YES'"]
            #cmd = ['/usr/bin/xcodebuild', '-sdk', 'macosx', '-project', appName + '.xcodeproj', '-skipUnavailableActions']
            #cmd = ['/usr/bin/xcodebuild', '-configuration', 'Release', 'clean']

        self.logger.log(lp.DEBUG, ".")
        self.logger.log(lp.DEBUG, ".")
        self.logger.log(lp.DEBUG, ".")
        self.logger.log(lp.DEBUG, ".")
        self.logger.log(lp.DEBUG, "buildDir: " + str(buildDir))
        self.logger.log(lp.DEBUG, ".")
        self.logger.log(lp.DEBUG, ".")
        self.logger.log(lp.DEBUG, ".")
        self.logger.log(lp.DEBUG, ".")

        print '.'
        print '.'
        print '.'
        print str(cmd)
        print '.'
        print '.'
        print '.'
        
        os.chdir(buildDir)
        self.logger.log(lp.DEBUG, str(cmd))
        
        self.rw.setCommand(cmd, close_fds=cfds)
        output, error, retcode = self.rw.communicate()
        
        if not error:
            success = True
        
        for line in output.split("\n"):
            self.logger.log(lp.DEBUG, str(line))
        for line in error.split("\n"):
            self.logger.log(lp.DEBUG, str(line))

        print "Done building stonix4mac..."

        #####
        # Return to the working directory
        os.chdir(returnDir)

        return success

    def buildPackageInit(self, builderScpt="", pkgLocation=''):
        '''
        Create an init for a package that contains basic imports for all of the
        files in the package.  Written to support including normally dynamically
        loaded modules in a frozen python module.
        
        @author: Roy Nielsen
        '''
        try:
            cmd = [builderScpt, "-d", "-p", pkgLocation]
            stdout, stderr = Popen(cmd, stdout=PIPE, stderr=PIPE).communicate()
        except Exception, err:
            trace = traceback.format_exc()
            self.logger.log(lp.DEBUG, str(trace))
            raise err
        self.logger.log(lp.DEBUG, "\\\\\\\\\"")
        self.logger.log(lp.DEBUG, "stdout: " + str(stdout))
        self.logger.log(lp.DEBUG, "stderr: " + str(stderr))
        self.logger.log(lp.DEBUG, "///////")

