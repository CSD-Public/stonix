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
Created 02/23/2015

Library of functions used to build Mac applications
@author: Eric Ball
@change: 2015/03/06 eball - Original implementation
@change: 2015/08/05 eball - Beautification, improving PEP8 compliance
@change: 2015/08/06 eball - Removed static paths from getpyuicpath()
@change: 2018/03/21 rsn - Added specific build path for importing PyInstaller
'''

import re
import os
import sys
import pwd
import site
import tarfile
import zipfile
import traceback
import plistlib as pl
from glob import glob
from subprocess import Popen, STDOUT, PIPE

#####
# Hard coded to pre-defined build tool site for
# buildingBuildToolsCommands-rev5.txt
site.addsitedir('/opt/tools/Library/Python/2.7/site-packages')
from PyInstaller.building import makespec, build_main

sys.path.append('./ramdisk')
from ramdisk.lib.loggers import LogPriority as lp
from ramdisk.lib.manage_user.manage_user import ManageUser
from ramdisk.lib.manage_keychain.manage_keychain import ManageKeychain
from ramdisk.lib.run_commands import RunWith


class BadBuildError(BaseException):
    '''Custom Exception'''
    def __init__(self, *args, **kwargs):
        BaseException.__init__(self, *args, **kwargs)

class MacBuildLib(object):
    def __init__(self, logger, pypaths=None):
        self.pypaths = pypaths
        self.logger = logger
        self.rw = RunWith(logger)
        self.manage_user = ManageUser(logger)
        self.manage_keychain = ManageKeychain(logger)

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
                       icon_file=None, pathex=[], specpath=None,
                       hiddenImports=[], hookspath='', runtime_hooks=[],
                       bundle_identifier='gov.lanl.stonix'):
        '''An interface for direct access to PyInstaller's makespec function
        
        @author: Eric Ball

        :param scripts: A list of python scripts to make a specfile for
        :param noupx: Do not use UPX even if it is available (Default value = False)
        :param strip: Apply a symbol-table strip to the executable and shared libs (Default value = False)
        :param console: Open a console window for standard i/o (Default value = True)
        :param icon_file: icon to be used for the completed program (Default value = None)
        :param pathex: A path to search for imports (like using PYTHONPATH) (Default value = [])
        :param specpath: Folder to store the generated spec file (default: CWD)
        :param hiddenImports:  (Default value = [])
        :param hookspath:  (Default value = '')
        :param runtime_hooks:  (Default value = [])
        :param bundle_identifier:  (Default value = 'gov.lanl.stonix')
        :returns: Output of PyInstaller.makespec
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
                                     bundle_identifier=bundle_identifier,
                                     excludes=["PyQt4"])
            else:
                return makespec.main(scripts, noupx=noupx, strip=strip,
                                     console=console, icon_file=icon_file,
                                     pathex=pathex, hiddenimports=hiddenImports,
                                     runtime_hooks=runtime_hooks,
                                     bundle_identifier=bundle_identifier,
                                     excludes=["PyQt4"])
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
            kwargs = {'workpath': workpath, 
                      'loglevel': 'INFO', 
                      'distpath': distpath,
                      'upx_dir': None,
                      'clean_build': clean_build}
        except Exception:
            raise

        return build_main.main(None, specfile, noconfirm, False, **kwargs)

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

    def changeViewControllerTitle(self, titleString=""):
        '''Change the window title string in the ViewController.swift file

        :param titleString:  (Default value = "")

        '''
        success = False
        try:
            with open("stonix4mac/stonix4mac/ViewController.swift") as viewController:
                fileContent = viewController.readlines()
                viewController.close()
            newFileContent = []
            for line in fileContent:
                if re.search("self\.view\.window\?\.title", line):
                    line = re.sub("\s+self\.view\.window\?\.title\s*=\s*.*$", "        self.view.window?.title = \"" + str(titleString) + "\"", line)
                    self.logger.log(lp.DEBUG, "Wrote title to line: \"" + str(line) + "\"")
                newFileContent.append(line)

            with open("stonix4mac/stonix4mac/ViewController.swift", "w") as viewController:
                for line in newFileContent:
                    viewController.write(line)
                viewController.close()
        except Exception as err:
            message = "error attempting to fix title..." + traceback.format_exc()
            self.logger.log(lp.DEBUG, message)

    def getHiddenImports(self, buildRoot='', treeRoot=''):
        '''Acquire a list of all '*.py' files in the stonix_resources directory,
        replace '/' with '.' for a module name that can be imported.

        :param buildRoot:  (Default value = '')
        :param treeRoot:  (Default value = '')

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
        '''Attempt to find PyQt5
        
        @author: Eric Ball


        :returns: Path to PyQt5 executable pyuic5

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

    def codeSignTarget(self, parentDirOfItemToSign, username, password, sig='', verbose='', deep='', itemName='', keychain=''):
        '''For codesigning on the Mac.

        :param parentDirOfItemToSign: 
        :param username: 
        :param password: 
        :param sig:  (Default value = '')
        :param verbose:  (Default value = '')
        :param deep:  (Default value = '')
        :param itemName:  (Default value = '')
        :param keychain:  (Default value = '')
        :returns: s: True for success, False otherwise.

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
                signingKeychain = userHome + "/Library/Keychains/login.keychain"
            else:
                signingKeychain = keychain

            #####
            # Make sure the keychain is unlocked
            #self.manage_keychain.setUser(username)
            #self.manage_keychain.unlockKeychain(password, keychain)

            #####
            # Build the codesign command
            cmd = ['/usr/bin/codesign']
            options = []
            if verbose:
                cmd += ['-' + verbose]
            if deep:
                cmd += ['--deep']
            # '--options=runtime' may be required for notarization, but currently breaks the build for MacOS 10.14 Mojave
            cmd += ['--force', '--timestamp', '--sign', sig, '--keychain', signingKeychain, itemName]
            self.logger.log(lp.DEBUG, "================================================================================")
            self.logger.log(lp.DEBUG, "CWD: " + str(os.getcwd()))
            self.logger.log(lp.DEBUG, "Command: " + str(cmd))
            self.logger.log(lp.DEBUG, "================================================================================")
            self.rw.setCommand(cmd)

            #####
            # Check the UID and run the command appropriately
            output, error, retcode = self.rw.waitNpassThruStdout()

            #####
            # Return to the working directory
            os.chdir(returnDir)

            self.logger.log(lp.INFO, "Output from trying to codesign: " + str(output))

        return success

    def productSignTarget(self, parentDirOfItemToSign, username, password, sig='', itemName='', newPkgName='', keychain=''):
        '''For codesigning on the Mac.

        :param parentDirOfItemToSign: 
        :param username: 
        :param password: 
        :param sig:  (Default value = '')
        :param itemName:  (Default value = '')
        :param newPkgName:  (Default value = '')
        :param keychain:  (Default value = '')
        :returns: s: True for success, False otherwise.

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
                signingKeychain = userHome + "/Library/Keychains/login.keychain"
            else:
                signingKeychain = keychain

            #####
            # Make sure the keychain is unlocked
            #self.manage_keychain.setUser(username)
            #self.manage_keychain.unlockKeychain(password, keychain)

            #####
            # Build the codesign command
            cmd = ['/usr/bin/productsign']
            cmd += ['--timestamp', '--sign', sig, '--keychain', signingKeychain, itemName, newPkgName]
            self.logger.log(lp.DEBUG, "================================================================================")
            self.logger.log(lp.DEBUG, "CWD: " + str(os.getcwd()))
            self.logger.log(lp.DEBUG, "Command: " + str(cmd))
            self.logger.log(lp.DEBUG, "================================================================================")
            self.rw.setCommand(cmd)

            #####
            # Check the UID and run the command appropriately
            output, error, retcode = self.rw.waitNpassThruStdout()

            #####
            # Return to the working directory
            os.chdir(returnDir)

            self.logger.log(lp.INFO, "Output from trying to productsign: " + str(output))

        return success

    def unlockKeychain(self, username, password, keychain=''):
        '''Unlock the appropriate keychain for signing purposes

        :param username: 
        :param password: 
        :param keychain:  (Default value = '')

        '''
        success = False
        if not username or not password:
            return success
        elif not keychain:
            userHome = self.manage_user.getUserHomeDir(username)
            keychain = userHome + "/Library/Keychains/login.keychain"
        success = self.manage_keychain.setUser(username)
        success = self.manage_keychain.unlockKeychain(password, keychain)
        self.logger.log(lp.DEBUG, "Unlock Keychain success: " + str(success))
        return success

    def setUpForSigning(self, username='', password='', keychain=''):
        '''Make sure there signing is set up such that xcodebuild can find the
        cert required for signing.
        
        @author: Roy Nielsen

        :param username:  (Default value = '')
        :param password:  (Default value = '')
        :param keychain:  (Default value = '')

        '''
        success = False
        output = ''
        loginKeychain = False
        self.logger.log(lp.DEBUG, keychain)

        if not username or not password:
            return success
        if not keychain:
            userHome = self.manage_user.getUserHomeDir(username)
            keychain = userHome + "/Library/Keychains/login.keychain"
            loginKeychain = True

        self.logger.log(lp.DEBUG, keychain)

        self.manage_keychain.setUser(username.strip())
        try:
            #####
            # Unlock the keychain so we can sign
            success, output = self.manage_keychain.unlockKeychain(password, keychain=keychain)
        except Exception as err:
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

        print('.')
        print('.')
        print('.')
        print(str(cmd))
        print('.')
        print('.')
        print('.')
        
        os.chdir(buildDir)
        self.logger.log(lp.DEBUG, str(cmd))
        
        self.rw.setCommand(cmd)
        output, error, retcode = self.rw.waitNpassThruStdout()
        
        if not error:
            success = True
        else:
            success = False
        #     raise BadBuildError("Error building program: " + str(retcode))
        
        for line in output.split("\n"):
            self.logger.log(lp.DEBUG, str(line))
        for line in error.split("\n"):
            self.logger.log(lp.DEBUG, str(line))

        print("Done building stonix4mac...")

        #####
        # Return to the working directory
        os.chdir(returnDir)

        return success

    def buildPackageInit(self, builderScpt="", rulesLocation=''):
        '''Create an init for a package that contains basic imports for all of the
        files in the package.  Written to support including normally dynamically
        loaded modules in a frozen python module.
        
        @author: Roy Nielsen

        :param builderScpt:  (Default value = "")
        :param rulesLocation:  (Default value = '')

        '''
        try:
            cmd = [builderScpt, "-d", "-r", rulesLocation]
            stdout, stderr = Popen(cmd, stdout=PIPE, stderr=PIPE).communicate()
        except Exception as err:
            trace = traceback.format_exc()
            self.logger.log(lp.DEBUG, str(trace))
            raise err
        self.logger.log(lp.DEBUG, "\\\\\\\\\"")
        self.logger.log(lp.DEBUG, "stdout: " + str(stdout))
        self.logger.log(lp.DEBUG, "stderr: " + str(stderr))
        self.logger.log(lp.DEBUG, "///////")

    def writeInit(self, pathToDir):
        '''Create an __init__.py file, based on all the files in that directory

        :param pathToDir: 
        :returns: success - whether or not this process was a success
        
        @author: Roy Nielsen

        '''
        success = False

        header = ''''''

        if self.isSaneFilePath(pathToDir):
            rulesList = []
        
            allFilesList = os.listdir(pathToDir)
        
            for rule in allFilesList:
                if re.search("\.py$", rule) and not re.match("__init__\.py", rule):
                    ruleClass = re.sub("\.py$", "", rule)
                    rulesList.append(ruleClass)
        
            try:
                initPath = os.path.join(pathToDir, "__init__.py")
                self.logger.log(lp.DEBUG, "initPath: " + str(initPath))
                fp = open(initPath, 'w')
                fp.write(header)
                for rule in rulesList:
                    fp.write("import " + rule + "\n")
                fp.write("\n")
            except OSError as err:
                trace = traceback.format_exc() 
                self.logger.log(lp.DEBUG, "Traceback: " + trace)
                raise err
            else:
                success = True
                self.logger.log(lp.DEBUG, "Done writing init.")
            finally:
                try:
                    fp.close()
                except:
                    pass

        return success

    def isSaneFilePath(self, filepath):
        '''Check for a good file path in the passed in string.
        
        @author: Roy Nielsen

        :param filepath: 

        '''
        sane = False
        if isinstance(filepath, str):
            if re.match("^[A-Za-z/][A-Za-z0-9\.\-_/]*", filepath):
                sane = True
        return sane

