"""
Implementation class for the individual ManageKeychain for MacOS

@author: Roy Nielsen
"""
from __future__ import absolute_import

import os
import re
########## 
# local app libraries
from ..run_commands import RunWith
from ..loggers import CyLogger
from ..loggers import LogPriority as lp
from ..manage_user.macos_user import MacOSUser
from .manage_keychain_template import ManageKeychainTemplate

class UnsupportedSecuritySubcommand(Exception):
    """
    Meant for being thrown when a command does not support a passed in subcommand.

    @author: Roy Nielsen
    """
    def __init__(self, *args, **kwargs):
        Exception.__init__(self, *args, **kwargs)


class MacOSKeychain(MacOSUser, ManageKeychainTemplate):
    """
    """
    def __init__(self, **kwargs):
        """
        Initialization Method
        
        @author: Roy Nielsen
        """
        if 'logDispatcher' not in kwargs:
            raise ValueError("Variable 'logDispatcher' a required parameter for " + str(self.__class__.__name__))
        super(MacOSKeychain, self).__init__(**kwargs)
        #self.logger = CyLogger(debug_mode=True)
        #self.logger.initializeLogs(logdir="/tmp", filename="kch", extension_type="none", myconsole=True)
        
        self.mgr = "/usr/bin/security"
        self.userName = ""
        self.runWith = RunWith(self.logger)

    #----------------------------------------------------------------------
    # helper methods
    #----------------------------------------------------------------------

    def validateSecurityCommand(self, command={}):
        """
        Validate that we have a properly formatted command, and the subcommand
        is valid.
        
        @param: the commandDict should be in the format below:
        
        cmd = { "set-keychain-password" : [oldPass, newPass, "'" + keychain + "'"] }
        
        where the key is the security 'subcommand' and the list is an ordered
        list of the arguments to give the subcommand.
        
        @returns: success - whether the command was successfull or not.
        
        @author: Roy Nielsen
        """
        success = False
        subcmd = []
        if not isinstance(command, dict):
            self.logger.log(lp.ERROR, "Command must be a dictionary...")
        else:
            #self.logger.log(lp.DEBUG, "cmd: " + str(command))
            commands = 0
            for subCommand, args in command.iteritems():
                commands += 1
                #####
                # Check to make sure only one command is in the dictionary
                if commands > 1:
                    self.logger.log(lp.ERROR, "Damn it Jim! One command at a time!!")
                    success = False
                    break
                #####
                # Check if the subcommand is a valid subcommand...
                validSubcommands = ["set-keychain-password",
                                    "unlock-keychain",
                                    "lock-keychain",
                                    "delete-keychain",
                                    "create-keychain"]
                if subCommand not in validSubcommands:
                    success = False
                    self.logger.log(lp.DEBUG, "subCommand: " + str(subCommand))
                    break
                #####
                # Check to make sure the key or subCommand is a string, and the value is
                # alist and args are
                if not isinstance(subCommand, basestring) or not isinstance(args, list):
                    self.logger.log(lp.ERROR, "subcommand needs to be a string, and args needs to be a list of strings")
                    success = False
                else:
                    #####
                    # Check the arguments to make sure they are all strings
                    success = True
                    for arg in args:
                        if not isinstance(arg, basestring):
                            self.logger.log(lp.ERROR, "Arg '" + str(arg) + "'needs to be a string...")
                            success = False
                            break
                    if success:
                        subcmd = [subCommand] + args
        return success, subcmd

    #-------------------------------------------------------------------------

    def runSecurityCommand(self, commandDict={}):
        """
        Use the passed in dictionary to create a MacOS 'security' command
        and execute it.
        
        @param: the commandDict should be in the format below:
        
        cmd = { "set-keychain-password" : [oldPass, newPass, "'" + keychain + "'"] }
        
        where the key is the security 'subcommand' and the list is an ordered
        list of the arguments to give the subcommand.
        
        @returns: success - whether the command was successfull or not.
        
        @author: Roy Nielsen
        """
        success = False
        output = ""
        error = ""
        returncode = ""
        uid = os.getuid()
        #####
        # Make sure the command dictionary was properly formed, as well as
        # returning the formatted subcommand list
        validationSuccess, subCmd = self.validateSecurityCommand(commandDict)
        #self.logger.log(lp.DEBUG, "validationSuccess: " + str(validationSuccess))
        #self.logger.log(lp.DEBUG, "subCmd: " + str(subCmd))
        if validationSuccess:
            #self.logger.log(lp.DEBUG, "cmdDict: " + str(commandDict))
            #####
            # Command setup - note that the keychain deliberately has quotes
            # around it - there could be spaces in the path to the keychain,
            # so the quotes are required to fully resolve the file path.  
            # Note: this is done in the build of the command, rather than 
            # the build of the variable.
            cmd = [self.mgr] + subCmd
            #####
            # set up the command
            self.runWith.setCommand(cmd)
            
            if re.match("^0$", str(uid)):
                #####
                # Run the command, lift down...
                output, error, retcode = self.runWith.liftDown(self.userName)
                self.logger.log(lp.ERROR, "Took the lift down...")
                if not str(error).strip():
                    success = True
            else:
                #####
                # Run the command
                output, error, retcode = self.runWith.communicate()
                self.logger.log(lp.INFO, "DSCL cmd ran in current context..")
                
                if not str(error).strip():
                    success = True

            passfound = False
            for arg in cmd:
                if re.match('password', arg):
                    passfound = True
                    break

            if not '-p' in cmd and not passfound:
                self.logger.log(lp.DEBUG, "Output: " + str(output))
                self.logger.log(lp.DEBUG, "Error: " + str(error))
                self.logger.log(lp.DEBUG, "Return code: " + str(returncode))

        return success, str(output), str(error), str(returncode)

    #----------------------------------------------------------------------

    def setUser(self, user=""):
        """
        Setter for the class user variable..
        
        @author: Roy Nielsen
        """
        success = False
        if self.isSaneUserName(user):
            self.userName = user
            success = True
        return success

    #----------------------------------------------------------------------
    # Subcommands
    #----------------------------------------------------------------------

    def lockKeychain(self, keychain="", all=False):
        """
        Lock the defined keychain

        @parameter: keychain - full path to the keychain to unlock

        @note: 
        security unlock-keychain -p <passwd>

        @author: Roy Nielsen
        """
        success = False
        keychain = keychain.strip()
        #####
        # Input validation for the file keychain.
        if self.isSaneFilePath(keychain):
            #####
            # Command setup - note that the keychain deliberately has quotes
            # around it - there could be spaces in the path to the keychain,
            # so the quotes are required to fully resolve the file path.  
            # Note: this is done in the build of the command, rather than 
            # the build of the variable.
            if all:
                cmd = { "unlock-keychain" : ["-a", keychain] }
            else:
                cmd = { "unlock-keychain" : [keychain] }
            success, stdout, stderr, retcode = self.runSecurityCommand(cmd)

        return success

    #-------------------------------------------------------------------------

    def unlockKeychain(self, passwd="", keychain=""):
        """
        Unlock the defined keychain

        @parameter: passwd - password for the keychain to unlock

        @parameter: keychain - full path to the keychain to unlock

        @note: 
        security unlock-keychain -p <passwd>

        @author: Roy Nielsen
        """
        success = False
        keychain = keychain.strip()
        passwd = passwd.strip()
        #####
        # Input validation for the file keychain.
        if self.isSaneFilePath(keychain) and isinstance(passwd, basestring):
            #####
            # Command setup - note that the keychain deliberately has quotes
            # around it - there could be spaces in the path to the keychain,
            # so the quotes are required to fully resolve the file path.  
            # Note: this is done in the build of the command, rather than 
            # the build of the variable.
            cmd = { "unlock-keychain" : ["-p", passwd, keychain] }
            success, stdout, stderr, retcode = self.runSecurityCommand(cmd)

        return success

    #-------------------------------------------------------------------------

    def changeKeychainPassword(self, user="",
                                     oldPass=False,
                                     newPass=False,
                                     keychain=False):
        """
        Use the "security" command to set the login keychain.  If it has not
        been created, create the login keychain.

        use the following command on the Mac:
        security set-keychain-password -o <oldpassword> -p <newpassword> <file.keychain>

        Most used keychain is the login.keychain.

        @author: Roy Nielsen
        """
        success = False
        user = user.strip()
        oldPass = oldPass.strip()
        newPass = newPass.strip()
        keychain = keychain.strip()

        #####
        # Input validation for the username, and check the passwords to make
        # sure they are valid strings.  Check for the existence of the keychain
        if self.isSaneUserName(user) and \
           isinstance(oldPass, basestring) and \
           isinstance(newPass, basestring) and \
           self.isSaneFilePath(keychain):
            if os.path.isfile(self.getUserHomeDir(user)):
                #####
                # if a keychain isn't passed in use the user's login keychain.
                if not keychain:
                    loginKeychain = self.getUserHomeDir(user) + \
                                   "/Library/Keychains/login.keychain"
            #####
            # Command setup - note that the keychain deliberately has quotes
            # around it - there could be spaces in the path to the keychain,
            # so the quotes are required to fully resolve the file path.  
            # Note: this is done in the build of the command, rather than 
            # the build of the variable.
            cmd = { "change-keychain-password" : ["-o", oldPass, "-p", newPass,
                                                  keychain] }
            self.logger.log(lp.DEBUG, "cmd: " + str(cmd))
            success, stdout, stderr, retcode = self.runSecurityCommand(cmd)
            self.logger.log(lp.DEBUG, "stdout: " + str(stdout))
            self.logger.log(lp.DEBUG, "stderr: " + str(stderr))
            self.logger.log(lp.DEBUG, "retcode: " + str(retcode))

        return success

    #-------------------------------------------------------------------------

    def deleteKeychain(self, keychain="", *args, **kwargs):
        """
        Delete keychain
        
        @param: keychain - full path to keychain to delete, it will be removed
                           from the index as well as deleted from the 
                           filesystem.
        
        @note: the command is:

        security delete-keychain <file.keychain>

        The <file.keychain> must be the full path to the keychain.
        
        @author: Roy Nielsen
        """
        success = False
        keychain = keychain.strip()
        #####
        # Input validation for the file keychain.
        if self.isSaneFilePath(keychain) and os.path.exists(keychain):
            #####
            # Command setup - note that the keychain deliberately has quotes
            # around it - there could be spaces in the path to the keychain,
            # so the quotes are required to fully resolve the file path.  
            # Note: this is done in the build of the command, rather than 
            # the build of the variable.
            cmd = { "delete-keychain" : [keychain] }
            success, stdout, stderr, retcode = self.runSecurityCommand(cmd)

        return success

    #-------------------------------------------------------------------------

    def createKeychain(self, passwd="", keychain="", *args, **kwargs):
        """
        Create a keychain.
        
        @author: Roy Nielsen
        """
        success = False
        passwd = passwd.strip()
        keychain = keychain.strip()
        #####
        # Input validation for the file keychain.
        if self.isSaneFilePath(keychain) and isinstance(passwd, basestring):
            #####
            # Command setup - note that the keychain deliberately has quotes
            # around it - there could be spaces in the path to the keychain,
            # so the quotes are required to fully resolve the file path.  
            # Note: this is done in the build of the command, rather than 
            # the build of the variable.
            cmd = { "create-keychain" : ["-p", passwd, keychain] }
            success, stdout, stderr, retcode = self.runSecurityCommand(cmd)

        return success
