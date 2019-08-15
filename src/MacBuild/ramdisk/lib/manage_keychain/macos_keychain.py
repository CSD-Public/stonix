"""
Implementation class for the individual ManageKeychain for MacOS

@author: Roy Nielsen
"""


import os
import re
import pwd
##########
# local app libraries
from ..run_commands import RunWith
from ..loggers import CyLogger
from ..loggers import LogPriority as lp
from ..manage_user.macos_user import MacOSUser
from .manage_keychain_template import ManageKeychainTemplate

class UnsupportedSecuritySubcommand(Exception):
    '''Meant for being thrown when a command does not support a passed
    in subcommand.
    
    @author: Roy Nielsen


    '''
    def __init__(self, *args, **kwargs):
        Exception.__init__(self, *args, **kwargs)


class MacOSKeychain(MacOSUser, ManageKeychainTemplate):
    ''' '''
    def __init__(self, **kwargs):
        """
        Initialization Method

        @author: Roy Nielsen
        """
        if 'logDispatcher' not in kwargs:
            raise ValueError("Variable 'logDispatcher' a required parameter" +
                             " for " + str(self.__class__.__name__))
        super(MacOSKeychain, self).__init__(**kwargs)

        self.mgr = "/usr/bin/security"
        self.userName = ""
        self.runWith = RunWith(self.logger)

    # ----------------------------------------------------------------------
    # helper methods
    # ----------------------------------------------------------------------

    def validateSecurityCommand(self, command={}):
        '''Validate that we have a properly formatted command, and the subcommand
        is valid.

        :param command:  (Default value = {})
        :returns: s: success - whether the command was successfull or not.
        
        @author: Roy Nielsen

        '''
        success = False
        subcmd = []
        if not isinstance(command, dict):
            self.logger.log(lp.ERROR, "Command must be a dictionary...")
        else:
            # self.logger.log(lp.DEBUG, "cmd: " + str(command))
            commands = 0
            for subCommand, args in list(command.items()):
                commands += 1
                #####
                # Check to make sure only one command is in the dictionary
                if commands > 1:
                    self.logger.log(lp.ERROR, "Damn it Jim! One command " +
                                    "at a time!!")
                    success = False
                    break
                #####
                # Check if the subcommand is a valid subcommand...
                validSubcommands = ["list-keychains",
                                    "default-keychain",
                                    "login-keychain",
                                    "create-keychain",
                                    "delete-keychain",
                                    "lock-keychain",
                                    "unlock-keychain",
                                    "set-keychain-password",
                                    "show-keychain-info",
                                    "dump-keychain",
                                    "find-certificate",
                                    "find-identity",
                                    "error"]
                if subCommand not in validSubcommands:
                    success = False
                    self.logger.log(lp.DEBUG, "subCommand: " + str(subCommand))
                    break
                #####
                # Check to make sure the key or subCommand is a string, and
                # the value is alist and args are
                if not isinstance(subCommand, str) or \
                   not isinstance(args, list):
                    self.logger.log(lp.ERROR, "subcommand needs to be a " +
                                    "string, and args needs to be a list " +
                                    "of strings")
                    success = False
                else:
                    #####
                    # Check the arguments to make sure they are all strings
                    success = True
                    for arg in args:
                        if not isinstance(arg, str):
                            self.logger.log(lp.ERROR, "Arg '" + str(arg) +
                                            "'needs to be a string...")
                            success = False
                            break
                    if success:
                        subcmd = [subCommand] + args
        return success, subcmd

    # -------------------------------------------------------------------------

    def runSecurityCommand(self, commandDict={}):
        '''Use the passed in dictionary to create a MacOS 'security' command
        and execute it.

        :param commandDict:  (Default value = {})
        :returns: s: success - whether the command was successfull or not.
        
        @author: Roy Nielsen

        '''
        success = False
        output = ""
        error = ""
        returncode = ""
        # uid = os.getuid()

        #####
        # Make sure the command dictionary was properly formed, as well as
        # returning the formatted subcommand list
        validationSuccess, subCmd = self.validateSecurityCommand(commandDict)
        # self.logger.log(lp.DEBUG, "validationSuccess: " + str(validationSuccess))
        # self.logger.log(lp.DEBUG, "subCmd: " + str(subCmd))
        if validationSuccess:
            # self.logger.log(lp.DEBUG, "cmdDict: " + str(commandDict))
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
            '''
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
                self.logger.log(lp.INFO, "security cmd ran in current context..")

                if not str(error).strip():
                    success = True
            '''
            #####
            # Run the command
            output, error, retcode = self.runWith.communicate()
            self.logger.log(lp.INFO, "security cmd ran in current context..")

            if not str(error).strip():
                success = True
            passfound = False
            for arg in cmd:
                if re.match('password', arg) or re.match("pass", arg) or re.match("passwd", arg):
                    passfound = True
                    break

            if '-p' not in cmd and not passfound:
                self.logger.log(lp.DEBUG, "Output: " + str(output))
                self.logger.log(lp.DEBUG, "Error: " + str(error))
                self.logger.log(lp.DEBUG, "Return code: " + str(returncode))

        return success, str(output).strip(), str(error).strip(), str(returncode).strip()

    # ----------------------------------------------------------------------

    def setUser(self, user=""):
        '''Setter for the class user variable..
        
        @author: Roy Nielsen

        :param user:  (Default value = "")

        '''
        success = False
        if self.isSaneUserName(user):
            self.userName = user
            success = True
        return success

    # ----------------------------------------------------------------------

    def catOne(self, subCommand="", prefDomain="", keychain="", setList=False, *args, **kwargs):
        '''Run a category one subcommand - a subcommand that has a options pattern of:
        
        [-h] [-d user|system|common|dynamic] [-s [keychain...]]
        
        such as list-keychains, default-keychain and login-keychain.

        :param subCommand:  (Default value = "")
        :param prefDomain:  (Default value = "")
        :param keychain:  (Default value = "")
        :param setList:  (Default value = False)
        :param *args: 
        :param **kwargs: 

        '''
        success = False
        stdout = False
        stderr = False
        retcode = 255

        keychain = keychain.strip()
        prefDomain = prefDomain.strip()
        options = []

        validSubcommands = ["list-keychains",
                            "default-keychain",
                            "login-keychain"]

        if subCommand not in validSubcommands:
            return success, False, False, False
        else:
            validDomains = ['user', 'system', 'common', 'dynamic']

            #####
            # Input validation
            if setList and self.isSaneFilePath(keychain) and \
               os.path.exists(keychain):
                options += ['-s', keychain]

            if prefDomain in validDomains:
                options += ['-d', prefDomain]

            #####
            # Command setup
            cmd = {subCommand: options}
            self.logger.log(lp.DEBUG, "Sending: " + str(cmd))

            success, stdout, stderr, retcode = self.runSecurityCommand(cmd)

        return success, stdout, stderr, retcode

    # ----------------------------------------------------------------------
    # Subcommands
    # ----------------------------------------------------------------------

    def listKeychains(self, keychain='', prefDomain='user', setList=False,
                      *args, **kwargs):
        '''Display or manipulate the keychain search list.  Only support a single
        keychain at a time.

        :param keychain:  (Default value = '')
        :param prefDomain:  (Default value = 'user')
        :param setList:  (Default value = False)
        :param *args: 
        :param **kwargs: 

        '''
        keychain = keychain.strip()
        prefDomain = prefDomain.strip()

        success, output, _, _ = self.catOne("list-keychains", prefDomain,
                                            keychain, setList)

        return success, output

    # -------------------------------------------------------------------------

    def defaultKeychain(self, keychain='', prefDomain='user', setList=False,
                        *args, **kwargs):
        '''Display or set the default keychain.

        :param keychain:  (Default value = '')
        :param prefDomain:  (Default value = 'user')
        :param setList:  (Default value = False)
        :param *args: 
        :param **kwargs: 

        '''
        keychain = keychain.strip()
        prefDomain = prefDomain.strip()
        success, output, _, _ = self.catOne("default-keychain",
                                            prefDomain, keychain, setList)
        return success, output

    # -------------------------------------------------------------------------

    def loginKeychain(self, keychain='', prefDomain='user', setList=False,
                      *args, **kwargs):
        '''Display or set the login keychain.

        :param keychain:  (Default value = '')
        :param prefDomain:  (Default value = 'user')
        :param setList:  (Default value = False)
        :param *args: 
        :param **kwargs: 

        '''
        keychain = keychain.strip()
        prefDomain = prefDomain.strip()

        success, output, _, _ = self.catOne("login-keychain", prefDomain, keychain, setList)

        return success, output

    # -------------------------------------------------------------------------

    def createKeychain(self, passwd="", keychain="",
                       *args, **kwargs):
        '''Create a keychain.
        
        @author: Roy Nielsen

        :param passwd:  (Default value = "")
        :param keychain:  (Default value = "")
        :param *args: 
        :param **kwargs: 

        '''
        success = False
        passwd = passwd.strip()
        keychain = keychain.strip()
        #####
        # Input validation for the file keychain.
        if self.isSaneFilePath(keychain) and isinstance(passwd, str):
            #####
            # Command setup - note that the keychain deliberately has quotes
            # around it - there could be spaces in the path to the keychain,
            # so the quotes are required to fully resolve the file path.
            # Note: this is done in the build of the command, rather than
            # the build of the variable.
            cmd = {"create-keychain": ["-p", '%s' % passwd, keychain]}
            success, _, _, _ = self.runSecurityCommand(cmd)

        return success

    # -------------------------------------------------------------------------

    def deleteKeychain(self, keychain="",
                       *args, **kwargs):
        '''Delete keychain

        :param keychain:  (Default value = "")
        :param *args: 
        :param **kwargs: 

        '''
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
            cmd = {"delete-keychain": [keychain]}
            success, _, _, _ = self.runSecurityCommand(cmd)

        return success

    # -------------------------------------------------------------------------

    def lockKeychain(self, keychain="", allKeychains=False):
        '''Lock the defined keychain

        :param eter: keychain - full path to the keychain to unlock
        
        @note:
        security unlock-keychain -p <passwd>
        
        @author: Roy Nielsen
        :param keychain:  (Default value = "")
        :param allKeychains:  (Default value = False)

        '''
        success = False
        keychain = keychain.strip()
        #####
        # Input validation for the file keychain.
        if self.isSaneFilePath(keychain) or allKeychains:
            #####
            # Command setup - note that the keychain deliberately has quotes
            # around it - there could be spaces in the path to the keychain,
            # so the quotes are required to fully resolve the file path.
            # Note: this is done in the build of the command, rather than
            # the build of the variable.
            if allKeychains:
                cmd = {"lock-keychain": ["-a"]}
            else:
                cmd = {"lock-keychain": [keychain]}
            success, stdout, _, _ = self.runSecurityCommand(cmd)

        return success, stdout

    # -------------------------------------------------------------------------

    def unlockKeychain(self, passwd="", keychain=""):
        '''Unlock the defined keychain

        :param eter: passwd - password for the keychain to unlock
        :param eter: keychain - full path to the keychain to unlock
        
        @note:
        security unlock-keychain -p <passwd>
        
        @author: Roy Nielsen
        :param passwd:  (Default value = "")
        :param keychain:  (Default value = "")

        '''
        success = False
        keychain = keychain.strip()
        passwd = passwd.strip()
        output = ""
        #####
        # Input validation for the file keychain.
        if self.isSaneFilePath(keychain) and isinstance(passwd, str):
            #####
            # Command setup - note that the keychain deliberately has quotes
            # around it - there could be spaces in the path to the keychain,
            # so the quotes are required to fully resolve the file path.
            # Note: this is done in the build of the command, rather than
            # the build of the variable.
            cmd = { "unlock-keychain" : ["-p", passwd, keychain] }
            success, output, error, retcode = self.runSecurityCommand(cmd)

            self.logger.log(lp.DEBUG, "Output: " + str(output))
            self.logger.log(lp.DEBUG, "Error: " + str(error))
            self.logger.log(lp.DEBUG, "Return code: " + str(retcode))
        return success, output

    # -------------------------------------------------------------------------

    def changeKeychainPassword(self,
                               user="",
                               oldPass=False,
                               newPass=False,
                               keychain=False):
        '''Use the "security" command to set the login keychain.  If it has not
        been created, create the login keychain.
        
        use the following command on the Mac:
        security set-keychain-password -o <oldpassword> -p <newpassword> <file.keychain>
        
        Most used keychain is the login.keychain-db.
        
        @author: Roy Nielsen

        :param user:  (Default value = "")
        :param oldPass:  (Default value = False)
        :param newPass:  (Default value = False)
        :param keychain:  (Default value = False)

        '''
        success = False
        stdout = ""
        user = user.strip()
        if oldPass and isinstance(oldPass, str):
            oldPass = oldPass.strip()
        if newPass and isinstance(newPass, str):
            newPass = newPass.strip()
        if keychain and isinstance(keychain, str):
            keychain = keychain.strip()

        #####
        # Input validation for the username, and check the passwords to make
        # sure they are valid strings.  Check for the existence of the keychain
        if self.isSaneUserName(user) and \
           isinstance(oldPass, str) and \
           isinstance(newPass, str) and \
           self.isSaneFilePath(keychain):
            userHome = pwd.getpwnam(user).pw_dir
            if os.path.isdir(userHome) and not keychain:
                #####
                # if a keychain isn't passed in use the user's login keychain.
                keychain = userHome + "/Library/Keychains/login.keychain-db"
            #####
            # Command setup - note that the keychain deliberately has quotes
            # around it - there could be spaces in the path to the keychain,
            # so the quotes are required to fully resolve the file path.
            # Note: this is done in the build of the command, rather than
            # the build of the variable.
            cmd = {"set-keychain-password": ["-o", '%s' % oldPass, "-p", '%s' % newPass, keychain]}
            self.logger.log(lp.DEBUG, "cmd: " + str(cmd))
            success, stdout, stderr, retcode = self.runSecurityCommand(cmd)
            self.logger.log(lp.DEBUG, "stdout: " + str(stdout))
            self.logger.log(lp.DEBUG, "stderr: " + str(stderr))
            self.logger.log(lp.DEBUG, "retcode: " + str(retcode))

        return success, stdout

    # -------------------------------------------------------------------------

    def showKeychainInfo(self, keychain,
                         *args, **kwargs):
        '''Show the settings for a keychain.

        :param keychain: 
        :param *args: 
        :param **kwargs: 

        '''
        success = False
        stdout = False
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
            cmd = {"show-keychain-info": [keychain]}
            self.logger.log(lp.DEBUG, "cmd: " + str(cmd))
            success, stdout, _, _ = self.runSecurityCommand(cmd)

        return success, stdout

    # -------------------------------------------------------------------------

    def dumpKeychain(self, *args, **kwargs):
        '''Dump the contents of one or more keychains.
        
        @Note: No parameters currently supported, will dump all information.
        
        @author: Roy Nielsen

        :param *args: 
        :param **kwargs: 

        '''
        #####
        # Command setup - note that the keychain deliberately has quotes
        # around it - there could be spaces in the path to the keychain,
        # so the quotes are required to fully resolve the file path.
        # Note: this is done in the build of the command, rather than
        # the build of the variable.
        cmd = {"dump-keychain": []}
        self.logger.log(lp.DEBUG, "cmd: " + str(cmd))
        success, stdout, _, _ = self.runSecurityCommand(cmd)

        return success, stdout

    # -------------------------------------------------------------------------

    def findCertificate(self, name='', keychain='',
                        *args, **kwargs):
        '''Find a certificate item.  Search based on 'name', currently finds all,
        matches, printing output in PEM format.

        :param name:  (Default value = '')
        :param keychain:  (Default value = '')
        :param *args: 
        :param **kwargs: 

        '''
        success = False
        stdout = False
        name = name.strip()
        keychain = keychain.strip()

        if not name or not isinstance(name, str):
            return success, stdout
        else:
            #####
            # Command setup - note that the keychain deliberately has quotes
            # around it - there could be spaces in the path to the keychain,
            # so the quotes are required to fully resolve the file path.
            # Note: this is done in the build of the command, rather than
            # the build of the variable.
            if self.isSaneFilePath(keychain) and os.path.exists(keychain):
                cmd = {"find-certificate": ["-a", "-c", name, "-p", keychain]}
            else:
                cmd = {"find-certificate": ["-a", "-c", name, "-p"]}
            self.logger.log(lp.DEBUG, "cmd: " + str(cmd))
            success, stdout, _, _ = self.runSecurityCommand(cmd)

        return success, stdout

    # -------------------------------------------------------------------------

    def findIdentity(self, valid=True, policy='', sstring='', keychain='',
                     *args, **kwargs):
        '''Find an identity (certificate + private key).  Only shows valid
        identities.

        :param valid:  (Default value = True)
        :param policy:  (Default value = '')
        :param sstring:  (Default value = '')
        :param keychain:  (Default value = '')
        :param *args: 
        :param **kwargs: 

        '''
        policy = policy.strip()
        keychain = keychain.strip()
        sstring = sstring.strip()
        options = []

        validPolicies = ["basic", "ssl-client", "ssl-server", "smime", "eap",
                         "ipsec", "ichat", "codesigning", "sys-default", 
                         "sys-kerberos-kdc"]

        if policy in validPolicies:
            #####
            # Only add the policy option if it in the valid set
            options += ['-p', policy]

        if sstring and isinstance(sstring, str):
            #####
            # sstring stands for search string.
            # Do not allow user input here, only known safe programmer input.
            options += ['-s', sstring]

        if valid:
            #####
            # Only valid entries in the kechain search list, add the '-v'
            options += ['-v']

        if self.isSaneFilePath(keychain) and os.path.exists(keychain):
            #####
            # If a keychain is given and passes validation, add it to the options.
            options += [keychain]

        #####
        # Set up and log the command
        cmd = {'find-identity' : options}
        self.logger.log(lp.DEBUG, "cmd: " + str(cmd))

        #####
        # Run the command.
        success, stdout, stderr, retcode = self.runSecurityCommand(cmd)

        self.logger.log(lp.DEBUG, str(success))
        self.logger.log(lp.DEBUG, str(stdout))
        self.logger.log(lp.DEBUG, str(stderr))
        self.logger.log(lp.DEBUG, str(retcode))

        return success, stdout

    # -------------------------------------------------------------------------

    def authorize(self, options='', right='',
                  *args, **kwargs):
        '''Display descriptive message for the given error code(s).

        :param options:  (Default value = '')
        :param right:  (Default value = '')
        :param *args: 
        :param **kwargs: 

        '''
        success = False
        stdout = False
        options = options.strip()
        right = right.strip()

        if not options or not isinstance(options, str):
            return success, stdout
        else:
            #####
            # Command setup - note that the keychain deliberately has quotes
            # around it - there could be spaces in the path to the keychain,
            # so the quotes are required to fully resolve the file path.
            # Note: this is done in the build of the command, rather than
            # the build of the variable.
            if right and isinstance(right, str):
                cmd = {"authorize": [options, right]}
            self.logger.log(lp.DEBUG, "cmd: " + str(cmd))
            success, stdout, _, _ = self.runSecurityCommand(cmd)

        return success, stdout

    # -------------------------------------------------------------------------

    def error(self, ecode='',
              *args, **kwargs):
        '''Display descrip6tive message for the given error code(s).

        :param ecode:  (Default value = '')
        :param *args: 
        :param **kwargs: 

        '''
        success = False
        stdout = False
        ecode = ecode.strip()

        if not ecode or not isinstance(ecode, str):
            return success, stdout
        else:
            #####
            # Command setup - note that the keychain deliberately has quotes
            # around it - there could be spaces in the path to the keychain,
            # so the quotes are required to fully resolve the file path.
            # Note: this is done in the build of the command, rather than
            # the build of the variable.
            cmd = {"error": [ecode]}
            self.logger.log(lp.DEBUG, "cmd: " + str(cmd))
            success, stdout, _, _ = self.runSecurityCommand(cmd)

        return success, stdout

    # -------------------------------------------------------------------------

    def setKeyPartitionList(self,
                            options=False,
                            keyPass='',
                            keychain='',
                            creator='',
                            description='',
                            comment='',
                            label='',
                            keyType='',
                            partIDs="apple-tool:,apple:,codesign:",
                            *args, **kwargs):
        '''Not known what exactly this subcommand does, it is required
        on MacOS Sierra to allow for signing with xcodebuild or codesign.
        
        Usage: set-key-partition-list [options...] [keychain]
            -a  Match "application label" string
            -c  Match "creator" (four-character code)
            -d  Match keys that can decrypt
            -D  Match "description" string
            -e  Match keys that can encrypt
            -j  Match "comment" string
            -l  Match "label" string
            -r  Match keys that can derive
            -s  Match keys that can sign
            -t  Type of key to find: one of "symmetric", "public", or "private"
            -u  Match keys that can unwrap
            -v  Match keys that can verify
            -w  Match keys that can wrap
            -S  Comma-separated list of allowed partition IDs
            -k  password for keychain (required)
        If no keychains are specified to search, the default search list is used.

        :param options:  (Default value = False)
        :param keyPass:  (Default value = '')
        :param keychain:  (Default value = '')
        :param creator:  (Default value = '')
        :param description:  (Default value = '')
        :param comment:  (Default value = '')
        :param label:  (Default value = '')
        :param keyType:  (Default value = '')
        :param partIDs:  (Default value = "apple-tool:)
        :param apple:: 
        :param codesign:": 
        :param *args: 
        :param **kwargs: 

        '''
        success = False
        stdout = False
        name = name.strip()
        keychain = keychain.strip()
        if not options:
            options = []

        if not keyPass or not isinstance(keyPass, str):
            return success, stdout

        #####
        # -a  Match "application label" string
        if 'a' in options: options = options + ['-a']

        #####
        # -d  Match keys that can decrypt
        if 'd' in options: options = options + ['-d']

        #####
        # -e  Match keys that can encrypt
        if 'e' in options: options = options + ['-e']

        #####
        # -r  Match keys that can derive
        if 'r' in options: options = options + ['-r']

        #####
        # -s  Match keys that can sign
        if 's' in options: options = options + ['-s']

        #####
        # -u  Match keys that can unwrap
        if 'u' in options: options = options + ['-u']

        #####
        # -v  Match keys that can verify
        if 'v' in options: options = options + ['-v']

        #####
        # -w  Match keys that can wrap
        if 'w' in options: options = options + ['-w']

        #####
        #  -c  Match "creator" (four-character code)
        if isinstance(creator, str) and len(creator) == 4:
            options = options + ['-c', creator]

        #####
        #  -D  Match "description" string
        if isinstance(description, str):
            options = options + ['-D', description]

        #####
        # -j  Match "comment" string
        if isinstance(comment, str):
            options = options + ['-j', comment]

        #####
        # -l  Match "label" string
        if isinstance(label, str):
            options = options + ['-l', label]

        #####
        # -t  Type of key to find: one of "symmetric", "public", or "private"
        if keyType in ["symmetric", "public", "private"]:
            options = options + ['-t', keyType]

        #####
        # -S  Comma-separated list of allowed partition IDs
        if partIDs and isinstance(partIDs, str):
            options = options + ['-S', partIDs]

        #####
        # -k  password for keychain (required)
        if keyPass:
            options = options + ['-k', keyPass]

        #####
        # Note: that the keychain deliberately has quotes
        # around it - there could be spaces in the path to the keychain,
        # so the quotes are required to fully resolve the file path.  
        # Note: this is done in the build of the command, rather than 
        # the build of the variable.
        if self.isSaneFilePath(keychain) and os.path.exists(keychain):
            options = options + [keychain]

        #####
        # Command setup
        cmd = { "set-key-partition-list" : options }
        self.logger.log(lp.DEBUG, "cmd: " + str(cmd))

        #####
        # Spawn the command via private method
        success, stdout, _, _ = self.runSecurityCommand(cmd)

        return success, stdout
