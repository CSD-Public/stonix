'''
Supports MacOS Yosemite, El Capitan and Sierra launchctl commands

Some methods might be useful in older Mac OS X operating systems.

@note: Manpage sections taken from the El Capitan man page.

@author: Roy Nielsen
'''
import os
import re
import sys

from logdispatcher import LogPriority as lp
from CommandHelper import CommandHelper
from stonixutilityfunctions import reportStack

class LaunchCtl(object):
    """
    Service manager that provides an interface to the Mac OS launchctl command.
    
    @privatemethod: validateSubCommand - validate a command that is
                    formatted as: { <subcommand> : [<arg1>, <arg1>, <arg3>]}
                    where each argN is a string.

    @privatemethod: runSubCommand - runs a launchctl command, in the format
                    described above, then collects standard out, standard error
                    and the launchctl return code, returning them to the caller.

    #-------------------------------------------------------------------------
    Legacy commands

    @publicmethod: load - (legacy) loads the passed in plist/service

    @publicmethod: unload - (legacy) unloads the passed in plist/service

    @publicmethod: start - (legacy) Start a service

    @publicmethod: stop - (legacy) Stop a service

    @publicmethod: list - (legacy) list a specific plist state, or
                   returns a list of running launchd services.

    @publicmethod: bsexec - (legacy) execute a command in as close as possible
                            context to the passed in PID.

    @publicmethod: asuser - (legacy) execute a command in as close as possible
                            context to the passed in UID

    #-------------------------------------------------------------------------
    Current commands

    @publicmethod: bootstrap

    @publicmethod: bootout

    @publicmethod: enable

    @publicmethod: disable

    @publicmethod: uncache

    @publicmethod: kickstart

    @publicmethod: kill - (2.0) Kills a service, with one of the passed
                   in signals that are described in the Mac OS signal(3) manpage.

    @publicmethod: blame

    @publicmethod: printTarget

    @publicmethod: printCache

    @publicmethod: printDisabled

    @publicmethod: procinfo

    @publicmethod: hostinfo

    @publicmethod: resolveport

    @publicmethod: reboot

    @Note: Future subcommands may include 'plist', 'config', 'error'.

    @author: Roy Nielsen
    """
    def __init__(self, logger):
        """
        Initialization Method

        @author: Roy Nielsen
        """
        self.launchctl = "/bin/launchctl"
        self.logger = logger
        self.ch = CommandHelper(self.logger)

    #----------------------------------------------------------------------
    # helper methods
    #----------------------------------------------------------------------

    def isSaneFilePath(self, filepath):
        """
        Check for a good file path in the passed in string.

        @author: Roy Nielsen
        """
        sane = False
        if isinstance(filepath, basestring):
            if re.match("^[A-Za-z/\.][A-Za-z0-9/\._-]*", filepath):
                sane = True
            else:
                self.logger.log(lp.DEBUG, "filepath: " + str(filepath) + " is not valid.")
        return sane

    #----------------------------------------------------------------------

    def validateSubCommand(self, command={}):
        """
        Validate that we have a properly formatted command, and the subcommand
        is valid.

        @param: the commandDict should be in the format below:

        cmd = { "load" : [options, sessionType, launchJobPath] }

        where the key is the launchctl 'subcommand' and the list is an ordered
        list of the arguments to give the subcommand.

        @returns: success - whether the command was formatted correctly or not.

        @author: Roy Nielsen
        """
        success = False
        subcmd = []
        if not isinstance(command, dict):
            self.logger.log(lp.ERROR, "Command must be a dictionary...")
        else:
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
                validSubcommands = ["load", "unload","start", "stop", "list",
                                    "bsexec", "asuser",
                                    "bootstrap", "bootout", "enable", "disable",
                                    "uncache", "kickstart", "kill", "blame",
                                    "print", "print-cache", "print-disabled",
                                    "procinfo", "hostinfo", "resolveport",
                                    "reboot"]
                if subCommand not in validSubcommands:
                    success = False
                    break
                else:
                    success = True
                #####
                # Check to make sure the key or subCommand is a string, and the value is
                # alist and args are
                if not isinstance(subCommand, basestring) or not isinstance(args, list):
                    self.logger.log(lp.ERROR, "subcommand needs to be a string, and args needs to be a list of strings")
                    success = False
                else:
                    #####
                    # Check the arguments to make sure they are all strings
                    for arg in args:
                        if not isinstance(arg, basestring):
                            self.logger.log(lp.ERROR, "Arg '" + str(arg) + "'needs to be a string...")
                            success = False
                    if success:
                        subcmd = [subCommand] + args
                        self.logger.log(lp.DEBUG, 'subcmd: ' + str(subcmd))
        return success, subcmd

    #-------------------------------------------------------------------------

    def runSubCommand(self, commandDict={}):
        """
        Use the passed in dictionary to create a MacOS 'security' command
        and execute it.

        @param: the commandDict should be in the format below:

        cmd = { "bsexec" : [pid, command, arg1, arg2, ...] }

        where the key is the security 'subcommand' and the list is an ordered
        list of the arguments to give the subcommand.

        @returns: success - whether the command was successfull or not.

        @author: Roy Nielsen
        """
        success = False
        output = ''
        error = ''
        returncode = ''
        #####
        # Make sure the command dictionary was properly formed, as well as
        # returning the formatted subcommand list
        validationSuccess, subCmd = self.validateSubCommand(commandDict)
        if validationSuccess:
            #####
            # Command setup - note that the keychain deliberately has quotes
            # around it - there could be spaces in the path to the keychain,
            # so the quotes are required to fully resolve the file path.
            # Note: this is done in the build of the command, rather than
            # the build of the variable.
            cmd = [self.launchctl] + subCmd
            self.logger.log(lp.DEBUG, 'cmd: ' + str(cmd))
            #####
            # set up and run the command
            #self.ch.setCommand(cmd)
            success = self.ch.executeCommand(cmd)

            output = self.ch.getOutput()
            error = self.ch.getError()
            returncode = self.ch.getReturnCode()
            #####
            # If the return code is 0, then we have success.
            if not returncode:
                success = True
                """
                if "bootstrap" in subCmd:
                    raise ValueError("cmd: " + str(cmd) + " output: " + str(output) + \
                                     " error: " + str(error) + " retcode: " + str(returncode))
                """

            if error:
                self.logger.log(lp.INFO, "Output: " + str(output))
                self.logger.log(lp.INFO, "Error: " + str(error))
                self.logger.log(lp.INFO, "Return code: " + str(returncode))
                success = False

        else:
            raise(ValueError("Invalid subcommand: " + str(commandDict)))

        return success, str(output), str(error), str(returncode)

    #----------------------------------------------------------------------
    # Legacy Subcommands
    #----------------------------------------------------------------------

    def load(self, plist="", options="", sessionType="", domain=False):
        """
        @note: From the launchctl man page:
          load | unload [-wF] [-S sessiontype] [-D domain] paths ...
              Load the specified configuration files or directories of con-
              figuration files.  Jobs that are not on-demand will be started
              as soon as possible. All specified jobs will be loaded before
              any of them are allowed to start. Note that per-user configura-
              tion files (LaunchAgents) must be owned by root (if they are
              located in /Library/LaunchAgents) or the user loading them (if
              they are located in $HOME/Library/LaunchAgents).  All system-
              wide daemons (LaunchDaemons) must be owned by root. Configura-
              tion files must disallow group and world writes. These restric-
              tions are in place for security reasons, as allowing writabil-
              ity to a launchd configuration file allows one to specify which
              executable will be launched.

              Note that allowing non-root write access to the
              /System/Library/LaunchDaemons directory WILL render your system
              unbootable.

              -w       Overrides the Disabled key and sets it to false or
                       true for the load and unload subcommands respectively.
                       In previous versions, this option would modify the
                       configuration file. Now the state of the Disabled key
                       is stored elsewhere on- disk in a location that may
                       not be directly manipulated by any process other than
                       launchd.

              -F       Force the loading or unloading of the plist. Ignore
                       the Disabled key.

              -S sessiontype
                       Some jobs only make sense in certain contexts. This
                       flag instructs launchctl to look for jobs in a differ-
                       ent location when using the -D flag, and allows
                       launchctl to restrict which jobs are loaded into which
                       session types. Sessions are only relevant for per-user
                       launchd contexts. Relevant sessions are Aqua (the
                       default), Background and LoginWindow.  Background
                       agents may be loaded independently of a GUI login.
                       Aqua agents are loaded only when a user has logged in
                       at the GUI. LoginWindow agents are loaded when the
                       LoginWindow UI is displaying and currently run as
                       root.

              -D domain
                       Look for plist(5) files ending in *.plist in the
                       domain given. This option may be thoughts of as
                       expanding into many individual paths depending on the
                       domain name given. Valid domains include "system,"
                       "local," "network" and "all." When providing a session
                       type, an additional domain is available for use called
                       "user." For example, without a session type given, "-D
                       system" would load from or unload property list files
                       from /System/Library/LaunchDaemons.  With a session
                       type passed, it would load from /System/Library/Laun-

              NOTE: Due to bugs in the previous implementation and long-
              standing client expectations around those bugs, the load and
              unload subcommands will only return a non-zero exit code due to
              improper usage.  Otherwise, zero is always returned.

        @author: Roy Nielsen
        """
        success = False
        #####
        # Input validation.
        if self.isSaneFilePath(plist):
            args = []

            if re.match("[-wF]+", str(options)) and isinstance(options, basestring):
                args.append(options)
            else:
                self.logger.log(lp.INFO, "Need a the options to be a single string...")

            sessionTypes = ['Aqua', 'StandardIO', 'Background', 'LoginWindow']
            if sessionType in sessionTypes:
                args += ['-S', sessionType]
            else:
                self.logger.log(lp.INFO, "Need a the sessionType in: " + str(sessionTypes))

            if isinstance(domain, basestring):
                args += ['-D', domain]
            else:
                self.logger.log(lp.INFO, "Need a the domain in: " + str(sessionTypes))

            args.append(plist)

            cmd = { "load" : args }
            success, stdout, stderr, retcode = self.runSubCommand(cmd)

            if not success and re.search("already loaded", stderr):
                success = True

        return success

    #-------------------------------------------------------------------------

    def unLoad(self, plist="", options="", sessionType="", domain=False):
        """
        @note: From the launchctl man page:
          load | unload [-wF] [-S sessiontype] [-D domain] paths ...
              Load the specified configuration files or directories of con-
              figuration files.  Jobs that are not on-demand will be started
              as soon as possible. All specified jobs will be loaded before
              any of them are allowed to start. Note that per-user configura-
              tion files (LaunchAgents) must be owned by root (if they are
              located in /Library/LaunchAgents) or the user loading them (if
              they are located in $HOME/Library/LaunchAgents).  All system-
              wide daemons (LaunchDaemons) must be owned by root. Configura-
              tion files must disallow group and world writes. These restric-
              tions are in place for security reasons, as allowing writabil-
              ity to a launchd configuration file allows one to specify which
              executable will be launched.

              Note that allowing non-root write access to the
              /System/Library/LaunchDaemons directory WILL render your system
              unbootable.

              -w       Overrides the Disabled key and sets it to false or
                       true for the load and unload subcommands respectively.
                       In previous versions, this option would modify the
                       configuration file. Now the state of the Disabled key
                       is stored elsewhere on- disk in a location that may
                       not be directly manipulated by any process other than
                       launchd.

              -F       Force the loading or unloading of the plist. Ignore
                       the Disabled key.

              -S sessiontype
                       Some jobs only make sense in certain contexts. This
                       flag instructs launchctl to look for jobs in a differ-
                       ent location when using the -D flag, and allows
                       launchctl to restrict which jobs are loaded into which
                       session types. Sessions are only relevant for per-user
                       launchd contexts. Relevant sessions are Aqua (the
                       default), Background and LoginWindow.  Background
                       agents may be loaded independently of a GUI login.
                       Aqua agents are loaded only when a user has logged in
                       at the GUI. LoginWindow agents are loaded when the
                       LoginWindow UI is displaying and currently run as
                       root.

              -D domain
                       Look for plist(5) files ending in *.plist in the
                       domain given. This option may be thoughts of as
                       expanding into many individual paths depending on the
                       domain name given. Valid domains include "system,"
                       "local," "network" and "all." When providing a session
                       type, an additional domain is available for use called
                       "user." For example, without a session type given, "-D
                       system" would load from or unload property list files
                       from /System/Library/LaunchDaemons.  With a session
                       type passed, it would load from /System/Library/Laun-

              NOTE: Due to bugs in the previous implementation and long-
              standing client expectations around those bugs, the load and
              unload subcommands will only return a non-zero exit code due to
              improper usage.  Otherwise, zero is always returned.

        @author: Roy Nielsen
        """
        success = False
        #####
        # Input validation.
        if self.isSaneFilePath(plist):
            args = []

            if re.match("[-wF]+", str(options)) and isinstance(options, basestring):
                args.append(options)
            else:
                self.logger.log(lp.INFO, "Need a the options to be a single string...")

            sessionTypes = ['Aqua', 'StandardIO', 'Background', 'LoginWindow']
            if sessionType in sessionTypes:
                args += ['-S', sessionType]
            else:
                self.logger.log(lp.INFO, "Need a the sessionType in: " + str(sessionTypes))

            if isinstance(domain, basestring):
                args += ['-D', domain]
            else:
                self.logger.log(lp.INFO, "Need a the domain in: " + str(sessionTypes))

            args.append(plist)

            cmd = { "unload" : args }
            success, stdout, stderr, retcode = self.runSubCommand(cmd)
            if not success and re.search('Could not find specified', stderr):
                success = True

        return success

    #-------------------------------------------------------------------------

    def start(self, label=""):
        """
        @note: From the launchctl man page:
          start label
              Start the specified job by label. The expected use of this sub-
              command is for debugging and testing so that one can manually
              kick-start an on-demand server.

        @author: Roy Nielsen
        """
        success = False
        #####
        # Input validation.
        if not label or not isinstance(label, basestring):
            return success
        
        cmd = { "start" : label }
        success, stdout, stderr, retcode = self.runSubCommand(cmd)

        return success

    #-------------------------------------------------------------------------

    def stop(self, label=""):
        """
        @note: From the launchctl man page:
          stop label
              Stop the specified job by label. If a job is on-demand, launchd
              may immediately restart the job if launchd finds any criteria
              that is satisfied.

        @author: Roy Nielsen
        """
        success = False
        #####
        # Input validation.
        if not label or not isinstance(label, basestring):
            return success
        
        cmd = { "stop" : label }
        success, stdout, stderr, retcode = self.runSubCommand(cmd)

        return success

    #-------------------------------------------------------------------------

    def list(self, label=""):
        """
        @note: From the launchctl man page:
          list [-x] [label]
              With no arguments, list all of the jobs loaded into launchd in
              three columns. The first column displays the PID of the job if
              it is running.  The second column displays the last exit status
              of the job. If the number in this column is negative, it repre-
              sents the negative of the signal which stopped the job. Thus,
              "-15" would indicate that the job was terminated with SIGTERM.
              The third column is the job's label. If [label] is specified,
              prints information about the requested job.

              -x       This flag is no longer supported.

        @author: Roy Nielsen
        """
        success = False
        error = True
        output = ""
        returncode = 0
        #####
        # Input validation.
        if label and isinstance(label, basestring):
            cmd = [self.launchctl, 'list', label]
        elif not label:
            cmd = [self.launchctl, 'list']
        else:
            return success
            #####
            # set up and run the command
            self.ch.setCommand(cmd)
            success = self.ch.executeCommand()
            if success:
                output = self.ch.getOutput()
                error = self.ch.getError()
                returncode = self.ch.getReturnCode()

        if not error:
            success = True
        else:
            self.logger.log(lp.DEBUG, "Output: " + str(output))
            self.logger.log(lp.DEBUG, "Error: " + str(error))
            self.logger.log(lp.DEBUG, "Return code: " + str(returncode))
            success = False

        return success, output, error, returncode

    #-------------------------------------------------------------------------

    def bsExec(self, pid, command, args=[]):
        '''
        @note: From the launchctl man page:
          bsexec PID command [args]
              This executes the given command in as similar an execution con-
              text as possible to the target PID. Adopted attributes include
              the Mach bootstrap namespace, exception server and security
              audit session. It does not modify the process' credentials
              (UID, GID, etc.) or adopt any environment variables from the
              target process. It affects only the Mach bootstrap context and
              directly-related attributes.

        @author: Roy Nielsen
        '''
        success = False
        #####
        # Input validation.
        if not isinstance(pid, int) or \
           not isinstance(command, basestring) or \
           not isinstance(args, list):
            return success
        
        cmd = { "bsexec" : [pid, command] + args }
        success, stdout, stderr, retcode = self.runSubCommand(cmd)

        return success

    #-------------------------------------------------------------------------

    def asUser(self, uid, command, args=[]):
        '''
        @note: From the launchctl man page:
          asuser UID command [args]
              This executes the given command in as similar an execution con-
              text as possible to that of the target user's bootstrap.
              Adopted attributes include the Mach bootstrap namespace, excep-
              tion server and security audit session. It does not modify the
              process' credentials (UID, GID, etc.) or adopt any user-spe-
              cific environment variables. It affects only the Mach bootstrap
              context and directly- related attributes.

        @author: Roy Nielsen
        '''
        success = False
        #####
        # Input validation.
        if not isinstance(uid, int) or \
           not isinstance(command, basestring) or \
           not isinstance(args, list):
            return success
        
        cmd = { "asuser" : [uid, command] + args }
        success, stdout, stderr, retcode = self.runSubCommand(cmd)

        if retcode != '0':
            raise ValueError(reportStack() + "- success: " + str(success) + \
                             " stdout: " + str(stdout) + \
                             " stderr: " + str(stderr) + \
                             " retcode: " + str(retcode))
        return success

    #----------------------------------------------------------------------
    # Supported Second generation subcommands
    #----------------------------------------------------------------------

    def bootStrap(self, servicePath='', domainTarget=""):
        '''
        @note: From the launchctl man page:
          bootstrap | bootout domain-target [service-path service-path2 ...] |
              service-target
              Bootstraps or removes domains and services. Services may be
              specified as a series of paths or a service identifier. Paths
              may point to XPC service bundles, launchd.plist(5) s, or a
              directories containing a collection of either. If there were
              one or more errors while bootstrapping or removing a collection
              of services, the problematic paths will be printed with the
              errors that occurred.

              If no paths or service target are specified, these commands can
              either bootstrap or remove a domain specified as a domain tar-
              get. Some domains will implicitly bootstrap pre-defined paths
              as part of their creation.

        @author: Roy Nielsen
        '''
        success = False
        #####
        # Input validation.
        if not isinstance(domainTarget, basestring) or \
           not isinstance(servicePath, basestring):
            return success
        
        cmd = { "bootstrap" : [domainTarget.split("/")[0], servicePath] }
        success, stdout, stderr, retcode = self.runSubCommand(cmd)

        if retcode != '0':
            raise ValueError(reportStack() + "- success: " + str(success) + \
                             " stdout: " + str(stdout) + \
                             " stderr: " + str(stderr) + \
                             " retcode: " + str(retcode))
        return success

    #----------------------------------------------------------------------

    def bootOut(self, domainTarget="", servicePath=''):
        '''
        @note: From the launchctl man page:
          bootstrap | bootout domain-target [service-path service-path2 ...] |
              service-target
              Bootstraps or removes domains and services. Services may be
              specified as a series of paths or a service identifier. Paths
              may point to XPC service bundles, launchd.plist(5) s, or a
              directories containing a collection of either. If there were
              one or more errors while bootstrapping or removing a collection
              of services, the problematic paths will be printed with the
              errors that occurred.

              If no paths or service target are specified, these commands can
              either bootstrap or remove a domain specified as a domain tar-
              get. Some domains will implicitly bootstrap pre-defined paths
              as part of their creation.

        @author: Roy Nielsen
        '''
        success = False
        #####
        # Input validation.
        if not isinstance(domainTarget, basestring) or \
           not isinstance(servicePath, basestring):
            return success
        
        cmd = { "bootout" : [domainTarget] }
        
        if self.printTarget(domainTarget):
            success, stdout, stderr, retcode = self.runSubCommand(cmd)
            #####
            # errors that indicate the process is complete or in
            # progress
            if re.search("No such process", stderr) or \
               re.search("Operation now in progress", stderr):
                success = True

        if retcode != '0'and not success:
            raise ValueError(reportStack() + "- success: " + str(success) + \
                             " stdout: " + str(stdout) + \
                             " stderr: " + str(stderr) + \
                             " retcode: " + str(retcode))
        return success

    #----------------------------------------------------------------------

    def enable(self, serviceTarget):
        '''
        From the launchctl man page:
          enable | disable service-target
              Enables or disables the service in the requested domain. Once a
              service is disabled, it cannot be loaded in the specified
              domain until it is once again enabled. This state persists
              across boots of the device. This subcommand may only target
              services within the system domain or user and user-login
              domains.

        @param: serviceTarget - See description below for details on
                this variable.
                
               system/[service-name]
                  Targets the system domain or a service within the system
                  domain. The system domain manages the root Mach bootstrap
                  and is considered a privileged execution context.
                  Anyone may read or query the system domain, but root privileges
                  are required to make modifications.

                user/<uid>/[service-name]
                  Targets the user domain for the given UID or a service
                  within that domain. A user domain may exist independently
                  of a logged-in user. User domains do not exist on iOS.

                For instance, when referring to a service with the identifier
                com.apple.example loaded into the GUI domain of a user with UID 501,
                domain-target is gui/501/, service-name is com.apple.example,
                and service-target is gui/501/com.apple.example.

        @author: Roy Nielsen
        '''
        success = False
        #####
        # Input validation.
        if not isinstance(serviceTarget, basestring):
            return success
        
        cmd = { "enable" : [serviceTarget] }
        success, stdout, stderr, retcode = self.runSubCommand(cmd)
        if retcode != '0':
            raise ValueError(reportStack() + "- success: " + str(success) + \
                             " stdout: " + str(stdout) + \
                             " stderr: " + str(stderr) + \
                             " retcode: " + str(retcode))
        return success

    #-------------------------------------------------------------------------

    def disable(self, serviceTarget):
        '''
        From the launchctl man page:
          enable | disable service-target
              Enables or disables the service in the requested domain. Once a
              service is disabled, it cannot be loaded in the specified
              domain until it is once again enabled. This state persists
              across boots of the device. This subcommand may only target
              services within the system domain or user and user-login
              domains.

        @param: serviceTarget - See description below for details on
                this variable.
                
               system/[service-name]
                  Targets the system domain or a service within the system
                  domain. The system domain manages the root Mach bootstrap
                  and is considered a privileged execution context.
                  Anyone may read or query the system domain, but root privileges
                  are required to make modifications.

                user/<uid>/[service-name]
                  Targets the user domain for the given UID or a service
                  within that domain. A user domain may exist independently
                  of a logged-in user. User domains do not exist on iOS.

                For instance, when referring to a service with the identifier
                com.apple.example loaded into the GUI domain of a user with UID 501,
                domain-target is gui/501/, service-name is com.apple.example,
                and service-target is gui/501/com.apple.example.

        @author: Roy Nielsen
        '''
        success = False
        #####
        # Input validation.
        if not isinstance(serviceTarget, basestring):
            return success
        
        cmd = { "disable" : [serviceTarget] }
        success, stdout, stderr, retcode = self.runSubCommand(cmd)

        if retcode != '0':
            raise ValueError(reportStack() + "- success: " + str(success) + \
                             " stdout: " + str(stdout) + \
                             " stderr: " + str(stderr) + \
                             " retcode: " + str(retcode))
        return success

    #-------------------------------------------------------------------------

    def unCache(self, serviceName):
        '''
        Bypass the cache and read the service configuration from disk
        
        @param: serviceName - name of the service to check (plist), must
                contain the full path to the service plist
        
        @note: From the launchctl man page:
          uncache service-name
              This subcommand instructs launchd to bypass its service cache
              for the named service and instead read the service's configura-
              tion file directly from disk.  launchd maintains an in-memory
              cache of XPC service configuration files to minimize the disk
              I/O. This subcommand will remove a cached entry so that devel-
              opers may more rapidly iterate on a service's configuration. It
              should not ever be used as part of production workflow.

        @author: Roy Nielsen
        '''
        success = False
        #####
        # Input validation.
        if not isinstance(serviceName, basestring):
            return success
        
        cmd = { "uncache" : [serviceName] }
        success, stdout, stderr, retcode = self.runSubCommand(cmd)

        return success

    #-------------------------------------------------------------------------

    def kickStart(self, serviceTarget="", options='-k'):
        """
        From the launchctl man page:
          kickstart [-kp] service-target
              Instructs launchd to kickstart the specified service. 
              Options can be one of:

              -k       If the service is already running, kill the running
                       instance before restarting the service.
            
              -p       Upon success, print the PID of the new process or the
                       already-running process to stdout.
            
            High sierra options:
              -s       Force the service to start.

              -x       Attach to xpcproxy(3) before it execs and becomes the service
                       process. This flag is generally not useful for anyone but the
                       launchd maintainer.
                       
              (-p)     No longer available in High Sierra

        @param: serviceTarget - See description below for details on
                this variable.
                
               system/[service-name]
                  Targets the system domain or a service within the system
                  domain. The system domain manages the root Mach bootstrap
                  and is considered a privileged execution context.
                  Anyone may read or query the system domain, but root privileges
                  are required to make modifications.

                user/<uid>/[service-name]
                  Targets the user domain for the given UID or a service
                  within that domain. A user domain may exist independently
                  of a logged-in user. User domains do not exist on iOS.

                For instance, when referring to a service with the identifier
                com.apple.example loaded into the GUI domain of a user with UID 501,
                domain-target is gui/501/, service-name is com.apple.example,
                and service-target is gui/501/com.apple.example.

        @author: Roy Nielsen
        """
        success = False
        #####
        # Input validation.
        args = []
        if re.match("[-kp]+", str(options)) and isinstance(options, basestring):
            args.append(options)
        else:
            self.logger.log(lp.INFO, "Need a the options to be a single string...")

        args.append(serviceTarget)

        self.logger.log(lp.DEBUG, "args: " + str(args))

        cmd = { "kickstart" : args }
        self.logger.log(lp.DEBUG, "cmd: " + str(cmd))
        success, stdout, stderr, retcode = self.runSubCommand(cmd)
        #####
        # If a '0' is returned
        if retcode == '0':
            success = True
        else:
            raise ValueError("kickstart - success: " + str(success) + \
                             " stdout: " + str(stdout) + \
                             " stderr: " + str(stderr) + \
                             " retcode: " + str(retcode))
            
        return success

    #-------------------------------------------------------------------------

    def kill(self, signal="", serviceTarget=""):
        """
        From the launchctl man page:
          kill signal-name | signal-number service-target
              Sends the specified signal to the specified service if it is
              running. The signal number or name (SIGTERM, SIGKILL, etc.) may
              be specified.
              
        @param: signal - Unix signals to be used can be found below in the 'signals'
                variable.
        @param: serviceTarget - See description below for details on
                this variable.
                
               system/[service-name]
                  Targets the system domain or a service within the system
                  domain. The system domain manages the root Mach bootstrap
                  and is considered a privileged execution context.
                  Anyone may read or query the system domain, but root privileges
                  are required to make modifications.

                user/<uid>/[service-name]
                  Targets the user domain for the given UID or a service
                  within that domain. A user domain may exist independently
                  of a logged-in user. User domains do not exist on iOS.

                For instance, when referring to a service with the identifier
                com.apple.example loaded into the GUI domain of a user with UID 501,
                domain-target is gui/501/, service-name is com.apple.example,
                and service-target is gui/501/com.apple.example.



        @author: Roy Nielsen
        """
        success = False
        args = []
        #####
        # Validate signal - from the signal(3) manpage on OS X.
        signals = ['SIGHUP', 'SIGINT', 'SIGQUIT', 'SIGILL', 'SIGTRAP',
                   'SIGABRT', 'SIGEMT', 'SIGFPE', 'SIGKILL', 'SIGBUS',
                   'SIGSEGV', 'SIGSYS', 'SIGPIPE', 'SIGALRM', 'SIGTERM',
                   'SIGURG', 'SIGSTOP', 'SIGTSTP', 'SIGCONT', 'SIGCHLD',
                   'SIGTTIN', 'SIGTTOU', 'SIGIO', 'SIGXCPU', 'SIGXFSZ',
                   'SIGVTALRM', 'SIGPROF', 'SIGWINCH', 'SIGINFO', 'SIGUSR1',
                   'SIGUSR2']
        if isinstance(signal, basestring) and signal in signals:
            args.append(signal)
        elif isinstance(signal, int) and signal < 32:
            args.append(signal)
        else:
            return success

        #####
        # Service target, just check for string...
        if isinstance(serviceTarget, basestring):
            args.append(serviceTarget)
        else:
            return success

        args.append(serviceTarget)

        cmd = { "kill" : args }
        success, stdout, stderr, retcode = self.runSubCommand(cmd)

        return success

    #-------------------------------------------------------------------------

    def blame(self, serviceTarget):
        '''
        From the launchctl man page:
          blame service-target
              If the service is running, prints a human-readable string
              describing why launchd launched the service. Note that services
              may run for many reasons; this subcommand will only show the
              most proximate reason. So if a service was run due to a timer
              firing, this subcommand will print that reason, irrespective of
              whether there were messages waiting on the service's various
              endpoints. This subcommand is only intended for debugging and
              profiling use and its output should not be relied upon in pro-
              duction scenarios.

        @param: serviceTarget - See description below for details on
                this variable.
                
               system/[service-name]
                  Targets the system domain or a service within the system
                  domain. The system domain manages the root Mach bootstrap
                  and is considered a privileged execution context.
                  Anyone may read or query the system domain, but root privileges
                  are required to make modifications.

                user/<uid>/[service-name]
                  Targets the user domain for the given UID or a service
                  within that domain. A user domain may exist independently
                  of a logged-in user. User domains do not exist on iOS.

                For instance, when referring to a service with the identifier
                com.apple.example loaded into the GUI domain of a user with UID 501,
                domain-target is gui/501/, service-name is com.apple.example,
                and service-target is gui/501/com.apple.example.

        @author: Roy Nielsen
        '''
        success = False
        #####
        # Input validation.
        if not isinstance(serviceTarget, basestring):
            return success

        cmd = { "blame" : [serviceTarget] }
        success, stdout, stderr, retcode = self.runSubCommand(cmd)

        return success, stdout

    #-------------------------------------------------------------------------

    def printTarget(self, target):
        '''
        @note: From the launchctl man page:
          print domain-target | service-target
              Prints information about the specified service or domain.
              Domain output includes various properties about the domain as
              well as a list of services and endpoints in the domain with
              state pertaining to each. Service output includes various prop-
              erties of the service, including information about its origin
              on-disk, its current state, execution context, and last exit
              status.

              IMPORTANT: This output is NOT API in any sense at all. Do NOT
              rely on the structure or information emitted for ANY reason. It
              may change from release to release without warning.

        @author: Roy Nielsen
        '''
        success = False
        #####
        # Input validation.
        if not isinstance(target, basestring):
            return success

        # prepended system/ to service-target in order to hot fix multiple issues
        # with service detection in servicehelper two implementation
        # all rules calling new servicehelper must specify the service target context
        # and they all currently do not. system/ is where all system services run.
        # currently servicehelper two cannot look for user context services when
        # being run in admin mode anyway, so this is just a best-effort workaround
        # until servicehelper two can be redesigned or all the rules changed to 
        # prepend system/ in their servicehelper calls
        cmd = { "print" : ["system/" + target] }
        success, stdout, stderr, retcode = self.runSubCommand(cmd)

        if re.search("Could not find service", stderr) and re.search("in domain for system", stderr):
            success = False

        return success, stdout

    #-------------------------------------------------------------------------

    def printCache(self):
        '''
        @note: From the launchctl man page:
        print-cache
              Prints the contents of the launchd service cache.

        @author: Roy Nielsen
        '''
        success = False

        cmd = { "print-cache" : [] }
        success, stdout, stderr, retcode = self.runSubCommand(cmd)

        return success, stdout

    #-------------------------------------------------------------------------

    def printDisabled(self):
        '''
        @note: From the launchctl man page:
          print-disabled
              Prints the list of disabled services.

        @author: Roy Nielsen
        '''
        success = False

        cmd = { "print-disabled" : [] }
        success, stdout, stderr, retcode = self.runSubCommand(cmd)

        return success, stdout

    #-------------------------------------------------------------------------

    def procInfo(self, pid):
        '''
        @note: From the launchctl man page:
          procinfo pid
              Prints information about the execution context of the specified
              PID. This information includes Mach task-special ports and
              exception ports (and when run against a DEVELOPMENT launchd,
              what names the ports are advertised as in the Mach bootstrap
              namespace, if they are known to launchd) and audit session con-
              text. This subcommand is intended for diagnostic purposes only,
              and its output should not be relied upon in production scenar-
              ios. This command requires root privileges.

        @author: Roy Nielsen
        '''
        success = False
        #####
        # Input validation.
        if not isinstance(pid, int):
            return success

        cmd = { "procinfo" : [pid] }
        success, stdout, stderr, retcode = self.runSubCommand(cmd)

        return success, stdout

    #-------------------------------------------------------------------------

    def hostinfo(self):
        '''
        @note: From the launchctl man page:
          hostinfo
              Prints information about the system's host-special ports,
              including the host-exception port. This subcommand requires
              root privileges.

        @author: Roy Nielsen
        '''
        success = False

        cmd = { "hostinfo" : [] }
        success, stdout, stderr, retcode = self.runSubCommand(cmd)

        return success

    #-------------------------------------------------------------------------

    def resolvePort(self, ownerPid, portName):
        '''
        @note: From the launchctl man page:
          resolveport owner-pid port-name
              Given a PID and the name of a Mach port right in that process'
              port namespace, resolves that port to an endpoint name known to
              launchd.  This subcommand requires root privileges.

        @author: Roy Nielsen
        '''
        success = False
        #####
        # Input validation.
        if not isinstance(ownerPid, int) or not isinstance(portName, basestring):
            return success
        
        cmd = { "rsolveport" : [ownerPid, portName] }
        success, stdout, stderr, retcode = self.runSubCommand(cmd)

        return success

    #-------------------------------------------------------------------------

    def reboot(self, context, mountPoint, single=False):
        '''
        
        @note: From the launchctl man page:
          reboot [system|userspace|halt|logout|apps|reroot <mount-point>]
              Instructs launchd to begin tearing down userspace. With no
              argument given or with the system argument given, launchd will
              make the reboot(2) system call when userspace has been com-
              pletely torn down. With the halt argument given, launchd will
              make the reboot(2) system call when userspace has been com-
              pletely torn down and pass the RB_HALT flag, halting the system
              and not initiating a reboot.

              With the userspace argument given, launchd will re-exec itself
              when userspace has been torn down and bring userspace back up.
              This is useful for rebooting the system quickly under condi-
              tions where kernel data structures or hardware do not need to
              be re-initialized.

              With the reroot argument given, launchd will perform a
              userspace shutdown as with the userspace argument, but it will
              exec a copy of launchd from the specified mount-point.  This
              mechanism is a light-weight way of changing boot partitions. As
              part of this process, launchd will make mount-point the new
              root partition and bring userspace up as if the kernel had des-
              ignated mount-point as the root partition.

              IMPORTANT: This type of reboot will, in no way, affect the
              already-running kernel on the host. Therefore, when using this
              option to switch to another volume, you should only target vol-
              umes whose userspace stacks are compatible with the already-
              running kernel.

              NOTE: As of the date of this writing, this option does not com-
              pletely work.

              With the logout argument given, launchd will tear down the
              caller's GUI login session in a manner similar to a logout ini-
              tiated from the Apple menu. The key difference is that a logout
              initiated through this subcommand will be much faster since it
              will not give apps a chance to display modal dialogs to block
              logout indefinitely; therefore there is data corruption risk to
              using this option. Only use it when you know you have no
              unsaved data in your running apps.

              With the apps argument given, launchd will terminate all apps
              running in the caller's GUI login session that did not come
              from a launchd.plist(5) on-disk. Apps like Finder, Dock and
              SystemUIServer will be unaffected. Apps are terminated in the
              same manner as the logout argument, and all the same caveats
              apply.

              -s       When rebooting the machine (either a full reboot or
                       userspace reboot), brings the subsequent boot session
                       up in single-user mode.

        @author: Roy Nielsen
        '''
        success = False
        validContexts = ['System', 'users', 'halt', 'logout', 'apps', 'reroot']
        
        if not isinstance(context, basestring) or \
           not context in validContexts:
            return success
        if mountPoint and isinstance(mountPoint, basestring):
            cmd = { "reboot" : [context, mountPoint] }
        elif not mountPoint:
            cmd = { "reboot" : [context] }
        else:
            return success

        success, stdout, stderr, retcode = self.runSubCommand(cmd)

        return success
