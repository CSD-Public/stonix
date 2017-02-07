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

# ============================================================================ #
#               Filename          $RCSfile: stonix4mac.py,v $
#               Description       Controller for GUI that calls stonix.app
#                                 differently based on current privileges,
#                                 and if the user wants to elevate with a 
#                                 valid admin account and run stonix.app.
#               OS                Mac OS X
#               Author            Roy Nielsen
#               Last updated by   $Author: $
#               Notes             
#               Release           $Revision: 1.0 $
#               Modified Date     $Date:  $
# ============================================================================ #

#####
# importing standard libraries
import os
import re
import sys
import time
#import signal
import getpass
import platform
from optparse import OptionParser
from subprocess import Popen, STDOUT, PIPE

#####
# import PyQt libraries
from PyQt5 import QtGui, QtWidgets, QtCore

#####
# Import class that manages the gui
from general_warning import GeneralWarning
from stonix_wrapper import StonixWrapper
from log_message import log_message
from darwin_funcs import isUserOnSystem, getResourcesDir, getOsVers
from run_commands import exec_subproc_stdout
from program_arguments import ProgramArguments
from lib.manage_user.manage_user import ManageUser 
from lib.environment import Environment
from lib.loggers import CyLogger
from lib.loggers import LogPriority as lp

if __name__ == "__main__" :
    """
    Main program

    Author: Roy Nielsen
    """
    #signal.signal(signal.SIGINT, signal.SIG_DFL)
    message_level = "debug"
    prog_args = ProgramArguments()
    arguments = prog_args.getArgs()
    environ = Environment()
    lowest_supported_version = "10.10"
    #####
    # Put something like stonix.py's processargs() functionality here.
    # Best possible thing is to put all the args stonix uses into
    # a list, then " ".join(args) when calling stonix...
    
    message_level = prog_args.get_msg_lvl()
    
    log_message("Message level is: " + message_level, "debug", message_level)


    #####
    # Manage User Info
    logger = CyLogger(debug_mode=True)
    logger.initializeLogs()
    mu = ManageUser(logger=logger)

    myuid = os.getuid()
    user = getpass.getuser()

    #####
    # Check the OS version to see if it meets minimum requirements

    # Get the current OS information
    os_vers = environ.getosver()
    try:
        min_vers = os_vers.split('.')[1]
    except IndexError:
        self.logger.log(lp.INFO, "Index error attempting to get OS version...")
    # use the predefined OS lower limit 'minor' number
    try:
        min_version_supported = lowest_supported_version.split('.')[1]
    except IndexError:
        pass
    # initialize supported_os to false
    supported_os = False
    # Do a check to see if the system meets the minimum standard OS.
    if not min_vers >= min_version_supported:
        logger.log(lp.VERBOSE, "This OS (" + str(os_vers) + ") is not supported.")
    else:
        supported_os = True

    #####
    # get the path to a link that links to the 
    # stonix.app/Contents/Resources/stonix binary blob compiled by 
    # pyinstaller
    stonixFullPath = os.path.join(getResourcesDir(), "stonix.app/Contents/MacOS/stonix")

    stonixfp = [stonixFullPath]

    if not arguments:
        cmd = stonixfp + ["-G"]
    else:
        cmd = stonixfp + arguments

    logger.log(lp.DEBUG, "Command built: " + str(cmd))

    logger.log(lp.DEBUG, "#==--- Initializing stonix4mac.app with UID %d ---==#"%myuid)
    
    logger.log(lp.DEBUG, "Message level is: " + str(message_level))
    logger.log(lp.DEBUG, "OS is: " + str(os_vers))
    logger.log(lp.DEBUG, "Supported OS: " + str(supported_os))

    if myuid == 0 and supported_os:
        #####
        # We are already root, just run stonix...
        logger.log(lp.DEBUG, "Already root, running stonix with root privilege...")
        
        #####
        # Only spawn a process when using the GUI (no cli)
        if not prog_args.opts.cli:
    
            child_pid = os.fork()
            if child_pid == 0 :
                logger.log(lp.DEBUG, "Child Process: PID# %s" % os.getpid())
            else:
                print "Exiting parent process: PID# %s" % os.getpid()
                sys.exit(0)
        #####
        # sleep to make sure there aren't two versions of stonix running
        # time.sleep(4)
        #####
        
        # Make the call to run stonix
        logger.log(lp.DEBUG, "Attempting to run command: " + str(cmd))
        Popen(cmd, stdout=PIPE, stderr=STDOUT).communicate()

    else:
        #####
        # Only spawn a process when using the GUI (no cli)
        if not prog_args.opts.cli:
            app = QtWidgets.QApplication(sys.argv)
            
            if supported_os:
                """
                Log and go to the next check..
                """
                log_message("Valid operating system, continuing...", "normal", message_level)
                stonix_wrapper = StonixWrapper(arguments, message_level)
                stonix_wrapper.show()
                stonix_wrapper.raise_()
            else:
                """
                Warn that the app is not running on 10.10 or above
                """
                logger.log(lp.DEBUG, "Setting up Check for unsupported OS warning dialog...")
                
                warningMessage = "<h2>Warning:</h2>" + \
                "<center>Requires an IA supported operating system," + \
                "<br><br>Cannot run on: " + str(os_vers) + \
                "<br><br>Exiting program.</center>"
                
                notSupportedOS = GeneralWarning()
                notSupportedOS.setWarningMessage(warningMessage)
                notSupportedOS.setWindowTitle("Requires an IA supported operating system.")
                notSupportedOS.setOpenExternalLinks()
                notSupportedOS.show()
                notSupportedOS.raise_()
            
                log_message("Finished setting up Check for supported OS warning dialog...", \
                            "normal", message_level)
            sys.exit(app.exec_())
            #app.quit()
        else:
            #####
            # Run in CLI mode, pass in the command line arguments...
            if supported_os:
                #####
                # Set up the command
                cmd = stonixFullPath + arguments
                #####
                # Make the call to run stonix
                # exec_subproc_stdout(cmd, "", message_level)
                # Make the call to run stonix
                logger.log(lp.DEBUG, "Attempting to run command: " + str(cmd))
                Popen(cmd, stdout=PIPE, stderr=STDOUT).communicate()
            else:
                logger.log(lp.DEBUG, "*************************************************")
                logger.log(lp.DEBUG, "*** Cannot run on this platform ****************")
                logger.log(lp.DEBUG, "*** Needs to run on supported OS ****************")
                logger.log(lp.DEBUG, "*************************************************")
                    
    logger.log(lp.DEBUG, "#==--- Exiting stonix4mac.app ---==#")
