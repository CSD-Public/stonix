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
import getpass
from optparse import OptionParser
from subprocess import Popen, STDOUT, PIPE

#####
# import PyQt libraries
from PyQt4.QtGui import QApplication

#####
# Import class that manages the gui
from general_warning import GeneralWarning
from stonix_wrapper import StonixWrapper
from log_message import log_message
from darwin_funcs import isUserOnSystem, getResourcesDir, getOsVers
from run_commands import exec_subproc_stdout
from program_arguments import ProgramArguments

if __name__ == "__main__" :
    """
    Main program

    Author: Roy Nielsen
    """
    message_level = "normal"
    prog_args = ProgramArguments()
    arguments = prog_args.getArgs()

    #####
    # Put something like stonix.py's processargs() functionality here.
    # Best possible thing is to put all the args stonix uses into
    # a list, then " ".join(args) when calling stonix...
    
    message_level = prog_args.get_msg_lvl()
    
    log_message("Message level is: " + message_level, "debug", message_level)

    myuid = os.getuid()
    user = getpass.getuser()
    os_vers = getOsVers(message_level).rstrip()
    #####
    # get the path to a link that links to the 
    # stonix.app/Contents/Resources/stonix binary blob compiled by 
    # pyinstaller
    stonixFullPath = os.path.join(getResourcesDir().strip("\""), "stonix.app/Contents/MacOS/stonix")

    stonixfp = [stonixFullPath]

    if not arguments:
        cmd = stonixfp +["-G"]
    else:
        cmd = stonixfp + arguments

    log_message("Command build: " + str(cmd))

    log_message("#==--- Initializing stonix4mac.app with UID %d ---==#"%myuid, \
                "normal", message_level)
    
    log_message("Message level is: " + str(message_level), "verbose", message_level)

    if myuid == 0 :
        #####
        # We are already root, just run stonix...
        log_message("Already root, running stonix with root privilege...", \
                    "normal", message_level)
        
        
        #####
        # Only spawn a process when using the GUI (no cli)
        if not prog_args.opts.cli:
    
            child_pid = os.fork()
            if child_pid == 0 :
                print "Child Process: PID# %s" % os.getpid()
    
            else:
                print "Exiting parent process: PID# %s" % os.getpid()
                sys.exit(254)
        #####
        # sleep to make sure there aren't two versions of stonix running
        # time.sleep(4)
        #####
        
        # Make the call to run stonix
        log_message("Attempting to run command: " + str(cmd))
        Popen(cmd, stdout=PIPE, stderr=STDOUT).communicate()
            
    else :
        #####
        # Only spawn a process when using the GUI (no cli)
        if not prog_args.opts.cli:
            app = QApplication(sys.argv)
            
            log_message("OS Version: \"" + str(os_vers).strip() + "\"")
            
            minver = re.search("^10\.(\d+)\.\d+$", str(os_vers))
            try:
               minor_version = int(minver.group(1).rstrip())
            except Exception, err:
               log_message("Error trying to get minor version: " + str(err))
               log_message("Trying 2 number version...")
               try:
                    minver = re.search("^10\.(\d+)", str(os_vers))
                    minor_version = int(minver.group(1).rstrip())
               except Exception, err:
                   log_message("Having trouble acquiring minor version: " + str(err))
                   raise err
            
            log_message("minor version: \"" + str(minor_version) + "\"")
            
            if minor_version <= 10:
                    """
                    Log and go to the next check..
                    """
                    log_message("Valid operating system, continuing...", "normal", message_level)
                    stonix_wrapper = StonixWrapper(arguments, message_level)
                    stonix_wrapper.show()
                    stonix_wrapper.raise_()
    
            else :
                """
                Warn that the app is not running on 10.9 or 10.8
                """
                log_message("Setting up Check for 10.9 and 10.8 warning dialog...", \
                            "normal", message_level)
                
                warningMessage = "<h2>Warning:</h2>" + \
                "<center>Requires Mountain Lion (10.8) or Mavericks (10.9)," + \
                "<br><br>Cannot run on: " + str(os_vers) + \
                "<br><br>Exiting program.</center>"
                
                notMountainLion = GeneralWarning()
                notMountainLion.setWarningMessage(warningMessage)
                notMountainLion.setWindowTitle("Requires 10.8")
                notMountainLion.setOpenExternalLinks()
                notMountainLion.show()
                notMountainLion.raise_()
            
                log_message("Finished setting up Check for 10.8 warning dialog...", \
                            "normal", message_level)
            app.exec_()    
        else:
            #####
            # Run in CLI mode, pass in the command line arguments...
            if re.match("10.9", str(os_vers)) or re.match("10.8", str(os_vers)):
                #####
                # Set up the command
                # cmd = stonixFullPath + " " + " ".join(arguments)
                #####
                # Make the call to run stonix
                # exec_subproc_stdout(cmd, "", message_level)
                # Make the call to run stonix
                log_message("Attempting to run command: " + str(cmd))
                Popen(cmd, stdout=PIPE, stderr=STDOUT).communicate()
            else:
                log_message("*************************************************", "normal", message_level)
                log_message("*** Cannot runn on this platform ****************", "normal", message_level)
                log_message("*** Needs to run on 10.8 or 10.9 ****************")
                log_message("*************************************************", "normal", message_level)
                    
    log_message("#==--- Exiting stonix4mac.app ---==#", "normal", message_level)

