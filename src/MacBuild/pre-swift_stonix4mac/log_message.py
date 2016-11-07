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
#               Filename          $RCSfile: log_message.py,v $
#               Description       Logging for any OS that has the generic *nix 
#                                 "logger" command.
#               OS                Linux, Mac OS X, Solaris, BSD
#               Author            Roy Nielsen
#               Last updated by   $Author: $
#               Notes             
#               Release           $Revision: 1.0 $
#               Modified Date     $Date:  $
# ============================================================================ #

import re
import sys
import inspect

from subprocess import call

def log_message(message="", level="normal", priority="debug", syslog_level=None) :
    """
    Logs a message to both stdout and to syslog via logger

    message - the message to log
    
    level - print the message if this value is less than or equal to
            the \"priority\" 
    
    priority - defined value to used to compare with the \"level\".  If 
               the level is less than or equal to the priority value,
               the message will be printed to stdout and via logger
    
    syslog_level - the syslog level to log with

    Author: Roy Nielsen
    """
    if syslog_level is None :
        syslog_level = ""
    else :
        syslog_level = "-p " + syslog_level + " "

    if not re.match("^normal$", level) :
        prog = sys.argv[0]
        # message to be in the format: 
        # <calling_script_name> : <name_of_calling_function> (<line number of calling function>) - <LEVEL>: <message to print>
        message = str(prog) + " : " + \
        inspect.stack()[1][3] + " (" + str(inspect.stack()[1][2]) + ") - " + \
        level.upper() + ": " + str(message)
    else :
        prog = sys.argv[0]
        message = str(prog) + " - " + inspect.stack()[1][3] + \
        " (" + str(inspect.stack()[1][2]) + ") - " + " : " + str(message)
    
    levels = ['quiet', 'normal', 'verbose', 'debug']
    
    if levels.index(level) <= levels.index(priority) :

        print message
        cmd_string = "/usr/bin/logger " + syslog_level + "\"" + message +"\""
        retcode = ""
        try :
            retcode = call(cmd_string, shell=True)
            if retcode < 0 :
                print >> sys.stderr, \
                         "logger Child was terminated by signal", \
                        -retcode
            else :
                pass

        except OSError, err :
            print >> sys.stderr, \
                     "Execution of " + \
                     str(cmd_string) + \
                     " failed: ", \
                     err        


