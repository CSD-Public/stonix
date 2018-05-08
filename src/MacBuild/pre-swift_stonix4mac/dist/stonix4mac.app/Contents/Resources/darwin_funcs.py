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
#               Filename          $RCSfile: darwin_funcs.py,v $
#               Description       Library of useful functions, Mac specific
#               OS                Mac OS X
#               Author            Roy Nielsen
#               Last updated by   $Author: $
#               Notes             
#               Release           $Revision: 1.0 $
#               Modified Date     $Date:  $
# ============================================================================ #
from __future__ import absolute_import
import os
import re
import pty
import sys
import stat
import time
import types
import shutil
import select
import inspect
import termios
from threading import Timer
from subprocess import call, Popen, PIPE, STDOUT

#####
# import local libraries
from log_message import log_message
from run_commands import RunWith 

def getResourcesDir() :
    """ 
    Get the full path to the Resources directory of the current app 
    
    Author: Roy Nielsen
    """
    # Gets the <app-path>/Contents/MacOS full path
    selfdir = os.path.abspath(os.path.join(os.path.dirname(sys.argv[0])))
    resource_dir = ""

    parents = selfdir.split("/")

    # Remove the "MacOS" dir from the list
    parents.pop()

    # Append "Contents" & "cmu" to the end of the list
    #parents.append("Contents")
    
    # Append "Resources" & "cmu" to the end of the list
    parents.append("Resources")
    
    # Join up the directory with slashes
    resource_dir = "/".join(parents)

    log_message("resources dir: " + str(resource_dir))

    return resource_dir


def getMacOSDir() :
    """ 
    Get the full path to the Resources directory of the current app 
    
    Author: Roy Nielsen
    """
    # Gets the <app-path>/Contents/MacOS full path
    selfdir = os.path.abspath(os.path.join(os.path.dirname(sys.argv[0])))
    resource_dir = ""

    parents = selfdir.split("/")

    # Remove the "MacOS" dir from the list
    parents.pop()

    # Append "Resources" & "cmu" to the end of the list
    parents.append("MacOS")
    
    # Join up the directory with slashes
    resource_dir = "/".join(parents) + "/"

    return resource_dir


##############################################################################

def getConsoleUserLoginWindowName():
    """
    Get the user that owns the console on the Mac.  This user is the user that
    is logged in to the GUI.
    """
    user = False

    cmd = ["/usr/bin/stat", "-f", "'%Su'", "/dev/console"]

    try:
        retval = Popen(cmd, stdout=PIPE, stderr=STDOUT).communicate()[0]
        space_stripped = str(retval).strip()
        quote_stripped = str(space_stripped).strip("'")

    except Exception, err:
        #logger.log(lp.VERBOSE, "Exception trying to get the console user...")
        #logger.log(lp.VERBOSE, "Associated exception: " + str(err))
        raise err
    else:
        """
        LANL's environment has chosen the regex below as a valid match for
        usernames on the network.
        """
        if re.match("^[A-Za-z][A-Za-z1-9_]+$", quote_stripped):
            user = str(quote_stripped)
    #logger.log(lp.VERBOSE, "user: " + str(user))
    
    return user

###########################################################################

