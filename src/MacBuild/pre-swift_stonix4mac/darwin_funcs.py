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
from run_commands import runWithTimeout, system_call_retval

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


def isUserOnLocalSystem(user="", message_level="normal") :
    """
    Check if the passed in user is a local user on the system
    
    Author: Roy Nielsen
    """
    is_user_on_local_system = False

    #####
    # If the passed in user is empty or only spaces, return false.
    if re.match("^\s*$", user) :
        return is_user_on_local_system
    
    #####
    # Get valid users on the system, put them in a list
    cmd = ["/usr/bin/dscl", ".", "list", "/users"]
    
    (retval, reterr) = system_call_retval(cmd, message_level)
    
    systemUserList = retval.split("\n")
    
    validSystemUserList = []
    
    for systemUser in systemUserList :
        if not re.match("^_.*", systemUser) and \
           not re.match("^root$", systemUser) and \
           not re.match("^nobody$", systemUser) and \
           not re.match("^daemon$", systemUser) and \
           not re.match("^\s*$", systemUser) :
            log_message("Valid System User: " + systemUser, "debug", message_level)
            validSystemUserList.append(systemUser)

    #####
    # Check if the passed in user is a valid local user on the system
    for systemUser in validSystemUserList :
        if re.match("^%s$"%(systemUser), user) :
            is_user_on_local_system = True
            log_message("User: \"" + str(user) + "\" found on the system", "debug", message_level)
            break

    log_message("ivar = " + str(is_user_on_local_system), "debug", message_level)
    return is_user_on_local_system


def isUserOnSystem(user="", message_level="normal") :
    """
    Check if the passed in user is a local user on the system
    
    Author: Roy Nielsen
    """
    is_user_on_local_system = False

    #####
    # If the passed in user is empty or only spaces, return false.
    if re.match("^\s*$", user) :
        return is_user_on_local_system
    
    #####
    # Get valid users on the system, put them in a list
    cmd = ["/usr/bin/dscl", "/Search", "list", "/Users"]
    
    (retval, reterr) = system_call_retval(cmd, message_level)
    
    systemUserList = retval.split("\n")

    validSystemUserList = []
    
    for systemUser in systemUserList :
        if not re.match("^_.*", systemUser) and \
           not re.match("^root$", systemUser) and \
           not re.match("^nobody$", systemUser) and \
           not re.match("^daemon$", systemUser) and \
           not re.match("^\s*$", systemUser) :
            log_message("Valid System User: " + systemUser, "debug", message_level)
            validSystemUserList.append(systemUser)

    #####
    # Check if the passed in user is a valid local user on the system
    for systemUser in validSystemUserList :
        if re.match("^%s$"%(systemUser), user) :
            is_user_on_local_system = True
            log_message("User: \"" + str(user) + "\" found on the system", "debug", message_level)
            break

    log_message("ivar = " + str(is_user_on_local_system), "debug", message_level)
    return is_user_on_local_system


def isFilevaultActive(message_level="normal") :
    """
    Determine if Filevault is active or not
    
    Author: Roy Nielsen
    """
    is_filevault_active = False
    
    cmd = ["/usr/bin/fdesetup", "status"]
    
    (retval, reterr) = system_call_retval(cmd, message_level)

    if re.search("On", str(retval)) :
        is_filevault_active = True
    elif re.search("Off", str(retval)) :
        is_filevault_active = False
    else :
        is_filevault_active = False
        
    return is_filevault_active


def doesRestorePartitionExist(message_level="normal") :
    """
    Checks for the existence of the restore partition
    
    Author: Roy Nielsen
    """
    log_message("Start checking for restore partition...", "debug", message_level)
    doesItExist = False
    
    #####
    # Get valid users on the system, put them in a list
    cmd = ["/usr/sbin/diskutil", "list", "/dev/disk0"]
    
    (retval, reterr) = system_call_retval(cmd, message_level)
    
    partitions = retval.split("\n")
    
    for partition in partitions :
        print partition
        if re.match("^\s+\S+\s+\S+\s+Recovery HD\s+\S+\s+\S+\s+\S+", partition) :
            doesItExist = True
            break
        else :
            continue
    log_message("Finishing check for restore parition with: " + str(doesItExist), "debug", message_level)
    return doesItExist


def getOsVers() :
    """
    Get the version of OS X
    
    Author: Roy Nielsen
    """
    message_level = 'debug'
    cmd_string = ["/usr/bin/sw_vers", "-productVersion"]
    
    (os_vers, os_vers_err) = system_call_retval(cmd_string, message_level)
    
    if os_vers :
        return os_vers
    else :
        return False


def checkIfUserIsLocalAdmin(user="", message_level="normal") :
    """
    Check the local directory and see if a user is a local admin on the system.

    command:
    dscl . read /Groups/admin GroupMembership
    
    above command returns:
    GroupMembership: root rsn
    
    Author: Roy Nielsen
    """

    userFound = False

    if not re.match("^\s*$", username) :

        dsclCommand = ["/usr/bin/dscl", ".", "read", "/Groups/admin", "GroupMembership"]

        log_message("About to run command: " + " ".join(dsclCommand), "debug", message_level)

        (retval, reterr) = system_call_retval(dsclCommand, message_level)
        
        #print "Retval: \"" + retval + "\""
        
        if retval :
            users = retval.split()[1:]
            #print str(users)
            for user in users :
                if re.match("^%s$"%user, username) :
                    userFound = True
                    break

    return userFound


def checkIfUserIsAdmin(user="", message_level="normal") :
    """
    Check if the passed in user is in the admin group - local or directory 
    service.  The Admin group is group 80 on the Mac.
    
    @author: Roy Nielsen
    """
    if re.match("^\s*$", user) :
        message = "Cannot check the group of a user string that is empty..."
        log_message(message, "normal", message_level)
        log_message("user: \"" + str(user) + "\"", "normal", message_level )
        found = False
    else: 
        found = False
        retval = False
        #####
        # Looking for user in local directory as well as all attached 
        # directory services
        cmd = ["/usr/bin/dscl", "/Search", "-read", "/Groups/admin", "GroupMembership"]

        #retval, reterr = Popen(cmd, stdout=PIPE, stderr=PIPE).communicate()

        (retcode, retval, reterr, didTimeOut) = runWithTimeout(cmd, 15)
        
        if didTimeOut :
            cmd = ["/usr/bin/dscl", ".", "-read", "/Groups/admin", "GroupMembership"]
            (retcode, retval, reterr, didTimeOut) = runWithTimout(cmd, 15)
        
        if retval :
            lines = retval.split("\n")
            users = []
            for line in lines :
                #print "Line: " + str(line)
                if re.match("^GroupMembership:\s+", line) :
                    members = line.split()[1:]
                    for member in members :
                        users.append(member)
                        
            #####
            # Find unique members of the list
            users = list(set(users))
            
            #####
            # Search the list for the passed in user
            for member in users :
                if re.match("^%s$"%user.strip(),  member.strip()) :
                    #print "found... user: " + user + " = " + member
                    found = True
                    break
                else :
                    found = False
    return found

##############################################################################

def getConsoleUserLoginWindowId():
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

