"""
Helper functions using MacOS specific methods.

@author: Roy Nielsen
"""
from __future__ import absolute_import
#--- Native python libraries
import os
import re
import sys
import platform

#--- non-native python libraries in this source tree
from run_commands import RunWith
from loggers import CyLogger
from loggers import LogPriority as lp

logger = CyLogger()
run = RunWith(logger)

###########################################################################

class FoundException(Exception) :
    """
    Exeption to raise when the condition is met in a for/while

    Accompanying code (in collect_for_hostmaster.py) derived from example
    in "Rapid GUI Programming with Python and QT" pgs 66 - 71,
    by Mark Summerfeild

    For more examples on python user defined exceptions:
    http://docs.python.org/2/tutorial/errors.html
    """
    pass

###########################################################################

def get_os_vers() :
    """
    Get the version of OS X
    
    @author: Roy Nielsen
    """
    os_vers = platform.mac_ver()[0] 
    if os_vers :
        return os_vers
    else :
        return -1

###########################################################################

def get_os_minor_vers() :
    """
    return the minor version of the OS.
    """
    minor_vers = -1
    os_vers = get_os_vers()
    if os_vers:
        re_vers = re.search("^10.(\d+).*", os_vers)
        if re_vers:
            minor_vers = re_vers.group(1)
        else :
            logger.log(lp.INFO, "No valid minor version found...")
    else :
        logger.log(lp.INFO, "Didn't get a valid os version...")

    return minor_vers

###########################################################################

def get_darwin_mac() :
    """
    Get the mac address and place it in net_hw_addr 

    Future METHOD: Use the "ifconfig" command - look for the "active" interface
    - collect "interface", "mac", "ipaddr" to return.  PATH to ifconfig may be
    specific to the Mac.

    Description:   Runs the networksetup -listallhardwareports,
                   processing the output to get the network interface mac
                   address.  Specific to the Mac.

    @author: Roy Nielsen
    """
    found = 0

    cmd = ["/usr/sbin/networksetup", "-listallhardwareports"]

    run.setCommand(cmd)
    run.communicate()
    retval, reterr, retcode = run.getNlogReturns()

    try :
        for line in retval.split("\n") :
            match_hw_addr = re.compile \
            ("^Ethernet Address:\s+(\w+:\w+:\w+:\w+:\w+:\w+)\s*$")

            if re.match("^Device:\s+(\w+)\s*$", line) :
                found = 1
            if re.match \
              ("^Ethernet Address:\s+(\w+:\w+:\w+:\w+:\w+:\w+)\s*$", \
              line) and found == 1 :
                raise FoundException
    except FoundException :
        hw_addr = match_hw_addr.search(line)
        net_hw_addr = hw_addr.group(1)
        #  net_hw_addr
    except Exception, err:
        logger.log(lp.VERBOSE, "Error attempting to acquire MAC address...")
        logger.log(lp.VERBOSE, "Exception: " + str(err))
        raise err
    else :
        net_hw_addr = "No MAC addr found"
        logger.log(lp.VERBOSE, "No MAC address found")

    return net_hw_addr

###########################################################################

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

    # Append "Resources" & "cmu" to the end of the list
    parents.append("Resources")

    # Join up the directory with slashes
    resource_dir = "/".join(parents)

    return resource_dir

###########################################################################

def getMacOSDir() :
    """
    Get the full path to the Resources directory of the current app

    Author: Roy Nielsen
    """
    # Gets the <app-path>/Contents/MacOS full path
    selfdir = os.path.abspath(os.path.join(os.path.dirname(sys.argv[0])))
    macos_dir = ""

    parents = selfdir.split("/")

    # Remove the "MacOS" dir from the list
    parents.pop()

    # Append "Resources" & "cmu" to the end of the list
    parents.append("MacOS")

    # Join up the directory with slashes
    macos_dir = "/".join(parents) + "/"

    return macos_dir

###########################################################################

def get_script() :
    """
    """
    return os.path.abspath(sys.argv[0])

###########################################################################

def is_laptop() :
    """
    Determine if the machine this is currently running on is a laptop

    @author: Roy Nielsen
    """
    isThisALaptop = False

    cmd = ["/usr/sbin/system_profiler", "SPHardwareDataType"]

    run.setCommand(cmd)
    run.communicate()
    retval, reterr, retcode = run.getNlogReturns()

    if not reterr:
        if retval:
            for line in retval.split("\n") :
                if re.match("^\s+Model Name:", line):
                    if re.search("[bB]ook", line):
                        isThisALaptop = True
                        break
        else :
            logger.log(lp.VERBOSE, "Error processing system_profiler output...")
    else :
        logger.log(lp.VERBOSE, "Error processing system_profiler output: " + str(reterr))
    return isThisALaptop

###########################################################################

def checkIfUserIsLocalAdmin(username="", message_level="normal") :
    """
    Check the local directory and see if a user is an admin on the system.

    command:
    dscl . read /Groups/admin GroupMembership

    above command returns:
    GroupMembership: root rsn

    Author: Roy Nielsen
    """

    userFound = False

    if not re.match("^\s*$", username) :

        cmd = ["/usr/bin/dscl", ".", "read", "/Groups/admin", "GroupMembership"]

        logger.log(lp.VERBOSE, "About to run command: " + " ".join(cmd))

        run.setCommand(cmd)
        run.communicate()
        retval, reterr, retcode = run.getNlogReturns()

        if retval:
            users = retval.split()[1:]
            #print str(users)
            for user in users :
                if re.match("^%s$"%user, username) :
                    userFound = True
                    break

    return userFound
