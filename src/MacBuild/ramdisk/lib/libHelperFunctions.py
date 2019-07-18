"""
Helper functions, OS agnostic

@author: Roy Nielsen
"""

#--- Native python libraries
import re
import os
import sys
import time
import ctypes
import traceback
from subprocess import Popen, STDOUT, PIPE
try:
    import termios
except:
    pass

#--- non-native python libraries in this source tree
from . loggers import CyLogger
from . loggers import LogPriority as lp
from . run_commands import RunWith

logger = CyLogger()
run = RunWith(logger)

def getOsFamily():
    '''Get the os name from the "uname -s" command
    
    @author: Roy Nielsen


    '''

    operatingsystemfamily = sys.platform

    return operatingsystemfamily

###########################################################################

class FoundException(Exception) :
    '''Exeption to raise when the condition is met in a for/while
    
    Accompanying code (in collect_for_hostmaster.py) derived from example
    in "Rapid GUI Programming with Python and QT" pgs 66 - 71,
    by Mark Summerfeild
    
    For more examples on python user defined exceptions:
    http://docs.python.org/2/tutorial/errors.html


    '''
    pass

##############################################################################

def get_console_user():
    '''Get the user that owns the console on the Mac.  This user is the user that
    is logged in to the GUI.


    '''
    user = False

    cmd = ["/usr/bin/stat", "-f", "'%Su'", "/dev/console"]

    try:
        retval = Popen(cmd, stdout=PIPE, stderr=STDOUT).communicate()[0]
        space_stripped = str(retval).strip()
        quote_stripped = str(space_stripped).strip("'")

    except Exception as err:
        logger.log(lp.VERBOSE, "Exception trying to get the console user...")
        logger.log(lp.VERBOSE, "Associated exception: " + str(err))
        logger.log(lp.WARNING, traceback.format_exc())
        logger.log(lp.WARNING, str(err))
        raise err
    else:
        """
        LANL's environment has chosen the regex below as a valid match for
        usernames on the network.
        """
        if re.match("^[A-Za-z][A-Za-z1-9_]+$", quote_stripped):
            user = str(quote_stripped)
    logger.log(lp.VERBOSE, "user: " + str(user))
    
    return user

###########################################################################

def is_valid_pn(random_pn=0) :
    '''Validate that the property number is seven digits.
    
    @author: Roy Nielsen

    :param random_pn:  (Default value = 0)

    '''
    retval = True

    # Need to check for 7 decimal places
    if not re.match("^\d\d\d\d\d\d\d$", str(random_pn)):
        logger.log(lp.VERBOSE, "PN is not valid...")
        retval = False
    else:
        logger.log(lp.VERBOSE, "PN \"" + str(random_pn) + "\" is valid")

    return retval

###########################################################################

def get_darwin_mac() :
    '''Get the mac address and place it in net_hw_addr
    
    Future METHOD: Use the "ifconfig" command - look for the "active" interface
    - collect "interface", "mac", "ipaddr" to return.  PATH to ifconfig may be
    specific to the Mac.
    
    Description:   Runs the networksetup -listallhardwareports,
                   processing the output to get the network interface mac
                   address.  Specific to the Mac.
    
    @author: Roy Nielsen


    '''
    found = 0

    output = Popen(["/usr/sbin/networksetup", "-listallhardwareports"], stdout=PIPE, stderr=STDOUT).communicate()[0]

    try :
        for line in output.split("\n") :
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
    except Exception as err:
        logger.log(lp.VERBOSE, "Error attempting to acquire MAC address...")
        logger.log(lp.VERBOSE, "Exception: " + str(err))
        raise err
    else :
        net_hw_addr = "No MAC addr found"
        logger.log(lp.VERBOSE, "No MAC address found")

    return net_hw_addr

###########################################################################

def is_laptop():
    '''Determine if the machine this is currently running on is a laptop
    
    @author: Roy Nielsen


    '''
    isThisALaptop = False
    
    cmd = ["/usr/sbin/system_profiler", "SPHardwareDataType"]
    
    retval, reterr = Popen(cmd, stdout=PIPE, stderr=PIPE).communicate()
    
    if not reterr :
        if retval :
            for line in retval.split("\n") :
                if re.match("^\s+Model Name:", line) :
                    if re.search("[bB]ook", line) :
                        isThisALaptop = True
                        break
        else :
            logger.log(lp.VERBOSE, "Error processing system_profiler output...")
    else :
        logger.log(lp.VERBOSE, "Error processing system_profiler output: " + str(reterr))
    return isThisALaptop

###########################################################################

def touch(filename=""):
    '''Python implementation of the touch command..

    :param filename:  (Default value = "")

    '''
    if re.match("^\s*$", filename) :
        logger.log(lp.INFO, "Cannot touch a file without a filename....")
    else :
        try:
            os.utime(filename, None)
        except:
            try :
                open(filename, 'a').close()
            except Exception as err :
                logger.log(lp.INFO, "Cannot open to touch: " + str(filename))

###########################################################################

def installFdeUser(myusername="", mypassword="") :
    '''Create an input plist for the fdesetup command to enable a user in the
    filevault login screen
    
    @author: Roy Nielsen

    :param myusername:  (Default value = "")
    :param mypassword:  (Default value = "")

    '''
    success = False
    logger.log(lp.DEBUG, "Starting installFdeUser...")
    
    if re.match("^\s*$", myusername) :
        logger.log(lp.INFO, "Empty username: '" + str(myusername) + "'")

    elif re.match("^\s*$", mypassword) :
        logger.log(lp.INFO, "Empty password: '" + str(mypassword) + "'")
        
    if re.match("^\s*$", myusername) or re.match("^\s*$", mypassword) :
        logger.log(lp.INFO, "in buildInputPlist -- cannot build the plist with an empty username or password...")
        return success

    plist = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" + \
            "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n" + \
            "<plist version=\"1.0\">\n" + \
            "\t<dict>\n" + \
            "\t\t<key>Username</key>\n" + \
            "\t\t<string>" + str(myusername) + "</string>\n" + \
            "\t\t<key>Password</key>\n" + \
            "\t\t<string>" + str(mypassword) + "</string>\n" + \
            "\t</dict>\n</plist>"

    #####
    # Do the fdesetup command
    cmd = ["/usr/bin/fdesetup", "enable", "-outputplist", "-inputplist"]
    logger.log(lp.DEBUG, "Command: " + str(cmd))

    proc = Popen(cmd, stdin=PIPE, stdout=PIPE, stderr=PIPE)
    
    (retval, reterr) = proc.communicate(plist + "\n")
    
    logger.log(lp.DEBUG, "retval: " + str(retval))
    logger.log(lp.DEBUG, "reterr: " + str(reterr))

    if not reterr:
        success = True
    
    logger.log(lp.DEBUG, "Installed an Fde User...")
    return success

###########################################################################

def removeFdeUser(myusername=""):
    '''Remove a user from the FDE login screen
    
    @author: Roy Nielsen

    :param myusername:  (Default value = "")

    '''
    success = False
    if re.match("^\s+$", myusername) or not myusername:
        logger.log(lp.INFO, "Empty username: '" + str(myusername) + "'")
        return success
    cmd = ["/usr/bin/fdesetup", "remove", myusername]
    run.setCommand(cmd)
    run.communicate()
    if not run.getStderr():
        success = True
    return success

############################################################################

def touch(filename=""):
    '''Python implementation of the touch command..

    :param filename:  (Default value = "")

    '''
    if re.match("^\s*$", filename) :
        logger.log(lp.INFO, "Cannot touch a file without a filename....")
    else :
        try:
            os.utime(filename, None)
        except:
            try :
                open(filename, 'a').close()
            except Exception as err :
                logger.log(lp.INFO, "Cannot open to touch: " + str(filename))

###########################################################################

def getecho (fileDescriptor):
    '''This returns the terminal echo mode. This returns True if echo is
    on or False if echo is off. Child applications that are expecting you
    to enter a password often set ECHO False. See waitnoecho().
    
    Borrowed from pexpect - acceptable to license

    :param fileDescriptor: 

    '''
    attr = termios.tcgetattr(fileDescriptor)
    if attr[3] & termios.ECHO:
        return True
    return False

############################################################################

def waitnoecho (fileDescriptor, timeout=3):
    '''This waits until the terminal ECHO flag is set False. This returns
    True if the echo mode is off. This returns False if the ECHO flag was
    not set False before the timeout. This can be used to detect when the
    child is waiting for a password. Usually a child application will turn
    off echo mode when it is waiting for the user to enter a password. For
    example, instead of expecting the "password:" prompt you can wait for
    the child to set ECHO off::
    
        see below in runAsWithSudo
    
    If timeout is None or negative, then this method to block forever until
    ECHO flag is False.
    
    Borrowed from pexpect - acceptable to license

    :param fileDescriptor: 
    :param timeout:  (Default value = 3)

    '''
    if timeout is not None and timeout > 0:
        end_time = time.time() + timeout
    while True:
        if not getecho(fileDescriptor):
            return True
        if timeout < 0 and timeout is not None:
            return False
        if timeout is not None:
            timeout = end_time - time.time()
        time.sleep(0.1)

###########################################################################

def isSaneFilePath(filepath):
    '''Check for a good file path in the passed in string.
    
    @author: Roy Nielsen

    :param filepath: 

    '''
    sane = False
    if filepath and isinstance(filepath, str):
        if re.match("^[A-Za-z0-9_\-/\.]*", filepath):
            sane = True
    return sane

###########################################################################

