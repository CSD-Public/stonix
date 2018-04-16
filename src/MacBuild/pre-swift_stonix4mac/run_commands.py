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
#               Filename          $RCSfile: run_commands.py,v $
#               Description       Generic functions to run commands with current,
#                                 other or admin user and with elevated privilege.
#               OS                Linux, Mac OS X, Solaris, BSD
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
import threading

from log_message import log_message
from subprocess import call, Popen, PIPE, STDOUT

def system_call_retval(cmd="", message_level="normal", myshell=False) :
    """
    Use the subprocess module to execute a command, returning
    the output of the command
    
    Author: Roy Nielsen
    """
    retval = ""
    reterr = ""
#    mycmd = cmd.split()
    if isinstance(cmd, types.ListType) :
        printcmd = " ".join(cmd)
    if isinstance(cmd, types.StringTypes) :
        printcmd = cmd
    
    try :
        if myshell == False :
            pipe = Popen(cmd, stdout=PIPE, stderr=PIPE)
        elif myshell == True :
            pipe = Popen(cmd, stdout=PIPE, stderr=PIPE, shell=myshell)
        else :
            pipe = Popen(cmd, stdout=PIPE, stderr=PIPE)
        
        (stdout_out, stderr_out) = pipe.communicate()

        if stdout_out :
            for line in stdout_out : 
                if line is not None :
                    line.strip("\n")
                    retval = retval + line

        if stderr_out :
            for line in stderr_out : 
                if line is not None :
                    line.strip("\n")
                    reterr = reterr + line            
            
    except ValueError, err :
        log_message("system_call_retval - ValueError: " + str(err) + " command: " + printcmd, "normal", message_level)
    except OSError, err :
        log_message("system_call_retval - OSError: " + str(err) + " command: " + printcmd, "normal", message_level)
    except IOError, err :
        log_message("system_call_retval - IOError: " + str(err) + " command: " + printcmd, "normal", message_level)
    except Exception, err :
        log_message("system_call_retval - Unexpected Exception: "  + str(err)  + " command: " + printcmd, "normal", message_level)
    else :
        log_message(printcmd + \
                    " Returned with error/returncode: " + \
                    str(pipe.returncode), \
                    "debug", \
                    message_level)
        pipe.stdout.close()
    finally:
        log_message("Done with command: " + printcmd, \
                    "verbose", \
                    message_level)
    return (retval, reterr)
        

def exec_subproc_stdout(cmd="", chk_string="", message_level="normal") :
    """
    Use the subprocess module to execute a command, sending output out
    immediately.
    """
    
    if isinstance(cmd, basestring) : 
        
        mycmd = []
        tmpcmd = cmd.split(" ")
        found_arg_with_spaces = 0
        full_arg = ""
    
        # rebuild the command if there are "\"'s escaping spaces in the command
        # -- specifically for filenames...
        slash = re.compile(r'\\$')
        for arg in tmpcmd :
            if slash.search(arg) :
                #print "FOUND CONTINUATION"
                # split up differently... as per file with spaces in the name
                if found_arg_with_spaces == 0 :
                    full_arg += arg.strip("\\")
                else :
                    full_arg += " " + arg.strip("\\")
                found_arg_with_spaces = 1
            elif found_arg_with_spaces :
                # print "found arg with spaces -- resetting...."
                full_arg += " " + arg.strip("\\")
                found_arg_with_spaces = 0
                mycmd.append(full_arg)
                full_arg = ""
            else :
                #print "Appending..."
                mycmd.append(arg)

    elif isinstance(cmd, list) :
            mycmd = cmd

    try :
        pipe = Popen(mycmd, stdout=PIPE, stderr=STDOUT)
        
        if pipe :
            while True:
                myout = pipe.stdout.readline()
                if myout == '' and pipe.poll() != None: 
                    break
                tmpline = myout.strip("\n")
                print tmpline

                if isinstance(chk_string, str) :
                    if not chk_string:
                        continue
                    else:
                        if chk_string(chk_string, tmpline):
                            wait_for_done(mycmd[0], message_level)
                            pipe.stdout.close()
                            exec_subproc_stdout(" ".join(mycmd), chk_string, message_level)
                elif isinstance(chk_string, list) :
                    if not chk_string:
                        continue
                    else:
                        for mystring in chk_string :
                            if chk_string(mystring, tmpline):
                                wait_for_done(mycmd[0], message_level)
                                pipe.stdout.close()
                                exec_subproc_stdout(" ".join(mycmd), chk_string, message_level)
                        
        pipe.wait()
        pipe.stdout.close()

    except ValueError, err :
        log_message("ValueError: " + str(err), "normal", message_level)
    except OSError, err :
        log_message("OSError: " + str(err) + str(mycmd), \
                    "normal", \
                    message_level)
    except IOError, err :
        log_message("IOError: " + str(err), "normal", message_level)
    except Exception, err :
        log_message("Unexpected Exception: "  + str(err), "normal", message_level)
    else :
        log_message("".join(cmd) + \
                    "Returned with error/returncode: " + \
                    str(pipe.returncode), \
                    "debug", \
                    message_level)
        pipe.stdout.close()
    finally:
        log_message("Done with command: " + "".join(cmd), \
                    "verbose", \
                    message_level)
        print 
        
        
def runWithWaitTillFinished(command=[], message_level="normal") :
    """
    Use subprocess to call a command and wait until it is finished before
    moving on...
    
    @author: Roy Nielsen
    """
    if command :
        if isinstance(command, types.ListType) :
            printcmd = " ".join(command)
        if isinstance(command, types.StringTypes) :
            printcmd = command
        proc = Popen(command, stdout=PIPE, stderr=PIPE)
        proc.wait()
        log_message("command: " + printcmd + " returned: " + str(proc.retcode), \
                    "verbose", self.message_level)
        return (proc.retcode)
    else :
        log_message("Cannot run a command that is empty...", "normal", message_level)


def kill_proc(proc, timeout) :
    """
    Support function for the "runWithTimeout" function below
    
    inspiration from: http://stackoverflow.com/questions/1191374/subprocess-with-timeout
    
    @author: Roy Nielsen
    """
    timout["value"] = True
    proc.kill()

  
def runWithTimeout(command, timout_sec, message_level="normal") :
    """
    Run a command with a timeout - return:
    Returncode of the process
    stdout of the process
    stderr of the process
    timout - True if the command timed out
             False if the command completed successfully
    
    inspiration from: http://stackoverflow.com/questions/1191374/subprocess-with-timeout
    
    @author: Roy Nielsen
    """
    if isinstance(command, list) :
        if not command :
            log_message("Cannot run a command with a command list that is empty...", "normal", message_level)
            return False, False, False, False
    elif isinstance(command, basestring) :
        if re.match("^\s*$", command) :
            log_message("Cannot run a command with a command that is an empty string...", "normal", message_level)
            return False, False, False, False

    proc = Popen(command, stdout=PIPE, stderr=PIPE)
    
    timeout = {"value" : False}
    timer = threading.Timer(timout_sec, kill_proc, [proc, timeout])
    timer.start()
    stdout, stderr = proc.communicate()
    timer.cancel()

    return proc.returncode, stdout, stderr, timeout["value"]


def runWithPty(command, message_level="normal") :
    """
    Run a command with the pty...
    
    @author: Roy Nielsen
    """
    output = "ERROR..."
    #####
    # Check input
    if command :
    
        (master, slave) = pty.openpty()
        
        #process = Popen(command, stdout=slave, stderr=slave, close_fds=True)
        process = Popen(command, stdout=slave, stderr=slave)
    
        output = ""
        #temp = os.read(master, 10)
        while True :
            #r,w,e = select.select([master], [], [], 0) # timeout of 0 means "poll"
            r,w,e = select.select([], [], [], 0) # timeout of 0 means "poll"
            if r :
                line = os.read(master, 512)
                #####
                # Warning, uncomment at your own risk - several programs
                # print empty lines that will cause this to break and
                # the output will be all goofed up.
                #if not line :
                #    break
                #print output.rstrip()
                output = output + line
            elif process.poll() is not None :
                break
        os.close(master)
        os.close(slave)
        process.wait()
        #print output.strip()
        output = output.strip()
        log_message("Leaving runAs with: \"" + str(output) + "\"", "debug", message_level)
    else :
        log_message("Cannot run a command that is empty...", "normal", message_level)
    return output


def authenticate(user="", password="", message_level="normal") :
    """
    Use pexpect to run "su" to run a command as another user...

    Required parameters: user, password, command
    
    inspiration from: http://stackoverflow.com/questions/12419198/python-subprocess-readlines-hangs
    
    @author: Roy Nielsen
    """
    authenticated = False

    if re.match("^\s*$", user) or \
       re.match("^\s*$", password):
        log_message("Cannot pass in empty parameters...", "normal", message_level)
        log_message("user = \"" + str(user) + "\"", "normal", message_level)
        log_message("check password...", "normal", message_level)
        return(255)
    else :
        output = ""
        internal_command = ["/usr/bin/su", "-", str(user), "-c", "/bin/echo hello world"]
        command = " ".join(internal_command)
        log_message("command: " + str(command), "debug", message_level)
        (master, slave) = pty.openpty()
        
        process = Popen(internal_command, stdin=slave, stdout=slave, stderr=slave, shell=False)
        #####
        # Read password prompt
        prompt = os.read(master, 512)
        #####
        # send the password
        os.write(master, password + "\n")
        #####
        # catch the password
        prompt = os.read(master, 512)
        #####
        # catch the output
        output = os.read(master, 512)

        os.close(master)
        os.close(slave)
        process.wait()
        #print output.strip()
        output = output.strip()

        #####
        # Check if valid or not...
        if re.match("^su: Sorry", str(output)):
            authenticated = False
        elif re.match("^hello world", str(output)):
            authenticated = True
        else:
            authenticated = False
        log_message("Leaving authenticate with output of: \"" + str(output) + "\"", "debug", message_level)
        return authenticated


def runAs(user="", password="", command=[], message_level="normal") :
    """
    Use pexpect to run "su" to run a command as another user...

    Required parameters: user, password, command
    
    inspiration from: http://stackoverflow.com/questions/12419198/python-subprocess-readlines-hangs
    
    @author: Roy Nielsen
    """
    if re.match("^\s*$", user) or \
       re.match("^\s*$", password) or \
       not command :
        log_message("Cannot pass in empty parameters...", "normal", message_level)
        log_message("user = \"" + str(user) + "\"", "normal", message_level)
        log_message("check password...", "normal", message_level)
        log_message("command = \"" + str(command) + "\"", "normal", message_level)
        return(255)
    else :
        output = ""
        internal_command = ["/usr/bin/su", "-", str(user), "-c"]

        if isinstance(command, list) :
            internal_command.append(" ".join(command))
            #log_message("Trying to execute: \"" + " ".join(internal_command) + "\"", \
            #            "verbose", message_level) 
        elif isinstance(command, basestring) :
            internal_command.append(command)
            #log_message("Trying to execute: \"" + str(internal_command) + "\"", \
            #            "verbose", message_level) 
        
        (master, slave) = pty.openpty()
        
        process = Popen(internal_command, stdin=slave, stdout=slave, stderr=slave, close_fds=True)

        prompt = os.read(master, 10)

        if re.match("^Password:", str(prompt)) :
            os.write(master, password + "\n")
            line = os.read(master, 512)
            output = output + line
            while True :
                r,w,e = select.select([master], [], [], 0) # timeout of 0 means "poll"
                if r :
                    line = os.read(master, 512)
                    #####
                    # Warning, uncomment at your own risk - several programs
                    # print empty lines that will cause this to break and
                    # the output will be all goofed up.
                    #if not line :
                    #    break
                    #print output.rstrip()
                    output = output + line
                elif process.poll() is not None :
                    break
            os.close(master)
            os.close(slave)
            process.wait()
            #print output.strip()
        output = output.strip()
        #log_message("Leaving runAs with: \"" + str(output) + "\"", "debug", message_level)
        return output


def getecho (fileDescriptor):

    """This returns the terminal echo mode. This returns True if echo is
    on or False if echo is off. Child applications that are expecting you
    to enter a password often set ECHO False. See waitnoecho(). 
    
    Borrowed from pexpect - acceptable to license
    """

    attr = termios.tcgetattr(fileDescriptor)
    if attr[3] & termios.ECHO:
        return True
    return False


def waitnoecho (fileDescriptor, timeout=3):

    """This waits until the terminal ECHO flag is set False. This returns
    True if the echo mode is off. This returns False if the ECHO flag was
    not set False before the timeout. This can be used to detect when the
    child is waiting for a password. Usually a child application will turn
    off echo mode when it is waiting for the user to enter a password. For
    example, instead of expecting the "password:" prompt you can wait for
    the child to set ECHO off::

        see below in runAsWithSudo

    If timeout is None or negative, then this method to block forever until ECHO
    flag is False.

    Borrowed from pexpect - acceptable to license
    """

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


def runAsWithSudo(user="", password="", command=[], message_level="normal") :
    """
    Use pty method to run "su" to run a command as another user...

    Required parameters: user, password, command
    
    inspiration from: http://stackoverflow.com/questions/12419198/python-subprocess-readlines-hangs
    
    @author: Roy Nielsen
    """
    log_message("Starting runAsWithSudo: ", "debug", message_level)
    log_message("\tuser: \"" + str(user) + "\"", "debug", message_level)
    log_message("\tcmd : \"" + str(command) + "\"", "debug", message_level)
    log_message("\tmessage_level: \"" + str(message_level) + "\"", "normal", message_level)
    if re.match("^\s+$", user) or re.match("^\s+$", password) or \
       not user or not password or \
       not command :
        log_message("Cannot pass in empty parameters...", "normal", message_level)
        log_message("user = \"" + str(user) + "\"", "normal", message_level)
        log_message("check password...", "normal", message_level)
        log_message("command = \"" + str(command) + "\"", "normal", message_level)
        return(255)
    else :
        output = ""
        
        internal_command = ["/usr/bin/su", str("-"), str(user).strip(), str("-c")]

        if isinstance(command, list) :
            cmd = []
            for i in range(len(command)):
                try:
                    cmd.append(str(command[i].decode('utf-8')))
                except UnicodeDecodeError :
                    cmd.append(str(command[i]))

            internal_command.append(str("/usr/bin/sudo -E -S -s '" + " ".join(cmd) + "'"))
            #log_message("Trying to execute: \"" + " ".join(internal_command) + "\"", \
            #            "verbose", message_level) 
            #print "Trying to execute: \"" + " ".join(internal_command) + "\""
        elif isinstance(command, basestring) :
            internal_command.append(str("/usr/bin/sudo -E -S -s '" + str(command.decode('utf-8')) + "'"))
            #log_message("Trying to execute: \"" + str(internal_command) + "\"", \
            #            "verbose", message_level)
            #print "Trying to execute: \"" + str(internal_command) + "\""
        try:
            (master, slave) = pty.openpty()
        except Exception, err:
            log_message("Error trying to open pty: " + str(err))
            raise err
        else:
            try:
                process = Popen(internal_command, stdin=slave, stdout=slave, stderr=slave, close_fds=True)
                """
                ***** NOT WORKING YET *****
                
                process = Popen(internal_command, stdin=slave, stdout=slave, stderr=STDOUT, close_fds=True)

                """
            except Exception, err:
                log_message("Error opening process to pty: " + str(err))
                raise err
            else:
                #####
                # Catch the su password prompt
                # prompt = os.read(master, 512)
                waitnoecho(master, 3)
                prompt = os.read(master, 512)
                
                #####
                # pass in the password
                os.write(master, password.strip() + "\n")
                
                #####
                # catch the password
                prompt = os.read(master, 512)
                
                #####
                # Wait for the next password prompt
                waitnoecho(master, 3)
                
                #####
                # catch the password prompt
                prompt = os.read(master, 512)

                #####
                # Enter the sudo password
                os.write(master, password + "\n")
                
                #####
                # Catch the password
                os.read(master, 512)

                #output = tmp + output
                while True :
                    r,w,e = select.select([master], [], [], 0) # timeout of 0 means "poll"
                    if r :
                        line = os.read(master, 512)
                        #####
                        # Warning, uncomment at your own risk - several programs
                        # print empty lines that will cause this to break and
                        # the output will be all goofed up.
                        #if not line :
                        #    break
                        #print output.rstrip()
                        output = output + line
                    elif process.poll() is not None :
                        break
                    #print output.strip()
                os.close(master)
                os.close(slave)
                process.wait()
                #print output.strip()
        #output = output.strip()
        #####
        # UNCOMMENT ONLY WHEN IN DEVELOPMENT AND DEBUGGING OR YOU MAY REVEAL
        # MORE THAN YOU WANT TO IN THE LOGS!!!
        #log_message("\n\nLeaving runAs with Sudo: \"" + str(output) + "\"\n\n", "debug", message_level)
        #print "\n\nLeaving runAs with Sudo: \"" + str(output) + "\"\n\n"
        return output


class RunThread(threading.Thread) :
    """
    Use a thread & subprocess.Popen to run something
    
    Inspiration: http://stackoverflow.com/questions/984941/python-subprocess-popen-from-a-thread

    To use - where command could be an array, or a string... :

    run_thread = RunThread(<command>, message_level)
    run_thread.start()
    run_thread.join()
    print run_thread.stdout

    @author: Roy Nielsen
    """
    def __init__(self, command=[], message_level="normal") :
        """
        Initialization method
        """
        self.command = command
        self.message_level = message_level
        self.retout = None
        self.reterr = None
        threading.Thread.__init__(self)
        
        if isinstance(self.command, types.ListType) :
            self.shell = True
            self.printcmd = " ".join(self.command)
        if isinstance(self.command, types.StringTypes) :
            self.shell = False
            self.printcmd = self.command
    
        log_message("Initialized runThread...", "normal", self.message_level)

    def run(self):
        if self.command :
            try :
                p = Popen(self.command, stdout=PIPE, stderr=PIPE, shell=self.shell)
            except Exception, err :
                log_message("Exception trying to open: " + str(self.printcmd), "normal", self.message_level)
                log_message("Associated exception: " + str(err), "normal", self.message_level)
                raise err
            else :
                try: 
                    self.retout, self.reterr = p.communicate()
                except Exception, err :
                    log_message("Exception trying to open: " + str(self.printcmd), "normal", self.message_level)
                    log_message("Associated exception: " + str(err), "normal", self.message_level)
                    raise err
                else :
                    #log_message("Return values: ", "debug", self.message_level)
                    #log_message("retout: " + str(self.retout), "debug", self.message_level)
                    #log_message("reterr: " + str(self.reterr), "debug", self.message_level)
                    log_message("Finished \"run\" of: " + str(self.printcmd), "normal", self.message_level)

            
    def getStdout(self) :
        """
        Getter for standard output
        
        @author: Roy Nielsen
        """
        log_message("Getting stdout...", "verbose", self.message_level)
        return self.retout


    def getStderr(self) :
        """
        Getter for standard err
        
        @author: Roy Nielsen
        """
        log_message("Getting stderr...", "verbose", self.message_level)
        return self.reterr

def runMyThreadCommand(cmd=[], message_level="normal") :
    """
    Use the RunThread class to get the stdout and stderr of a command
    
    @author: Roy Nielsen
    """
    retval = None
    reterr = None
    
    if cmd and message_level :
        run_thread = RunThread(cmd, message_level)
        run_thread.start()
        run_thread.join()
        retval = run_thread.getStdout()
        reterr = run_thread.getStderr()
    else :
        log_message("Invalid parameters, please report this as a bug.")
        
    return retval, reterr

