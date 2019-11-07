"""
Library for running executables from the command line in different ways

Inspiration for some of the below found on the internet.

@author: Roy Nielsen
"""

import os
import re
import pty
import time
import types
import select
import termios
import threading
import traceback
from subprocess import Popen, PIPE

from .loggers import CyLogger
from .loggers import LogPriority as lp
from .get_libc import getLibc


class OSNotValidForRunWith(BaseException):
    '''Custom Exception'''
    def __init__(self, *args, **kwargs):
        BaseException.__init__(self, *args, **kwargs)


class NotACyLoggerError(BaseException):
    '''Custom Exception'''
    def __init__(self, *args, **kwargs):
        BaseException.__init__(self, *args, **kwargs)


class SetCommandTypeError(BaseException):
    '''Custom Exception'''
    def __init__(self, *args, **kwargs):
        BaseException.__init__(self, *args, **kwargs)


class RunWith(object):
    '''Class that will run commands in various ways.
    
    @method setCommand(self, command=[])
    @method getStdout(self)
    @method getStderr(self)
    @method getReturnCode(self)
    @method getReturns(self)
    @method getNlogReturns(self)
    @method getNprintReturns(self)
    @method communicate(self)
    @method wait(self)
    @method waitNpassThruStdout(self)
    @method killProc(self)
    @method timeout(self, seconds=0)
    @method runAs(self, user="", password="")
    @method liftDown(self)
    @method getecho(self)
    @method waitnoecho(self)
    @method runAsWithSudo(self, user="", password="")
    @method runWithSudo(self, user="", password="")
    
    @WARNING - Known to work on Mac, may or may not work on other platforms
    
    @author: Roy Nielsen


    '''
    def __init__(self, logger):
        if isinstance(logger, CyLogger):
            self.logger = logger
        else:
            raise NotACyLoggerError("Passed in value for logger" +
                                    " is invalid, try again.")
        self.command = None
        self.stdout = None
        self.stderr = None
        self.retcode = None
        self.module_version = '20160224.184019.673753'
        self.printcmd = None
        self.myshell = None
        self.prompt = ""
        self.environ = None
        self.cfds = None
        #####
        # setting up to call ctypes to do a filesystem sync
        self.libc = getLibc()

    def setCommand(self, command, env=None, myshell=None, close_fds=None):
        '''initialize a command to run
        
        @author: Roy Nielsen

        :param command: 
        :param env:  (Default value = None)
        :param myshell:  (Default value = None)
        :param close_fds:  (Default value = None)

        '''
        #####
        # Handle Popen's shell, or "myshell"...
        if command and isinstance(command, list):
            try:
                self.printcmd = " ".join(command)
                self.command = command
                if myshell is None or not isinstance(myshell, bool):
                    self.myshell = False
                else:
                    self.myshell = myshell
            except TypeError:
                raise SetCommandTypeError("Can only be passed a command " +
                                          "string or a list only containing " +
                                          "string elements for a command.")
        elif command and isinstance(command, str):
            self.command = command
            self.printcmd = command
            if myshell is None or not isinstance(myshell, bool):
                self.myshell = True
            else:
                self.myshell = myshell
        else:
            raise SetCommandTypeError("Command cannot be this type: " +
                            str(type(command)))

        self.logger.log(lp.DEBUG, "myshell: " + str(self.myshell))

        if env and isinstance(env, dict):
            self.environ = env
        else:
            self.environ = None

        if close_fds is None or not isinstance(close_fds, bool):
            self.cfds = False
        else:
            self.cfds = close_fds

    ###########################################################################

    def getStdout(self):
        '''Getter for the standard output of the last command.
        
        @author: Roy Nielsen


        '''
        return self.stdout

    ###########################################################################

    def getStderr(self):
        '''Getter for the standard error of the last command.
        
        @author: Roy Nielsen


        '''
        return self.stderr

    ###########################################################################

    def getReturnCode(self):
        '''Getter for the return code of the last command.
        
        @author: Roy Nielsen


        '''
        return self.retcode

    ###########################################################################

    def getReturns(self):
        '''Getter for the retval, reterr & retcode of the last command.
        
        @author: Roy Nielsen


        '''
        return self.stdout, self.stderr, self.retcode

    ###########################################################################

    def getNlogReturns(self):
        '''Getter for the retval, reterr & retcode of the last command.
        
        Will also log the values
        
        @author: Roy Nielsen


        '''
        self.logger.log(lp.INFO, "Output: " + str(self.stdout))
        self.logger.log(lp.INFO, "Error: " + str(self.stderr))
        self.logger.log(lp.INFO, "Return code: " + str(self.retcode))
        return self.stdout, self.stderr, self.retcode

    ###########################################################################

    def getNprintReturns(self):
        '''Getter for the retval, reterr & retcode of the last command.
        
        Will also print the values
        
        @author: Roy Nielsen


        '''
        print(("Output: " + str(self.stdout)))
        print(("Error: " + str(self.stderr)))
        print(("Return code: " + str(self.retcode)))
        return self.stdout, self.stderr, self.retcode

    ###########################################################################

    def communicate(self, silent=True):
        '''Use the subprocess module to execute a command, returning
        the output of the command

        :param silent:  (Default value = True)

        '''
        self.stdout = ''
        self.stderr = ''
        self.retcode = 999
        if self.command and isinstance(silent, bool):
            try:
                proc = Popen(self.command, stdout=PIPE, stderr=PIPE, shell=self.myshell, env=self.environ, close_fds=self.cfds)
                self.stdout, self.stderr = proc.communicate()
                self.stdout = self.stdout.decode('utf-8')
                self.stderr = self.stderr.decode('utf-8')
                self.retcode = proc.returncode
                self.libc.sync()
            except Exception as err:
                if not silent:
                    self.logger.log(lp.WARNING, "command: " + str(self.printcmd))
                    self.logger.log(lp.DEBUG, "stdout: " + str(self.stdout))
                    self.logger.log(lp.DEBUG, "stderr: " + str(self.stderr))
                    self.logger.log(lp.DEBUG, "retcode: " + str(self.retcode))
                self.logger.log(lp.WARNING, "stderr: " + str(self.stderr))
                self.logger.log(lp.WARNING, traceback.format_exc())
                self.logger.log(lp.WARNING, str(err))
                raise err
            else:
                if not silent:
                    self.logger.log(lp.DEBUG, "Done with: " + self.printcmd)
                self.logger.log(lp.DEBUG, "Command returned with error/returncode: " + str(self.retcode))
            finally:
                #####
                # Lines below could reveal a password if it is passed as an
                # argument to the command.  Could reveal in whatever stream
                # the logger is set to log (syslog, console, etc, etc.
                if not silent:
                    self.logger.log(lp.DEBUG, "Done with command: " + self.printcmd)
                    self.logger.log(lp.DEBUG, "stdout: " + str(self.stdout))
                    self.logger.log(lp.DEBUG, "stderr: " + str(self.stderr))
                    self.logger.log(lp.DEBUG, "retcode: " + str(self.retcode))
        else:
            self.logger.log(lp.WARNING,
                            "Cannot run a command that way...")
            self.stdout = None
            self.stderr = None
            self.retcode = None

        self.command = None
        return self.stdout, self.stderr, self.retcode

    ###########################################################################

    def wait(self, silent=True):
        '''Use subprocess to call a command and wait until it is finished before
        moving on...
        
        @author: Roy Nielsen

        :param silent:  (Default value = True)

        '''
        self.stdout = ''
        self.stderr = ''
        if self.command:
            try:
                proc = Popen(self.command,
                             stdout=PIPE, stderr=PIPE,
                             shell=self.myshell,
                             env=self.environ,
                             close_fds=self.cfds)
                proc.wait()
                for line in proc.stdout.readline():
                    if line:
                        self.stdout = self.stdout + str(line) + "\n"
                if proc.stderr:
                    for line in proc.stderr.readline():
                        if line:
                            self.stderr = self.stderr + str(line) + "\n"
                else:
                    self.stderr = ""
                proc.wait()
                self.retcode = proc.returncode
                self.libc.sync()
            except Exception as err:
                if not silent:
                    self.logger.log(lp.WARNING, "command: " + str(self.printcmd))
                self.logger.log(lp.WARNING, "stderr: " + str(self.stderr))
                self.logger.log(lp.WARNING, traceback.format_exc())
                self.logger.log(lp.WARNING, str(err))
                raise err
            else:
                if not silent:
                    self.logger.log(lp.DEBUG, "Done with: " + self.printcmd)
                self.logger.log(lp.DEBUG, "Command returned with error/returncode: " + str(self.retcode))
            finally:
                if not silent:
                    self.logger.log(lp.DEBUG, "Done with command: " + self.printcmd)
                    self.logger.log(lp.DEBUG, "stdout: " + str(self.stdout))
                    self.logger.log(lp.DEBUG, "stderr: " + str(self.stderr))
                    self.logger.log(lp.DEBUG, "retcode: " + str(self.retcode))
        else:
            self.logger.log(lp.WARNING,
                            "Cannot run a command that is empty...")
            self.stdout = None
            self.stderr = None
            self.retcode = None

        self.command = None
        return self.stdout, self.stderr, self.retcode

    ###########################################################################

    def waitNpassThruStdout(self, chk_string=None, respawn=False, silent=True):
        '''Use the subprocess module to execute a command, returning
        the output of the command
        
        Author: Roy Nielsen

        :param chk_string:  (Default value = None)
        :param respawn:  (Default value = False)
        :param silent:  (Default value = True)

        '''
        self.stdout = ''
        self.stderr = ''
        self.retcode = 999
        if self.command:
            try:
                proc = Popen(self.command, stdout=PIPE, stderr=PIPE,
                             shell=self.myshell,
                             env=self.environ,
                             close_fds=self.cfds)
                if proc:
                    while True:
                        #####
                        # process stdout
                        myout = proc.stdout.readline().decode('utf-8')
                        if myout == '' and proc.poll() is not None:
                            break
                        tmpline = myout.strip()
                        self.stdout += tmpline + "\n"

                        if tmpline and not silent:
                            self.logger.log(lp.DEBUG, str(tmpline))

                        if isinstance(chk_string, str):
                            if not chk_string:
                                continue
                            else:
                                if re.search(chk_string, tmpline):
                                    # proc.stdout.close()
                                    # proc.stderr.close()
                                    if respawn:
                                        pass
                                    else:
                                        self.logger.log(lp.INFO,
                                                        "chk_string found" +
                                                        "... exiting process.")
                                    break

                        if isinstance(chk_string, list):
                            if not chk_string:
                                continue
                            else:
                                found = False
                                for mystring in chk_string:
                                    if chk_string(mystring, tmpline):
                                        # proc.stdout.close()
                                        # proc.stderr.close()
                                        if respawn:
                                            pass
                                        else:
                                            self.logger.log(lp.INFO,
                                                            "chk_string " +
                                                            "found... " +
                                                            "exiting process.")
                                            found = True
                                            break
                                if found:
                                    break

                    while True:
                        myerr = proc.stderr.readline().decode('utf-8')
                        if myerr == '' and proc.poll() is not None:
                            break
                        tmpline = myerr.strip()
                        self.stderr += tmpline + "\n"

                        if tmpline and not silent:
                            self.logger.log(lp.DEBUG, str(tmpline))

                        if isinstance(chk_string, str):
                            if not chk_string:
                                continue
                            else:
                                if re.search(chk_string, tmpline):
                                    # proc.stdout.close()
                                    # proc.stderr.close()
                                    if respawn:
                                        pass
                                    else:
                                        self.logger.log(lp.INFO,
                                                        "chk_string found" +
                                                        "... exiting process.")
                                    break

                        if isinstance(chk_string, list):
                            if not chk_string:
                                continue
                            else:
                                found = False
                                for mystring in chk_string:
                                    if chk_string(mystring, tmpline):
                                        # proc.stdout.close()
                                        # proc.stderr.close()
                                        if respawn:
                                            pass
                                        else:
                                            self.logger.log(lp.INFO,
                                                            "chk_string " +
                                                            "found... " +
                                                            "exiting process.")
                                            found = True
                                            break
                                if found:
                                    break

                proc.wait()
                # proc.stdout.close()
                # proc.stderr.close()
                self.retcode = proc.returncode
                self.libc.sync()

            except Exception as err:
                if not silent:
                    self.logger.log(lp.WARNING, "command: " + str(self.printcmd))
                self.logger.log(lp.WARNING, "stderr: " + str(self.stderr))
                self.logger.log(lp.WARNING, traceback.format_exc())
                self.logger.log(lp.WARNING, str(err))
                raise err
            else:
                if not silent:
                    self.logger.log(lp.DEBUG, "Done with: " + self.printcmd)
            finally:
                self.retcode = proc.returncode
                if not silent:
                    self.logger.log(lp.DEBUG, "Done with command: " + self.printcmd)
                self.logger.log(lp.DEBUG, "stdout: " + str(self.stdout))
                self.logger.log(lp.DEBUG, "stderr: " + str(self.stderr))
                self.logger.log(lp.DEBUG, "retcode: " + str(self.retcode))
        else:
            self.logger.log(lp.WARNING,
                            "Cannot run a command that is empty...")
            self.stdout = None
            self.stderr = None
            self.retcode = None

        self.command = None
        return self.stdout, self.stderr, self.retcode

    ###########################################################################

    def killProc(self, proc, timeout):
        '''Support function for the "runWithTimeout" function below
        
        @author: Roy Nielsen

        :param proc: 
        :param timeout: 

        '''
        timeout["value"] = True
        proc.kill()

    ###########################################################################

    def timeout(self, timout_sec, silent=True):
        '''Run a command with a timeout - return:

        :param timout_sec: 
        :param silent:  (Default value = True)
        :returns: stdout of the process
        stderr of the process
        timout - True if the command timed out
                 False if the command completed successfully
        
        @author: Roy Nielsen

        '''
        if self.command:
            try:
                proc = Popen(self.command,
                             stdout=PIPE, stderr=PIPE, shell=self.myshell)

                timeout = {"value": False}
                timer = threading.Timer(timout_sec, self.killProc,
                                        [proc, timeout])
                timer.start()
                self.stdout, self.stderr = proc.communicate()
                timer.cancel()
                self.retcode = proc.returncode
            except Exception as err:
                if not silent:
                    self.logger.log(lp.WARNING, "command: " + str(self.printcmd))
                self.logger.log(lp.WARNING, "stderr: " + str(self.stderr))
                self.logger.log(lp.WARNING, traceback.format_exc())
                self.logger.log(lp.WARNING, str(err))
                raise err
            else:
                if not silent:
                    self.logger.log(lp.DEBUG, "Done with: " + self.printcmd)
                self.stdout = proc.stdout
                self.stderr = proc.stderr
                self.retcode = proc.returncode
                self.libc.sync()
                proc.stdout.close()
                proc.stderr.close()
            finally:
                if not silent:
                    self.logger.log(lp.DEBUG, "Done with command: " +
                                    str(self.printcmd))
                    self.logger.log(lp.DEBUG, "stdout: " + str(self.stdout))
                    self.logger.log(lp.DEBUG, "stderr: " + str(self.stderr))
                    self.logger.log(lp.DEBUG, "retcode: " + str(self.retcode))
        else:
            self.logger.log(lp.WARNING,
                            "Cannot run a command that is empty...")
            self.stdout = None
            self.stderr = None
            self.retcode = None

        self.command = None
        return self.stdout, self.stderr, self.retcode, timeout["value"]

    ###########################################################################

    def runAs(self, user="", password="", silent=True):
        '''Use pexpect to run "su" to run a command as another user...
        
        Required parameters: user, password, command
        
        @author: Roy Nielsen

        :param user:  (Default value = "")
        :param password:  (Default value = "")
        :param silent:  (Default value = True)

        '''
        self.stdout = ""
        self.stderr = ""
        self.retcode = 999
        # pretcode = 0
        if re.match("^\s*$", user) or \
           re.match("^\s*$", password) or \
           not self.command:
            self.logger.log(lp.WARNING, "Cannot pass in empty parameters...")
            self.logger.log(lp.WARNING, "user = \"" + str(user) + "\"")
            self.logger.log(lp.WARNING, "check password...")
            if not silent:
                self.logger.log(lp.WARNING,
                                "command = \"" + str(self.command) + "\"")
            return 255
        else:
            output = ""
            internal_command = ["/usr/bin/su", "-", str(user.strip()), "-c"]

            if isinstance(self.command, list):
                internal_command.append(" ".join(self.command))
                if not silent:
                    self.logger.log(lp.DEBUG, "Trying to execute: \"" +
                                    " ".join(internal_command) + "\"")
            elif isinstance(self.command, str):
                internal_command += self.command
                if not silent:
                    self.logger.log(lp.DEBUG, "Trying to execute: \"" +
                                    " ".join(internal_command) + "\"")

            (master, slave) = pty.openpty()

            proc = Popen(internal_command,
                         stdin=slave, stdout=slave, stderr=slave,
                         close_fds=True)

            prompt = os.read(master, 10)

            if re.match("^Password:", str(prompt)):
                os.write(master, password + "\n")
                line = os.read(master, 512)
                output = output + line
                while True:
                    #####
                    # timeout of 0 means "poll"
                    ready, _, _ = select.select([master], [], [], 0)
                    if ready:
                        line = os.read(master, 512)
                        #####
                        # Warning, uncomment at your own risk - several
                        # programs print empty lines that will cause this to
                        # break and the output will be all goofed up.
                        # if not line :
                        #    break
                        # print output.rstrip()
                        output = output + line
                    elif proc.poll() is not None:
                        break
                os.close(master)
                os.close(slave)
                self.libc.sync()
                proc.wait()
                self.libc.sync()
                self.stdout = proc.stdout
                self.stderr = proc.stderr
                self.retcode = proc.returncode
            else:
                output = prompt
                while True:
                    #####
                    # timeout of 0 means "poll"
                    ready, _, _ = select.select([master], [], [], 0)
                    if ready:
                        line = os.read(master, 512)
                        #####
                        # Warning, uncomment at your own risk - several
                        # programs print empty lines that will cause this to
                        # break and the output will be all goofed up.
                        # if not line :
                        #    break
                        # print output.rstrip()
                        output = output + line
                    elif proc.poll() is not None:
                        break
                os.close(master)
                os.close(slave)
                proc.wait()
                self.stdout = output
                self.stderr = str(proc.stderr)
                self.retcode = proc.returncode
            output = output.strip()
            if not silent:
                self.logger.log(lp.DEBUG, "retcode: " + str(self.stdout))
                self.logger.log(lp.DEBUG, "retcode: " + str(self.stderr))
                self.logger.log(lp.DEBUG, "retcode: " + str(self.retcode))

        self.command = None
        return self.stdout, self.stderr, self.retcode

    ###########################################################################

    def liftDown(self, user="", target_dir="", silent=True):
        '''Use the lift (elevator) to execute a command from privileged mode
        to a user's context with that user's uid.  Does not require a password.

        :param user:  (Default value = "")
        :param target_dir:  (Default value = "")
        :param silent:  (Default value = True)

        '''
        self.stdout = ""
        self.stderr = ""
        self.retcode = 999
        user = user.strip()

        if os.getuid() != 0:
            self.logger.log("This can only run if running in privileged mode.")
            return 256

        if isinstance(target_dir, str) and target_dir:
            return_dir = os.getcwd()
            if os.path.exists(target_dir):
                os.chdir(target_dir)

        if re.match("^\s*$", user) or not self.command:
            self.logger.log(lp.WARNING, "Cannot pass in empty parameters...")
            self.logger.log(lp.WARNING, "user = " + str(user))
            if not silent:
                self.logger.log(lp.WARNING,
                                "command = \"" + str(self.command) + "\"")
            return 255
        else:
            internal_command = ["/usr/bin/su", "-", str(user), "-c"]

            if isinstance(self.command, list):
                cmd = []
                for i in range(len(self.command)):
                    try:
                        cmd.append(str(self.command[i]))
                    except UnicodeDecodeError:
                        cmd.append(str(self.command[i]))

                internal_command.append(str(" ".join(cmd)))
            elif isinstance(self.command, str):
                internal_command.append(self.command)

        self.setCommand(internal_command)
        self.stdout, self.stderr, self.retcode = self.communicate()
        if not silent:
            for line in self.stdout.split('\n'):
                self.logger.log(lp.DEBUG, "out: " + str(line))
            for line in self.stderr.split('\n'):
                self.logger.log(lp.DEBUG, "err: " + str(line))
            self.logger.log(lp.DEBUG, "out: " + str(self.retcode))

        if target_dir:
            os.chdir(return_dir)

        self.command = None
        return self.stdout, self.stderr, self.retcode

    ###########################################################################

    def getecho (self, fileDescriptor):
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

    ###########################################################################

    def waitnoecho (self, fileDescriptor, timeout=3):
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
            if not self.getecho(fileDescriptor):
                return True
            if timeout < 0 and timeout is not None:
                return False
            if timeout is not None:
                timeout = end_time - time.time()
            time.sleep(0.1)

    ###########################################################################

    def runAsWithSudo(self, user="", password="", silent=True) :
        '''Use pty method to run "su" to run a command as another user...
        
        Required parameters: user, password, command
        
        @author: Roy Nielsen

        :param user:  (Default value = "")
        :param password:  (Default value = "")
        :param silent:  (Default value = True)

        '''
        self.logger.log(lp.DEBUG, "Starting runAsWithSudo: ")
        self.logger.log(lp.DEBUG, "\tuser: \"" + str(user) + "\"")
        self.logger.log(lp.DEBUG, "\tcmd : \"" + str(self.command) + "\"")
        if re.match("^\s+$", user) or re.match("^\s+$", password) or \
           not user or not password or \
           not self.command:
            self.logger.log(lp.WARNING, "Cannot pass in empty parameters...")
            self.logger.log(lp.WARNING, "user = \"" + str(user) + "\"")
            self.logger.log(lp.WARNING, "check password...")
            if not silent:
                self.logger.log(lp.WARNING, "command: " + str(self.command))
            return 255
        else:
            output = ""

            internal_command = ["/usr/bin/su", str("-m"),
                                str(user).strip(), str("-c")]

            if isinstance(self.command, list):
                cmd = []
                for i in range(len(self.command)):
                    try:
                        cmd.append(str(self.command[i].decode('utf-8')))
                    except UnicodeDecodeError:
                        cmd.append(str(self.command[i]))

                internal_command.append(str("/usr/bin/sudo -S -s '" +
                                            " ".join(cmd) + "'"))
            elif isinstance(self.command, str):
                try:
                    internal_command.append(str("/usr/bin/sudo -E -S -s " +
                                                "'" +
                                                str(self.command.decode('utf-8')) +
                                                "'"))
                except UnicodeDecodeError:
                    internal_command.append(str("/usr/bin/sudo -E -S -s " +
                                                "'" +
                                                str(self.command) + "'"))

            try:
                (master, slave) = pty.openpty()
            except Exception as err:
                self.logger.log(lp.WARNING, "Error trying to open pty: " +
                                str(err))
                self.logger.log(lp.WARNING, traceback.format_exc())
                self.logger.log(lp.WARNING, str(err))
                raise err
            else:
                try:
                    proc = Popen(internal_command,
                                 stdin=slave, stdout=slave, stderr=slave,
                                 close_fds=True)
                except Exception as err:
                    self.logger.log(lp.WARNING,
                                    "Error opening process to pty: " +
                                    str(err))
                    self.logger.log(lp.WARNING, traceback.format_exc())
                    self.logger.log(lp.WARNING, str(err))
                    raise err
                else:
                    #####
                    # Catch the su password prompt
                    # prompt = os.read(master, 512)
                    self.waitnoecho(master, 3)
                    self.prompt = os.read(master, 512)

                    #####
                    # pass in the password
                    os.write(master, password.strip() + "\n")

                    #####
                    # catch the password
                    self.prompt = os.read(master, 512)

                    #####
                    # Wait for the next password prompt
                    self.waitnoecho(master, 3)

                    #####
                    # catch the password prompt
                    self.prompt = os.read(master, 512)

                    #####
                    # Enter the sudo password
                    os.write(master, password + "\n")

                    #####
                    # Catch the password
                    os.read(master, 512)

                    # output = tmp + output
                    while True:
                        #####
                        # timeout of 0 means "poll"
                        ready, _, _ = select.select([master], [], [], 0)
                        if ready:
                            line = os.read(master, 512)
                            #####
                            # Warning, uncomment at your own risk - several
                            # programs print empty lines that will cause this
                            # to break and the output will be all goofed up.
                            # if not line :
                            #    break
                            # print output.rstrip()
                            output = output + line
                        elif proc.poll() is not None:
                            break
                        # print output.strip()
                    os.close(master)
                    os.close(slave)
                    self.libc.sync()
                    proc.wait()
                    self.libc.sync()
                    self.stdout = proc.stdout
                    self.stderr = proc.stderr
                    self.retcode = proc.returncode
                    # print output.strip()
            if not silent:
                self.logger.log(lp.DEBUG, "\n\nLeaving runAs with Sudo: \"" +
                                str(self.output) + "\"\n\n")
        self.command = None
        return self.stdout, self.stderr, self.retcode

    ###########################################################################

    def runWithSudo(self, password="", silent=True) :
        '''Use pty method to run "sudo" to run a command with elevated privilege.
        
        Required parameters: user, password, command
        
        @author: Roy Nielsen

        :param password:  (Default value = "")
        :param silent:  (Default value = True)

        '''
        self.logger.log(lp.DEBUG, "Starting runWithSudo: ")
        self.logger.log(lp.DEBUG, "\tcmd : " + str(self.command))
        if re.match("^\s+$", password) or \
           not password or \
           not self.command:
            self.logger.log(lp.WARNING, "Cannot pass in empty parameters...")
            self.logger.log(lp.WARNING, "check password...")
            if not silent:
                self.logger.log(lp.WARNING, "command: " + str(self.command))
            return(255)
        else:
            output = ""
            cmd = ["/usr/bin/sudo", "-S", "-s"]

            if isinstance(self.command, list):
                cmd = cmd + [" ".join(self.command)]

            elif isinstance(self.command, str):
                cmd = cmd + [self.command]

            try:
                (master, slave) = pty.openpty()
            except Exception as err:
                self.logger.log(lp.WARNING, "Error trying to open pty: " +
                                str(err))
                self.logger.log(lp.WARNING, traceback.format_exc())
                self.logger.log(lp.WARNING, str(err))
                raise err
            else:
                try:
                    proc = Popen(cmd, stdin=slave, stdout=slave, stderr=slave,
                                 close_fds=True)
                except Exception as err:
                    self.logger.log(lp.WARNING,
                                    "Error opening process to pty: " +
                                    str(err))
                    self.logger.log(lp.WARNING, traceback.format_exc())
                    self.logger.log(lp.WARNING, str(err))
                    raise err
                else:
                    #####
                    # Catch the sudo password prompt
                    # prompt = os.read(master, 512)
                    self.waitnoecho(master, 3)
                    self.prompt = os.read(master, 512)

                    #####
                    # Enter the sudo password
                    os.write(master, password + "\n")

                    #####
                    # Catch the password
                    os.read(master, 512)

                    # output = tmp + output
                    while True:
                        #####
                        # timeout of 0 means "poll"
                        ready, _, _ = select.select([master], [], [], 0)
                        if ready:
                            line = os.read(master, 512)
                            #####
                            # Warning, uncomment at your own risk - several
                            # programs print empty lines that will cause this
                            # to break and the output will be all goofed up.
                            # if not line :
                            #    break
                            # print output.rstrip()
                            output = output + line
                        elif proc.poll() is not None:
                            break
                        # print output.strip()
                    os.close(master)
                    os.close(slave)
                    self.libc.sync()
                    proc.wait()
                    self.libc.sync()
                    self.stdout = output
                    self.stderr = proc.stderr
                    self.retcode = proc.returncode
                    #print output.strip()
            #output = output.strip()
            if not silent:
                #####
                # ONLY USE WHEN IN DEVELOPMENT AND DEBUGGING OR YOU MAY
                # REVEAL MORE THAN YOU WANT TO IN THE LOGS!!!
                self.logger.log(lp.DEBUG, "\n\nLeaving runAs with Sudo: \"" + \
                                str(output) + "\"\n" + str(self.output) + "\n")
            return output

##############################################################################

class RunThread(threading.Thread):
    '''Use a thread & subprocess.Popen to run something
    
    To use - where command could be an array, or a string... :
    
    run_thread = RunThread(<command>, message_level)
    run_thread.start()
    run_thread.join()
    print run_thread.stdout
    
    @author: Roy Nielsen


    '''
    def __init__(self, command, logger, myshell=False):
        """
        Initialization method
        """
        self.command = command
        self.logger = logger
        self.retout = None
        self.reterr = None
        self.shell = myshell
        threading.Thread.__init__(self)

        if isinstance(self.command, list):
            self.shell = True
            self.printcmd = " ".join(self.command)
        if isinstance(self.command, str):
            self.shell = False
            self.printcmd = self.command

        if isinstance(logger, CyLogger):
            self.logger = logger
        else:
            raise NotACyLoggerError("Passed in value for logger " +
                                    "is invalid, try again.")

        self.logger.log(lp.INFO, "Initialized runThread...")

    ##########################################################################

    def run(self):
        if self.command:
            try:
                p = Popen(self.command, stdout=PIPE,
                                        stderr=PIPE,
                                        shell=self.shell)
                self.retout, self.reterr = p.communicate()
                self.logger.log(lp.WARNING, "Finished \"run\" of: " +
                                str(self.command))
            except Exception as err:
                self.logger.log(lp.WARNING, "Exception trying to open: " +
                                str(self.command))
                self.logger.log(lp.WARNING, traceback.format_exc())
                self.logger.log(lp.WARNING, str(err))
                raise err
            else:
                try:
                    self.retout, self.reterr = p.communicate()
                except Exception as err:
                    self.logger.log(lp.WARNING, "Exception trying to open: " +
                                    str(self.printcmd))
                    self.logger.log(lp.WARNING, "Associated exception: " +
                                    str(err))
                    raise err
                else:
                    self.logger.log(lp.WARNING, "Finished \"run\" of: " +
                                    str(self.printcmd))

    ##########################################################################

    def getStdout(self):
        '''Getter for standard output
        
        @author: Roy Nielsen


        '''
        self.logger.log(lp.INFO, "Getting stdout...")
        return self.retout

    ##########################################################################

    def getStderr(self):
        '''Getter for standard err
        
        @author: Roy Nielsen


        '''
        self.logger.log(lp.DEBUG, "Getting stderr...")
        return self.reterr

##############################################################################

def runMyThreadCommand(cmd, logger, myshell=False):
    '''Use the RunThread class to get the stdout and stderr of a command
    
    @author: Roy Nielsen

    :param cmd: 
    :param logger: 
    :param myshell:  (Default value = False)

    '''
    retval = None
    reterr = None
    if not isinstance(logger, CyLogger):
        raise NotACyLoggerError("Passed in value for logger is "
                                "invalid, try again.")
    print((str(cmd)))
    print((str(logger)))
    if cmd and logger:
        run_thread = RunThread(cmd, logger, myshell)
        run_thread.start()
        # run_thread.run()
        run_thread.join()
        retval = run_thread.getStdout()
        reterr = run_thread.getStderr()
    else:
        logger.log(lp.INFO, "Invalid parameters, please report this as a bug.")

    return retval, reterr

