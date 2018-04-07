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

'''
@author: ekkehard
@author: rsn
@author: dwalker
@change: 2013/11/19 ekkehard original implementation
@change: 2014/04/01 rsn added getOutputGroup & getFirstOutputGroup
@change: 2014/04/01 dwalker added setRegexFlag & enhanced findInOutput
@change: 2014/04/15 ekkehard enhance documentation & pep8 compliance
@change: 2014/04/15 ekkehard made logging more intelligent
@change: 2014/10/20 ekkehard fix pep8 violation
@change: 2015/09/22 ekkehard Uniform logging
@change: 2017/10/17 rsn Added __calledBy() method for determining the
                        caller of command helper
@change: 2018/03/29 Breen Malmberg fixed an instance where a variable (commandaborted)
        was not properly getting set to True when a command would abort due to timeout;
        
'''

import inspect
import re
import subprocess
import traceback
import types
import time

from logdispatcher import LogPriority


class CommandHelper(object):
    '''
    CommandHelper is class that helps with execution of subprocess Popen based
    commands and then finding or parsing strerror and/or strout
    their output.
    @author: rsn
    @author: dwalker
    @author: ekkehard
    '''

###############################################################################

    def __init__(self, logdispatcher):
        '''
        Initialize all object attributes
        @author: ekkehard j. koch
        '''
        self.logdispatcher = logdispatcher
        self.command = []
        self.commandblank = True
        self.returncode = 0
        self.output = []
        self.stdout = []
        self.stderr = []
        self.shell = False
        self.setLogPriority(LogPriority.DEBUG)
        self.flags = ["DEBUG", "IGNORECASE", "LOCALE", "MULTILINE", "DOTALL",
                      "UNICODE", "VERBOSE"]
        self.flag = ""

        # set this to False if you need to run a command that has no return code
        self.wait = True
        self.cmdtimeout = 0

###############################################################################

    def __calledBy(self):
        """
        Log the caller of the method that calls this method

        @author: Roy Nielsen
        """
        try:
            filename = inspect.stack()[3][1]
            functionName = str(inspect.stack()[3][3])
            lineNumber = str(inspect.stack()[3][2])
        except Exception, err:
            raise err
        else:
            self.logdispatcher.log(LogPriority.DEBUG, "called by: " + \
                                      filename + ": " + \
                                      functionName + " (" + \
                                      lineNumber + ")")
        return " Filename: " + str(filename) + "Line: " + str(lineNumber) + " functionName: " + str(functionName)

###############################################################################

    def getCommand(self):
        '''
        Get the current command.
        @param self:essential if you override this definition
        @return: string or list of command
        @author: ekkehard j. koch
        '''
        return self.command

###############################################################################

    def getError(self):
        '''
        Get standard error stream for last executed command
        @param self:essential if you override this definition
        @return: list of standard error stream
        @author: ekkehard j. koch
        '''
        return self.stderr

###############################################################################

    def getErrorOutput(self):
        '''
        Get standard out stream and standard error for last executed command
        @param self:essential if you override this definition
        @return: list of output
        @author: ekkehard j. koch
        '''

        return self.output

###############################################################################

    def getOutput(self):
        '''
        Get standard out stream for last executed command
        @param self:essential if you override this definition
        @return: self.stdout
        @rtype: list
        @author: ekkehard j. koch
        @change: Breen Malmberg - 12/3/2015
        '''

        return self.stdout

###############################################################################

    def getOutputGroup(self, expression, groupnumber, searchgroup="output"):
        '''
        getOutputGroup (expression,groupnumber) finds an expression in the
        returns the specified group after using regular expression on output
        @param self:essential if you override this definition
        @param expression string: expression to search for in searchgroup
        @param groupnumber integer: number of group to return
        @param searchgroup string: group to search in output, stdout, stderr
        @return: returnlist
        @rtype: list
        @author: rsn
        @change: Breen Malmberg - 12/3/2015
        '''

        returnlist = []

        try:

            if searchgroup == "output":
                searchstream = self.output
            elif searchgroup == "stdout":
                searchstream = self.stdout
            elif searchgroup == "stderr":
                searchstream = self.stderr
            else:
                searchstream = self.output
            for line in searchstream:
                reresult = re.search(expression, line)
                groupstr = reresult.group(groupnumber)
                msg = "Group(" + str(groupnumber) + ")='" + \
                groupstr + "'; line='" + line + "'"
                self.logdispatcher.log(LogPriority.DEBUG, msg)
                returnlist.append(groupstr)
            msg = "expression = " + str(expression) + ", " + \
            "groupnumber = " + str(groupnumber) + ", " + \
            "searchgroup = " + str(searchgroup) + " = " + \
            "returnlist = " + str(returnlist) + ";"
            self.logdispatcher.log(LogPriority.DEBUG, msg)
        except Exception:
            raise
        return returnlist

###############################################################################

    def getFirstOutputGroup(self, expression, groupnumber, searchgroup="output"):
        '''
        getOutputGroup (expression, groupnumber) finds an expression in the
        returns the first instance (string) of the group specified in the
        regular expression that is found in the output.
        @param self:essential if you override this definition
        @param expresssion string: expression to search for
        @param groupnumber integer: number of group to return
        @param searchgroup string: group to search in output, stdout, stderr
        @return: returnstring
        @rtype: bool
        @author: rsn
        @change: Breen Malmberg - 12/3/2015
        '''

        returnstring = ""

        try:

            if searchgroup == "output":
                searchstream = self.output
            elif searchgroup == "stdout":
                searchstream = self.stdout
            elif searchgroup == "stderr":
                searchstream = self.stderr
            else:
                searchstream = self.output
            for line in searchstream:
                reresult = re.search(expression, line)
                if reresult:
                    groupstr = reresult.group(groupnumber)
                    msg = "Group(" + str(groupnumber) + ")='" + \
                    groupstr + "'; line='" + line + "'"
                    self.logdispatcher.log(LogPriority.DEBUG, msg)
                    returnstring = groupstr
                    break
            msg = "expression = " + str(expression) + ", " + \
            "groupnumber = " + str(groupnumber) + ", " + \
            "searchgroup = " + str(searchgroup) + " = " + \
            "returnstring = " + str(returnstring) + ";"
            self.logdispatcher.log(LogPriority.DEBUG, msg)
        except Exception:
            raise
        return returnstring

###############################################################################

    def getOutputString(self):
        '''
        Get standard out in string format
        @param self:essential if you override this definition
        @return: stdstring
        @rtype: string
        @author: ekkehard j. koch
        @change: Breen Malmberg - 12/3/2015
        '''

        stdstring = ""

        try:

            if self.stdout:
                if not isinstance(self.stdout, list):
                    self.logdispatcher.log(LogPriority.DEBUG,
                                           "Parameter self.stdout is not a " +
                                           "list. Cannot compile stdout " +
                                           "string. Returning blank stdout " +
                                           "string...")
                    return stdstring

                for line in self.stdout:
                    stdstring += line + "\n"
            else:
                self.logdispatcher.log(LogPriority.DEBUG, "No stdout string to display")

        except Exception:
            raise
        return stdstring

###############################################################################

    def getErrorString(self):
        '''
        Get standard error in string format
        @param self:essential if you override this definition
        @return: self.stderr
        @rtype: string
        @author: dwalker
        @change: Breen Malmberg - 12/3/2015
        '''

        errstring = ""

        try:

            if self.stderr:
                if not isinstance(self.stderr, list):
                    self.logdispatcher.log(LogPriority.DEBUG,
                                           "Parameter self.stderr is not a " +
                                           "list. Cannot compile error " +
                                           "string. Returning blank error " +
                                           "string...")
                    return errstring

                for line in self.stderr:
                    errstring += line + "\n"
            else:
                self.logdispatcher.log(LogPriority.DEBUG,
                                       "No error string to display")

        except Exception:
            raise
        return errstring

###############################################################################

    def getAllString(self):
        '''
        Get both the stdout and stderr together as one string
        @param self:essential if you override this definition
        @return: allstring
        @rtype: string
        @author: Breen Malmberg
        '''

        allstring = ""

        stdoutstring = self.getOutputString()
        stderrstring = self.getErrorString()

        try:

            if not isinstance(stdoutstring, basestring):
                self.logdispatcher.log(LogPriority.DEBUG,
                                       "Content of parameter stdoutstring " +
                                       "is not in string format. Will not " +
                                       "include content in output!")
                stdoutstring = ""

            if not isinstance(stderrstring, basestring):
                self.logdispatcher.log(LogPriority.DEBUG,
                                       "Content of parameter stderrstring " +
                                       "is not in string format. Will not " +
                                       "include content in output!")
                stderrstring = ""

            if stderrstring:
                allstring += stderrstring
            if allstring:
                allstring += '\n'
            if stdoutstring:
                allstring += stdoutstring

            if not allstring:
                self.logdispatcher.log(LogPriority.DEBUG,
                                       "There was no output to return")

        except Exception:
            raise
        return allstring

###############################################################################

    def getAllList(self):
        '''
        Get both the stdout and stderr together as one list
        @param self:essential if you override this definition
        @return: alllist
        @rtype: list
        @author: Breen Malmberg
        '''

        alllist = []

        stdoutlist = self.getOutput()
        stderrlist = self.getError()

        try:

            if not isinstance(stdoutlist, list):
                self.logdispatcher.log(LogPriority.DEBUG, "Content of parameter stdoutlist is not in list format. Will not include content in output!")
                stdoutlist = []
            if not isinstance(stderrlist, list):
                self.logdispatcher.log(LogPriority.DEBUG, "Content of parameter stderrlist is not in list format. Will not include content in output!")
                stderrlist = []

            if stdoutlist:
                for line in stdoutlist:
                    alllist.append(line)
            if stderrlist:
                for line in stderrlist:
                    alllist.append(line)

            if not alllist:
                self.logdispatcher.log(LogPriority.DEBUG, "There was no output to return")

        except Exception:
            raise
        return alllist

###############################################################################

    def getReturnCode(self):
        '''
        Get return code for last executed command
        @param self:essential if you override this definition
        @return: string of return code
        @author: ekkehard j. koch
        '''
        return self.returncode

###############################################################################

    def setCommand(self, command):
        '''
        setCommand (command) set the command for the CommandHelper
        @param self:essential if you override this definition
        @param command string: command to set the command property to
        @return: bool indicating success or failure
        @author: ekkehard j. koch
        '''

        success = False

        try:

            self.stdout = []
            self.stderr = []
            self.output = []
            commandtype = type(command)
            if (commandtype is types.StringType):
                self.shell = True
                if len(command.strip()) > 0:
                    self.commandblank = False
                else:
                    self.commandblank = True
                    msg = "The command of type '" + str(commandtype) + \
                        "' is blank!"
                    self.logdispatcher.log(LogPriority.ERROR, msg)
                    raise ValueError(msg)
                self.command = command.strip()
                success = True
                msg = "Command Set To '" + self.command + "'"
                self.logdispatcher.log(LogPriority.DEBUG, msg)
            elif (commandtype is types.ListType):
                self.shell = False
                self.command = []
                self.commandblank = True
                success = True
                if len(command) == 0:
                    msg = "The command of type '" + str(commandtype) + \
                        "' is blank!"
                    self.logdispatcher.log(LogPriority.ERROR, msg)
                    raise ValueError(msg)
                for commandlistitem in command:
                    commandtype = type(commandlistitem)
                    if (commandtype is types.StringType):
                        self.command.append(commandlistitem.strip())
                        if len(commandlistitem.strip()) > 0:
                            self.commandblank = False
                    else:
                        success = False
                        msg = "Command List Item '" + str(commandlistitem) + \
                            "' has in invalid type of '" + str(commandtype) + "'"
                        self.logdispatcher.log(LogPriority.DEBUG, msg)
                        raise TypeError(msg)
                msg = "Command Set To '" + str(self.command) + "'"
                self.logdispatcher.log(LogPriority.DEBUG, msg)
            else:
                success = False
                msg = "Command '" + str(command) + "' has in invalid type of '" + \
                    str(commandtype) + "'"
                self.logdispatcher.log(LogPriority.DEBUG, msg)
                raise TypeError(msg)
        except Exception:
            message = str(self.__calledBy()) + "\nInvalid command input: " + str(traceback.format_exc())
            raise ValueError(str(message))
        return success

###############################################################################

    def setLogPriority(self, logpriority=None):
        '''
        Setting log priority use LogPriority.DEBUG, LogPrority.ERROR, etc.
        @param self:essential if you override this definition
        @param logpriority of type LogPriority.xxx
        @return: bool indicating success or failure
        @author: ekkehard j. koch
        '''

        success = True

        logprioritytype = type(logpriority)
        if (logpriority is None):
            self.logpriority = LogPriority.DEBUG
        elif (logprioritytype is types.StringType):
            self.logpriority = logpriority
        else:
            self.logpriority = LogPriority.DEBUG
            success = False
            raise TypeError("LogPriority is set to '" +
                            str(self.logpriority) +
                            "'! Invalid LogPriority Object of type '" +
                            str(logprioritytype) + "' specified!")
        return success

###############################################################################

    def setRegexFlag(self, flag):
        '''
        Set the Regular Expression Flag.
        @param self:essential if you override this definition
        @param flag used in regular expression
        @author: rsn
        '''
        if flag in self.flags:
            self.flag = flag

###############################################################################

    def executeCommand(self, command=None):
        '''
        executeCommand (command) excecute the command for the CommandHelper
        @param self:essential if you override this definition
        @param command string or list: command to set the command property to
        @return: bool indicating success or failure
        @author: ekkehard j. koch
        '''

        commandaborted = False

        try:
            commandobj = None
            success = True
            if (type(command) is not None):
                success = self.setCommand(command)
            else:
                if self.command:
                    self.logdispatcher.log(LogPriority.DEBUG,
                                           "Unable to set command " +
                                           str(self.command))

            if (success):
                if (self.commandblank == True):
                    success = False
                    raise ValueError("Cannot Execute a blank command (" +
                                     "".join(self.command) + ")")

            if (success):
                time_start = time.time()
                commandobj = subprocess.Popen(self.command,
                                              stdout=subprocess.PIPE,
                                              stderr=subprocess.PIPE,
                                              shell=self.shell)
                if self.cmdtimeout:
                    while commandobj.poll() is None:
                        if time.time() - time_start >= self.cmdtimeout:
                            commandobj.terminate()
                            commandobj.returncode = -1
                            self.logdispatcher.log(LogPriority.DEBUG, "Command exceeded specified max. run time of: " + str(self.cmdtimeout) + " seconds! Command aborted!")
                            commandaborted = True
                            break
                        else:
                            continue

                if commandaborted:
                    success = False
                    self.returncode = commandobj.returncode
                    return success

                outlines = []
                errlines = []
                outstr = ''
                # If we are not waiting, we cannot collect stdout and stderr
                if self.wait:

                    if commandobj is not None:
                        outs, errs = commandobj.communicate()
                        outlines = str(outs).splitlines()
                        errlines = str(errs).splitlines()
                        outstr = str(outs)

                if commandobj is not None:
                    self.stdout = outlines
                    self.stderr = errlines
                    self.output = self.stderr + self.stdout

                    self.returncode = commandobj.returncode
                    msg = "returncode: " + str(self.returncode)
                    self.logdispatcher.log(self.logpriority, msg)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception, err:
            success = False
            msg = str(err) + " - " + str(traceback.format_exc())
            self.logdispatcher.log(LogPriority.ERROR, msg)
            raise
        else:
            if commandobj is not None:
                if commandobj.stdout is not None:
                    commandobj.stdout.close()
                if commandobj.stderr is not None:
                    commandobj.stderr.close()
        finally:

            msg = "You should not see this. CommandHelper.executeCommand()"
            if self.returncode is not None:
                msg = "returncode:(" + str(self.returncode) + ") \noutput:(" + str(outstr) + "); command:(" + str(self.command) + ")"
            else:
                msg = "returncode:(None) \noutput:(" + str(outstr) + "); command:(" + str(self.command) + ")"
            self.logdispatcher.log(LogPriority.DEBUG, msg)

        return success

###############################################################################

    def findInOutput(self, expression, searchgroup="output", dtype="list"):
        '''
        findInOutput (expression) finds an expression in the combined stderr
        and stdout
        @param self:essential if you override this definition
        @param expression string: expression to search for in searchgroup
        @param searchgroup string: group to search in output, stdout, stderr
        @param dtype string: search as list or string
        @return: bool indicating success or failure
        @author: ekkehard j. koch
        @author: dwalker
        '''

        try:
            searchstring = ""
            msg = ""
            success = False
            if searchgroup == "output":
                searchstream = self.output
            elif searchgroup == "stdout":
                searchstream = self.stdout
            elif searchgroup == "stderr":
                searchstream = self.stderr
            else:
                searchstream = self.output
            if dtype == "list":
                for line in searchstream:
                    if re.search(expression, line):
                        success = True
                        if msg == "":
                            msg = "found in line = " + str(line)
                        else:
                            msg = msg + \
                            ", found in line = " + str(line)
                self.logdispatcher.log(self.logpriority, msg)
            elif dtype == "string":
                searchstring = self.getOutputString()
                msg = "string: " + str(searchstring)
                self.logdispatcher.log(self.logpriority, msg)
                if self.flag:
                    if self.flag == "DOTALL":
                        if re.search(expression, searchstring, \
                                     flags=re.DOTALL):
                            success = True
                            msg = "flag = " + str(self.flag)
                    elif self.flag == "DEBUG":
                        if re.search(expression, searchstring, flags=re.DEBUG):
                            success = True
                            msg = "flag = " + str(self.flag)
                    elif self.flag == "LOCALE":
                        if re.search(expression, searchstring, \
                                     flags=re.LOCALE):
                            success = True
                            msg = "flag = " + str(self.flag)
                    elif self.flag == "MULTILINE":
                        if re.search(expression, searchstring, \
                                     flags=re.MULTILINE):
                            success = True
                            msg = "flag = " + str(self.flag)
                    elif self.flag == "UNICODE":
                        if re.search(expression, searchstring, \
                                     flags=re.UNICODE):
                            success = True
                            msg = "flag = " + str(self.flag)
                    elif self.flag == "VERBOSE":
                        if re.search(expression, searchstring, \
                                     flags=re.VERBOSE):
                            success = True
                            msg = "flag = " + str(self.flag)
                    else:
                        if re.search(expression, searchstring):
                            success = True
                        msg = "unrecognized flag = " + str(self.flag)
                else:
                    if re.search(expression, searchstring):
                        success = True
                        msg = "no flag"
                if success:
                    msg = msg + ", found = " + \
                    str(searchstring)
                else:
                    msg = msg + ", not found = " + \
                    str(searchstring)
            msg = "expression = " + str(expression) + ", " + \
            "searchgroup = " + str(searchgroup) + ", " + \
            "dtype = " + str(dtype) + ", " + \
            str(msg) + ", " + \
            "success = " + str(success) + ";"
            self.logdispatcher.log(LogPriority.DEBUG, msg)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception, err:
            success = False
            msg = str(err) + " - " + str(traceback.format_exc())
            self.logdispatcher.log(LogPriority.DEBUG, msg)
            raise
        return success
