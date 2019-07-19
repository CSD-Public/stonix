###############################################################################
#                                                                             #
# Copyright 2019. Triad National Security, LLC. All rights reserved.          #
# This program was produced under U.S. Government contract 89233218CNA000001  #
# for Los Alamos National Laboratory (LANL), which is operated by Triad       #
# National Security, LLC for the U.S. Department of Energy/National Nuclear   #
# Security Administration.                                                    #
#                                                                             #
# All rights in the program are reserved by Triad National Security, LLC, and #
# the U.S. Department of Energy/National Nuclear Security Administration. The #
# Government is granted for itself and others acting on its behalf a          #
# nonexclusive, paid-up, irrevocable worldwide license in this material to    #
# reproduce, prepare derivative works, distribute copies to the public,       #
# perform publicly and display publicly, and to permit others to do so.       #
#                                                                             #
###############################################################################


"""
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
        
"""

import inspect
import re
import subprocess
import traceback
import types
import time

from .logdispatcher import LogPriority


class CommandHelper(object):
    """CommandHelper is class that helps with execution of subprocess Popen based
    commands and then finding or parsing strerror and/or strout
    their output.
    @author: rsn
    @author: dwalker
    @author: ekkehard


    """

###############################################################################

    def __init__(self, logdispatcher):
        """
        Initialize all object attributes
        @author: ekkehard j. koch
        """
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
        except Exception as err:
            raise err
        else:
            self.logdispatcher.log(LogPriority.DEBUG, "called by: " + \
                                      filename + ": " + \
                                      functionName + " (" + \
                                      lineNumber + ")")
        return " Filename: " + str(filename) + "Line: " + str(lineNumber) + " functionName: " + str(functionName)

###############################################################################

    def getCommand(self):
        """Get the current command.

        :param self: essential if you override this definition
        :returns: string or list of command
        @author: ekkehard j. koch

        """
        return self.command

###############################################################################

    def getError(self):
        """Get standard error stream for last executed command

        :param self: essential if you override this definition
        :returns: list of standard error stream
        @author: ekkehard j. koch

        """
        return self.stderr

###############################################################################

    def getErrorOutput(self):
        """Get standard out stream and standard error for last executed command

        :param self: essential if you override this definition
        :returns: list of output
        @author: ekkehard j. koch

        """

        return self.output

###############################################################################

    def getOutput(self):
        """Get standard out stream for last executed command

        :param self: essential if you override this definition
        :returns: self.stdout
        :rtype: list
@author: ekkehard j. koch
@change: Breen Malmberg - 12/3/2015

        """

        return self.stdout

###############################################################################

    def getOutputGroup(self, expression, groupnumber, searchgroup="output"):
        """getOutputGroup (expression,groupnumber) finds an expression in the
        returns the specified group after using regular expression on output

        :param self: essential if you override this definition
        :param expression: string: expression to search for in searchgroup
        :param groupnumber: integer: number of group to return
        :param searchgroup: string: group to search in output, stdout, stderr (Default value = "output")
        :returns: returnlist
        :rtype: list
@author: rsn
@change: Breen Malmberg - 12/3/2015

        """

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
        """getOutputGroup (expression, groupnumber) finds an expression in the
        returns the first instance (string) of the group specified in the
        regular expression that is found in the output.

        :param self: essential if you override this definition
        :param expresssion: string: expression to search for
        :param groupnumber: integer: number of group to return
        :param searchgroup: string: group to search in output, stdout, stderr (Default value = "output")
        :param expression: 
        :returns: returnstring
        :rtype: bool
@author: rsn
@change: Breen Malmberg - 12/3/2015

        """

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
        """Get standard out in string format

        :param self: essential if you override this definition
        :returns: stdstring
        :rtype: string
@author: ekkehard j. koch
@change: Breen Malmberg - 12/3/2015

        """

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
        """Get standard error in string format

        :param self: essential if you override this definition
        :returns: self.stderr
        :rtype: string
@author: dwalker
@change: Breen Malmberg - 12/3/2015

        """

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
        """Get both the stdout and stderr together as one string

        :param self: essential if you override this definition
        :returns: allstring
        :rtype: string
@author: Breen Malmberg

        """

        allstring = ""

        stdoutstring = self.getOutputString()
        stderrstring = self.getErrorString()

        try:

            if not isinstance(stdoutstring, str):
                self.logdispatcher.log(LogPriority.DEBUG,
                                       "Content of parameter stdoutstring " +
                                       "is not in string format. Will not " +
                                       "include content in output!")
                stdoutstring = ""

            if not isinstance(stderrstring, str):
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
        """Get both the stdout and stderr together as one list

        :param self: essential if you override this definition
        :returns: alllist
        :rtype: list
@author: Breen Malmberg

        """

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
        """Get return code for last executed command


        :returns: self.returncode

        :rtype: bool
@author: ekkehard j. koch

        """

        return self.returncode

###############################################################################

    def setCommand(self, command):
        """setCommand (command) set the command for the CommandHelper

        :param command: string: command to set the command property to
        :returns: success
        :rtype: bool
@author: ekkehard j. koch
@change: Breen Malmberg - 04/11/2018 - fixed a typo in the msg = on line 472;
        fixed doc string; removed most of the raiseexception calls (they were unnecessary
        since the entire code block is already encapsulated with a try except; also removed
        the call to explicit exception type within the except portion as that is
        automatically detected and reported by python and overriding that can lead to
        incorrect except type reporting in debug logs; added a logger error log call within
        the except block with the appropriate message; removed possible variable confusion
        issue by assigning a unique variable to list items to determine their type
        rather than assigning the type of each list item to the same variable being used
        to determine the type of the command parameter being passed in; added default
        variable initializations to several uninitialized method-scope variables;
        pulled the default variable initializations outside of the try except (these will
        never fail); removed repeated instances of command variable checking and made
        a single check at the beginning of the rule, with debug output; changed the default
        initialization of the variable 'success' to True which removed the need for several
        redundant instances of setting it to True when there were also already instances of
        it being set to False (one or the other; both are not needed explicitly)

        """

        success = True
        self.stdout = []
        self.stderr = []
        self.output = []
        msg = ""
        message = ""

        try:

            if command == "":
                msg = "The given command string parameter was blank!"
                self.logdispatcher.log(LogPriority.DEBUG, msg)
                raise ValueError(msg)

            if command == []:
                msg = "The given command list parameter was empty!"
                self.logdispatcher.log(LogPriority.DEBUG, msg)
                raise ValueError(msg)


            commandtype = type(command)

            if (commandtype is bytes):
                self.shell = True
                if len(command.strip()) > 0:
                    self.commandblank = False
                self.command = command.strip()
                msg = "Command Set To '" + self.command + "'"
                self.logdispatcher.log(LogPriority.DEBUG, msg)

            elif (commandtype is list):
                self.shell = False
                self.command = []
                self.commandblank = True

                for commandlistitem in command:
                    commandlitype = type(commandlistitem)

                    if (commandlitype is bytes):
                        self.command.append(commandlistitem.strip())
                        if len(commandlistitem.strip()) > 0:
                            self.commandblank = False
                    else:
                        success = False
                        msg = "Command List Item '" + str(commandlistitem) + \
                            "' has in invalid type of '" + str(commandlitype) + "'"
                        self.logdispatcher.log(LogPriority.DEBUG, msg)

                msg = "Command Set To '" + str(self.command) + "'"
                self.logdispatcher.log(LogPriority.DEBUG, msg)

            else:
                success = False
                msg = "Command '" + str(command) + "' has an invalid type of '" + \
                    str(commandtype) + "'"
                self.logdispatcher.log(LogPriority.DEBUG, msg)

        except Exception:
            message = str(self.__calledBy()) + "\nInvalid command input: " + str(traceback.format_exc())
            self.logdispatcher.log(LogPriority.ERROR, message)
        return success

###############################################################################

    def setLogPriority(self, logpriority=None):
        """Setting log priority use LogPriority.DEBUG, LogPrority.ERROR, etc.

        :param logpriority: of type LogPriority.xxx (Default value = None)
        :returns: success
        :rtype: bool
@author: ekkehard j. koch

        """

        success = True

        logprioritytype = type(logpriority)
        if (logpriority is None):
            self.logpriority = LogPriority.DEBUG
        elif isinstance(logprioritytype, bytes):
        # elif (logprioritytype is bytes):
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
        """Set the Regular Expression Flag.

        :param self: essential if you override this definition
        :param flag: used in regular expression
        @author: rsn

        """
        if flag in self.flags:
            self.flag = flag

###############################################################################

    def executeCommand(self, command=None):
        """executeCommand (command) excecute the command for the CommandHelper

        :param self: essential if you override this definition
        :param command: string or list: command to set the command property to (Default value = None)
        :returns: bool indicating success or failure
        @author: ekkehard j. koch

        """

        commandaborted = False
        commandobj = None
        success = True

        try:

            if type(command) is not None:
                success = self.setCommand(command)
            else:
                if self.command:
                    self.logdispatcher.log(LogPriority.DEBUG,
                                           "Unable to set command " +
                                           str(self.command))

            if success:
                if self.commandblank:
                    success = False
                    self.logdispatcher.log(LogPriority.WARNING, "Attempted to execute a blank command!")

            if success:
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
                outstr = ""
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
                    outstr = " ".join(self.output)

                    self.returncode = commandobj.returncode
                    msg = "returncode: " + str(self.returncode)
                    self.logdispatcher.log(self.logpriority, msg)

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as err:
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
            if 'outstr' not in locals():
                outstr = ""
            msg = "You should not see this. CommandHelper.executeCommand()"
            if self.returncode is not None:
                msg = "returncode:(" + str(self.returncode) + ") \noutput:(" + str(outstr) + "); command:(" + str(self.command) + ")"
            else:
                msg = "returncode:(None) \noutput:(" + str(outstr) + "); command:(" + str(self.command) + ")"
            self.logdispatcher.log(LogPriority.DEBUG, msg)

        return success

###############################################################################

    def findInOutput(self, expression, searchgroup="output", dtype="list"):
        """findInOutput (expression) finds an expression in the combined stderr
        and stdout

        :param self: essential if you override this definition
        :param expression: string: expression to search for in searchgroup
        :param searchgroup: string: group to search in output, stdout, stderr (Default value = "output")
        :param dtype: string: search as list or string (Default value = "list")
        :returns: bool indicating success or failure
        @author: ekkehard j. koch
        @author: dwalker

        """

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
        except Exception as err:
            success = False
            msg = str(err) + " - " + str(traceback.format_exc())
            self.logdispatcher.log(LogPriority.DEBUG, msg)
            raise
        return success
