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
@change: 2019/08/07 Brandon R. Gonzales - Command output and error output are
        now being decoded to 'utf-8', and are being treated as 'str' types
        instead of 'bytes' types
        
"""

import inspect
import re
import subprocess
import traceback
import time

from stonix_resources.logdispatcher import LogPriority


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

        :param str expression: expression to search for
        :param groupnumber: integer: number of group to return
        :param searchgroup: string: group to search in output, stdout, stderr (Default value = "output")

        :return: returnstring
        :rtype: bool

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
        error string could be one of several types:
        bytes (or bytes-like object)
        list
        string
        we need to handle all cases

        :return: errstring
        :rtype: string

        """

        errstring = ""

        try:

            if self.stderr:
                if type(self.stderr) is str:
                    errstring = self.stderr
                elif type(self.stderr) is list:
                    for i in self.stderr:
                        if type(i) is str:
                            errstring += "\n" + i
                        elif type(i) is bytes:
                            errstring += "\n" + i.decode('utf-8')
                        elif type(i) is int:
                            errstring += "\n" + str(i)

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

    def getReturnCode(self):
        """Get return code for last executed command


        :returns: self.returncode

        :rtype: int
@author: ekkehard j. koch

        """

        return self.returncode

    def validate_command(self, command):
        """
        A valid format for a command is:
        list of non-empty strings
        -or-
        non-empty string

        :param command: the command to evaluate
        """

        self.valid_command = True

        self.logdispatcher.log(LogPriority.DEBUG, "Validating command format...")

        command_type = type(command)

        valid_types = [list, str]

        if command_type not in valid_types:
            self.logdispatcher.log(LogPriority.DEBUG, "Invalid data type for command. Expecting: str or list. Got: " + str(command_type))
            self.valid_command = False

        if command == "":
            self.logdispatcher.log(LogPriority.DEBUG, "Command was an empty string. Cannot run nothing")
            self.valid_command = False
        elif command == []:
            self.logdispatcher.log(LogPriority.DEBUG, "Command was an empty list. Cannot run nothing")
            self.valid_command = False

        if not self.valid_command:
            self.logdispatcher.log(LogPriority.DEBUG, "Command is not a valid format")

    def convert_bytes_to_string(self, data):
        """

        :param data:
        :return: data
        :rtype: str|list
        """

        self.logdispatcher.log(LogPriority.DEBUG, "Converting any bytes objects into strings...")

        data_type = type(data)

        if data_type is list:
            for e in data:
                if type(e) is bytes:
                    data = [e.decode('utf-8') for e in data]
        elif data_type is bytes:
            data = data.decode('utf-8')
            data = str(data)

        return data

    def set_shell_bool(self, command_type):
        """

        :param command_type: data type
        """

        self.shell = True

        if command_type is list:
            self.shell = False

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
@change: Brandon R. Gonzales - 05/08/2019 - Change commandtype conditionals to
        check if the command type is 'str' instead of 'bytes'

        """

        success = True

        try:

            # convert any bytes objects to strings
            command = self.convert_bytes_to_string(command)

            # validate the format of the command
            self.validate_command(command)

            if not self.valid_command:
                self.logdispatcher.log(LogPriority.DEBUG, "Cannot run invalid command")
                success = False
                return success

            command_type = type(command)

            # determine whether to use shell or no in subprocess command
            self.set_shell_bool(command_type)

            # strip command or command elements
            if command_type is str:
                self.command = command.strip()
            elif command_type is list:
                command = [li.strip() for li in command]

            self.command = command

            self.logdispatcher.log(LogPriority.DEBUG, "Command set to: " + str(self.command))

        except Exception:
            self.logdispatcher.log(LogPriority.ERROR, str(traceback.format_exc()))
            raise

        return success

    def setLogPriority(self, logpriority=None):
        """Setting log priority use LogPriority.DEBUG, LogPrority.ERROR, etc.

        :param logpriority: of type LogPriority.xxx (Default value = None)
        :returns: success
        :rtype: bool
@author: ekkehard j. koch

        """

        success = True

        logprioritytype = type(logpriority)
        #print("logprioritytype: ", logprioritytype, "\n")
        if (logpriority is None):
            self.logpriority = LogPriority.DEBUG
        elif isinstance(logpriority, str):
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
        """
        attempt to execute the given command

        :param command: string or list: command to set the command property to (Default value = None)
        :return: success
        :rtype: bool

        """

        commandaborted = False
        commandobj = None
        success = True
        self.stdout = []
        self.stderr = []
        self.output = []

        try:

            if not self.setCommand(command):
                success = False
                return success
            start_time = time.time()
            self.logdispatcher.log(LogPriority.DEBUG, "Beginning new command execution")
            commandobj = subprocess.Popen(self.command,
                                          stdout=subprocess.PIPE,
                                          stderr=subprocess.PIPE,
                                          shell=self.shell)

            # if a time limit is specified for this command run,
            # time out if that limit is reached
            if self.cmdtimeout:
                while commandobj.poll() is None:
                    if time.time() - start_time >= self.cmdtimeout:
                        commandobj.terminate()
                        commandobj.returncode = -1
                        self.logdispatcher.log(LogPriority.DEBUG, "Command run exceeded timeout limit. Command run aborted.")
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
                    outs = self.convert_bytes_to_string(outs)
                    errs = self.convert_bytes_to_string(errs)
                    outlines = outs.splitlines()
                    errlines = errs.splitlines()
                    outstr = str(outs)

            if commandobj is not None:
                self.stdout = outlines
                self.stderr = errlines
                self.output = self.stderr + self.stdout
                outstr = " ".join(self.output)

            self.returncode = commandobj.returncode

            try:
                commandobj.stdout.close()
            except:
                pass
            try:
                commandobj.stderr.close()
            except:
                pass

            if "outstr" not in locals():
                outstr = ""

            self.logdispatcher.log(LogPriority.DEBUG, "Command: " + str(self.command))
            self.logdispatcher.log(LogPriority.DEBUG, "Output: " + str(outstr))
            self.logdispatcher.log(LogPriority.DEBUG, "Return Code: " + str(self.returncode))

            if success:
                self.logdispatcher.log(LogPriority.DEBUG, "Command executed successfully")
            else:
                self.logdispatcher.log(LogPriority.DEBUG, "Command execution failed")

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.logdispatcher.log(LogPriority.ERROR, str(traceback.format_exc()))

        return success

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
