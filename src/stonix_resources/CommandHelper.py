'''
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

@author: ekkehard j. koch
@author: rsn
@author: dwalker
@change: 11/19/2013 ekkehard original implementation
@change: 04/01/2014 rsn added getOutputGroup & getFirstOutputGroup
@change: 04/01/2014 dwalker added setRegexFlag & enhanced findInOutput
@change: 04/15/2014 ekkehard enhance documentation & pep8 compliance
@change: 04/15/2014 ekkehard made logging more intelligent
@change: 10/20/2014 ekkehard fix pep8 viloation
'''
import re
import subprocess
import traceback
import types
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
        @return: list of standard out stream
        @author: ekkehard j. koch
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
        @return: bool indicating success or failure
        @author: rsn
        '''
        returnlist = []
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
            self.logdispatcher.log(LogPriority.DEBUG,
                                   "Group(" + str(groupnumber) + ")='" +
                                   groupstr + "'; line='" + line + "'")
            returnlist.append(groupstr)
        self.logdispatcher.log(LogPriority.DEBUG,
                               "expression = " + str(expression) + ", " + \
                               "groupnumber = " + str(groupnumber) + ", " + \
                               "searchgroup = " + str(searchgroup) + " = " + \
                               "returnlist = " + str(returnlist) + ";")
        return returnlist

###############################################################################

    def getFirstOutputGroup(self,
                            expression,
                            groupnumber,
                            searchgroup="output"):
        '''
        getOutputGroup (expression, groupnumber) finds an expression in the
        returns the first instance (string) of the group specified in the
        regular expression that is found in the output.
        @param self:essential if you override this definition
        @param expresssion string: expression to search for
        @param groupnumber integer: number of group to return
        @param searchgroup string: group to search in output, stdout, stderr
        @return: bool indicating success or failure
        @author: rsn
        '''
        returnstring = ""
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
                self.logdispatcher.log(LogPriority.DEBUG,
                                       "Group(" + str(groupnumber) + ")='" +
                                       groupstr + "'; line='" + line + "'")
                returnstring = groupstr
                break

        self.logdispatcher.log(LogPriority.DEBUG,
                               "expression = " + str(expression) + ", " + \
                               "groupnumber = " + str(groupnumber) + ", " + \
                               "searchgroup = " + str(searchgroup) + " = " + \
                               "returnstring = " + str(returnstring) + ";")
        return returnstring

###############################################################################

    def getOutputString(self):
        '''
        Get standard out in string format
        @param self:essential if you override this definition
        @return: string of self.output
        @author: ekkehard j. koch
        '''
        #should this be self.stdout instead of self.output?
        #self.output is both stderr and stdout together, should have a 
        #separate method for getting a string of both together
        outputstr = ""
        if self.output:
            for line in self.output:
                outputstr += line
        else:
            msg = "self.output contents is empty nothing to return"
            self.logdispatcher.log(LogPriority.DEBUG, msg)
            #####
            # An empty string is a valid value, DO NOT raise error here.
            #raise ValueError(msg)
            outputstr = outputstr.strip()
        return outputstr

###############################################################################

    def getErrorString(self):
        '''
        Get standard error in string format
        @param self:essential if you override this definition
        @return: string of stderr
        @author: dwalker
        '''
        errorstr = ""
        if self.stderr:
            for line in self.stderr:
                errorstr += line
        else:
            msg = "self.stderr contents is empty nothing to return"
            self.logdispatcher.log(LogPriority.DEBUG, msg)
            #####
            # An empty string is a valid value, DO NOT raise error here.
            #raise ValueError(msg)
            errorstr = errorstr.strip()
        return errorstr
    
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
                msg = "The command is of type '" + str(commandtype) + \
                "' is blank!"
                self.logdispatcher.log(LogPriority.DEBUG, msg)
                raise ValueError(msg)
            self.command = command.strip()
            success = True
            self.logdispatcher.log(LogPriority.DEBUG,
                                   "Command Set To '" +
                                   self.command + "'")
        elif (commandtype is types.ListType):
            self.shell = False
            self.command = []
            self.commandblank = True
            success = True
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
                    raise ValueError(msg)

            self.logdispatcher.log(LogPriority.DEBUG,
                               "Command Set To '" +
                                str(self.command) + "'")
        else:
            success = False
            msg = "Command '" + str(command) + "' has in invalid type of '" + \
            str(commandtype) + "'"
            self.logdispatcher.log(LogPriority.DEBUG, msg)
            raise TypeError(msg)
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
        try:
            commandobj = None
            success = True
            if (type(command) is not None):
                success = self.setCommand(command)

            if (success):
                if (self.commandblank == True):
                    success = False
                    raise ValueError("Cannot Execute a blank command (" + \
                                           "".join(self.command) + ")")

            if (success):
                commandobj = subprocess.Popen(self.command,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, 
                               shell=self.shell)
                outlines = []
                errlines = []
                for line in iter(commandobj.stdout.readline, ''):
                    outlines.append(line)
                commandobj.stdout.close()
                for line in iter(commandobj.stderr.readline, ''):
                    errlines.append(line)
                commandobj.stderr.close()

                if self.wait:
                    commandobj.wait()

                if commandobj is not None:
                    self.stdout = outlines
                    self.stderr = errlines
                    self.output = self.stderr + self.stdout

                    self.returncode = commandobj.returncode

                    self.logdispatcher.log(self.logpriority,
                                           "returncode: " +
                                            str(self.returncode))
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception, err:
            success = False
            messagestring = str(err) + " - " + str(traceback.format_exc())
            self.logdispatcher.log(LogPriority.DEBUG, messagestring)
            raise
        else:
            if commandobj is not None:
                if commandobj.stdout is not None:
                    commandobj.stdout.close()
                if commandobj.stderr is not None:
                    commandobj.stderr.close()
        finally:
            logstring = "You should not see this. CommandHelper.executeCommand()"
            if self.returncode is not None:
                logstring = "returncode:(" + str(self.returncode) + ") output:(" + str(self.output) + "); command:(" + str(self.command) + ")"
            else:
                logstring = "returncode:(None) output:(" + str(self.output) + "); command:(" + str(self.command) + ")"
            self.logdispatcher.log(LogPriority.DEBUG, logstring)

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
            messagestring = ""
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
                        if messagestring == "":
                            messagestring = "found in line = " + str(line)
                        else:
                            messagestring = messagestring + \
                            ", found in line = " + str(line)
                    self.logdispatcher.log(self.logpriority, "list item: " + \
                                           str(line))
            elif dtype == "string":
                searchstring = self.getOutputString()
                self.logdispatcher.log(self.logpriority, "string: " + \
                                           str(searchstring))
                if self.flag:
                    if self.flag == "DOTALL":
                        if re.search(expression, searchstring, \
                                     flags=re.DOTALL):
                            success = True
                            messagestring = "flag = " + str(self.flag)
                    elif self.flag == "DEBUG":
                        if re.search(expression, searchstring, flags=re.DEBUG):
                            success = True
                            messagestring = "flag = " + str(self.flag)
                    elif self.flag == "LOCALE":
                        if re.search(expression, searchstring, \
                                     flags=re.LOCALE):
                            success = True
                            messagestring = "flag = " + str(self.flag)
                    elif self.flag == "MULTILINE":
                        if re.search(expression, searchstring, \
                                     flags=re.MULTILINE):
                            success = True
                            messagestring = "flag = " + str(self.flag)
                    elif self.flag == "UNICODE":
                        if re.search(expression, searchstring, \
                                     flags=re.UNICODE):
                            success = True
                            messagestring = "flag = " + str(self.flag)
                    elif self.flag == "VERBOSE":
                        if re.search(expression, searchstring, \
                                     flags=re.VERBOSE):
                            success = True
                            messagestring = "flag = " + str(self.flag)
                    else:
                        if re.search(expression, searchstring):
                            success = True
                        messagestring = "unrecognized flag = " + str(self.flag)
                else:
                    if re.search(expression, searchstring):
                        success = True
                        messagestring = "no flag"
                if success:
                    messagestring = messagestring + ", found = " + \
                    str(searchstring)
                else:
                    messagestring = messagestring + ", not found = " + \
                    str(searchstring)

            self.logdispatcher.log(LogPriority.DEBUG,
                               "expression = " + str(expression) + ", " + \
                               "searchgroup = " + str(searchgroup) + ", " + \
                               "dtype = " + str(dtype) + ", " + \
                               str(messagestring) + ", " + \
                               "success = " + str(success) + ";")
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception, err:
            success = False
            messagestring = str(err) + " - " + str(traceback.format_exc())
            self.logdispatcher.log(LogPriority.DEBUG, messagestring)
            raise
        return success
