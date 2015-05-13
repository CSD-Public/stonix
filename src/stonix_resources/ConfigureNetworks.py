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
This method runs all the report methods for RuleKVEditors in defined in the
dictionary

@author: ekkehard j. koch
@change: 2015/05/07 ekkehard Original Implementation
'''
import re
import sys
import inspect
import subprocess
import traceback
import types
from subprocess import call


class ConfigureNetworks():
    '''

    @author: ekkehard j. koch
    '''

###############################################################################

    def __init__(self):
        self.location = ""
        self.locationIsValidWiFiLocation = False
        self.locationInitialized = False
        self.ns = {}
        self.nsInitialized = False
        self.nso = {}
        self.nsInitialized = False
        self.nsc = "/usr/sbin/networksetup"
        self.ch = CommandHelperLite()
        self.getLocation()
        self.updateCurrentNetworkConfigurationDictionary()

###############################################################################

    def getLocation(self):
        try:
            success = True
            command = [self.nsc, "-getcurrentlocation"]
            self.ch.executeCommand(command)
            for line in self.ch.getOutput():
                lineprocessed = line.strip()
                self.location = lineprocessed
                self.locationInitialized = True
            self.locationIsValidWiFiLocation = self.isValidLocationName(self.location)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            success = False
            raise
        return success

###############################################################################

    def updateCurrentNetworkConfigurationDictionary(self):
        try:
            success = True
# issue networksetup -listallnetworkservices to get all network services
            command = [self.nsc, "-listnetworkserviceorder"]
            self.ch.executeCommand(command)
            order = -1
            newserviceonnexline = False
            newservice = False
            noinfo = False
            for line in self.ch.getOutput():
                if newserviceonnexline:
                    newservice = True
                    newserviceonnexline = False
                else:
                    newservice = False
                    newserviceonnexline = False
                if line == "An asterisk (*) denotes that a network service is disabled.\n":
                    infoOnThisLine = False
                    newserviceonnexline = True
                elif line == "\n":
                    infoOnThisLine = False
                    newserviceonnexline = True
                else:
                    infoOnThisLine = True
                lineprocessed = line.strip()
                if newservice and infoOnThisLine:
                    order = order + 1
# see if network is enabled
                    if lineprocessed[:3] == "(*)":
                        networkenabled = False
                    else:
                        networkenabled = True
                    linearray = lineprocessed.split()
                    linearray = linearray[1:]
                    servicename = ""
                    for item in linearray:
                        if servicename == "":
                            servicename = item
                        else:
                            servicename = servicename + " " + item
                    self.ns[servicename] = {"name": servicename,
                                            "enabled": networkenabled}
# determine network type
                elif infoOnThisLine:
                    lineprocessed = lineprocessed.strip("(")
                    lineprocessed = lineprocessed.strip(")")
                    linearray = lineprocessed.split(",")
                    for item in linearray:
                        lineprocessed = item.strip()
                        itemarray = lineprocessed.split(":")
                        self.ns[servicename][itemarray[0].strip().lower()] = itemarray[1].strip()
                    hardwareport = self.ns[servicename]["hardware port"].lower()
                    splitline = hardwareport.split()
                    networktype = ""
                    for item in splitline:
                        if item.lower() == "ethernet":
                            networktype = item.lower()
                        elif item.lower() == "bluetooth":
                            networktype = item.lower()
                        elif item.lower() == "usb":
                            networktype = item.lower()
                        elif item.lower() == "wi-fi":
                            networktype = item.lower()
                        elif item.lower() == "firewire":
                            networktype = item.lower()
                        elif item.lower() == "thunderbolt":
                            networktype = item.lower()
                    if networktype == "":
                        networktype = "unknown"
# update dictionary entry for network
                    self.ns[servicename]["type"] = networktype
# create an ordered list to look up later
                    orderkey = str(order).zfill(4)
                    self.nso[orderkey] = servicename
                    self.updateNetworkConfigurationDictionaryEntry(servicename)
            self.nsInitialized = True
            self.nsoInitialized = True
        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception:
            success = False
            raise
        return success

###############################################################################

    def updateNetworkConfigurationDictionaryEntry(self, pKey):
        try:
            success = True
            key = pKey
            entry = self.ns[key]
            if success:
                if entry == None:
                    success = False
            if success:
                command = [self.nsc, "-getmacaddress", key]
                self.ch.executeCommand(command)
                for line in self.ch.getOutput():
                    try:
                        macaddress = re.search("(\w\w:\w\w:\w\w:\w\w:\w\w:\w\w)",
                                               line.strip()).group(1)
                    except:
                        macaddress = ""
                    self.ns[key]["macaddress"] = macaddress
            if success:
                command = [self.nsc,
                           "-getnetworkserviceenabled", key]
                self.ch.executeCommand(command)
                for line in self.ch.getOutput():
                    lineprocessed = line.strip()
                    if lineprocessed == "Enabled":
                        self.ns[key]["enabled"] = True
                    else:
                        self.ns[key]["enabled"] = False
        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception:
            success = False
            raise
        return success

###############################################################################

    def isValidLocationName(self, pLocationName=""):
        success = False
        if pLocationName == "":
            locationName = self.location.lower()
        else:
            locationName = pLocationName.lower()
        if 'wi-fi' in locationName:
            success = True
        elif 'wireless' in locationName:
            success = True
        elif 'airport' in locationName:
            success = True
        elif 'off-site' in locationName:
            success = True
        elif 'offsite' in locationName:
            success = True
        else:
            success = False
        return success

###############################################################################

    def disableNetworkService(self, pNetworkName):
        try:
            success = True
            networkName = pNetworkName
            if networkName == "":
                success = False
            if success:
                command = [self.nsc,
                           "-setnetworkserviceenabled",
                           networkName, "off"]
                self.ch.executeCommand(command)
        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception:
            success = False
            raise
        return success

###############################################################################

    def enableNetwork(self, pNetworkName):
        try:
            success = True
            networkName = pNetworkName
            if networkName == "":
                success = False
            if success:
                command = [self.nsc,
                           "-setnetworkserviceenabled",
                           networkName, "on"]
                self.ch.executeCommand(command)
        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception:
            success = False
            raise
        return success

class CommandHelperLite():
    '''
    CommandHelperLite is class that helps with execution of subprocess Popen based
    commands and then finding or parsing strerror and/or strout
    their output.
    @author: ekkehard
    '''

###############################################################################

    def __init__(self):
        '''
        Initialize all object attributes
        @author: ekkehard j. koch
        '''
        self.logpriority="debug"
        self.logsyslog_level=None
        self.command = []
        self.commandblank = True
        self.returncode = 0
        self.output = []
        self.stdout = []
        self.stderr = []
        self.shell = False

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
            log_message("Group(" + str(groupnumber) + ")='" +
                        groupstr + "'; line='" + line + "'",
                        "debug",
                        self.logpriority,
                        self.logsyslog_level)
            returnlist.append(groupstr)
        log_message("expression = " + str(expression) + ", " + \
                    "groupnumber = " + str(groupnumber) + ", " + \
                    "searchgroup = " + str(searchgroup) + " = " + \
                    "returnlist = " + str(returnlist) + ";",
                    "normal",
                    self.logpriority, self.logsyslog_level)
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
                log_message("Group(" + str(groupnumber) + ")='" +
                            groupstr + "'; line='" + line + "'",
                            "normal",
                            self.logpriority,
                            self.logsyslog_level)
                returnstring = groupstr
                break

        log_message("expression = " + str(expression) + ", " + \
                    "groupnumber = " + str(groupnumber) + ", " + \
                    "searchgroup = " + str(searchgroup) + " = " + \
                    "returnstring = " + str(returnstring) + ";",
                    "normal",
                    self.logpriority, self.logsyslog_level)
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
            log_message(msg,
                        "normal",
                        self.logpriority, self.logsyslog_level)
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
            log_message(msg,
                        "normal",
                        self.logpriority, self.logsyslog_level)
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
                log_message(msg,
                            "normal",
                            self.logpriority,
                            self.logsyslog_level)
                raise ValueError(msg)
            self.command = command.strip()
            success = True
            log_message("Command Set To '" +
                        self.command + "'",
                        "normal",
                        self.logpriority,
                        self.logsyslog_level)
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
                    log_message(msg,
                                "normal",
                                self.logpriority,
                                self.logsyslog_level)
                    raise ValueError(msg)

            log_message("Command Set To '" +
                        str(self.command) + "'",
                        "debug",
                        self.logpriority,
                        self.logsyslog_level)
        else:
            success = False
            msg = "Command '" + str(command) + "' has in invalid type of '" + \
            str(commandtype) + "'"
            log_message(msg,
                        "normal",
                        self.logpriority,
                        self.logsyslog_level)
            raise TypeError(msg)
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
                if self.wait:
                    commandobj.wait()

                if commandobj is not None:

                    self.stdout = commandobj.stdout.readlines()

                    self.stderr = commandobj.stderr.readlines()
                    self.output = self.stderr + self.stdout

                    self.returncode = commandobj.returncode

                    log_message("returncode: " +
                                str(self.returncode),
                                "debug",
                                self.logpriority,
                                self.logsyslog_level)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception, err:
            success = False
            messagestring = str(err) + " - " + str(traceback.format_exc())
            log_message(messagestring,
                        "normal",
                        self.logpriority,
                        self.logsyslog_level)
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
            log_message(logstring,
                        "normal",
                        self.logpriority,
                        self.logsyslog_level)

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
                    log_message("list item: " + \
                                str(line),
                                "debug",
                                self.logpriority,
                                self.logsyslog_level)
            elif dtype == "string":
                searchstring = self.getOutputString()
                log_message("string: " + str(searchstring),
                            "debug",
                            self.logpriority,
                            self.logsyslog_level)
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

            log_message("expression = " + str(expression) + ", " + \
                        "searchgroup = " + str(searchgroup) + ", " + \
                        "dtype = " + str(dtype) + ", " + \
                        str(messagestring) + ", " + \
                        "success = " + str(success) + ";",
                        "normal",
                        self.logpriority,
                        self.logsyslog_level)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception, err:
            success = False
            messagestring = str(err) + " - " + str(traceback.format_exc())
            log_message(messagestring,
                        "normal",
                        self.logpriority,
                        self.logsyslog_level)
            raise
        return success


def log_message(message="",
                level="normal",
                priority="debug",
                syslog_level=None):
    """
    Logs a message to both stdout and to syslog via logger

    message - the message to log

    level - print the message if this value is less than or equal to
            the \"priority\"

    priority - defined value to used to compare with the \"level\".  If
               the level is less than or equal to the priority value,
               the message will be printed to stdout and via logger

    syslog_level - the syslog level to log with

    Author: Roy Nielsen
    """
    if syslog_level is None:
        syslog_level = ""
    else:
        syslog_level = "-p " + syslog_level + " "

    if not re.match("^normal$", level):
        prog = sys.argv[0]
# message to be in the format:
# <calling_script_name> : <name_of_calling_function>
# (<line number of calling function>) - <LEVEL>: <message to print>
        message = str(prog) + " : " + \
        inspect.stack()[1][3] + " (" + str(inspect.stack()[1][2]) + ") - " + \
        level.upper() + ": " + str(message)
    else:
        prog = sys.argv[0]
        message = str(prog) + " - " + inspect.stack()[1][3] + \
        " (" + str(inspect.stack()[1][2]) + ") - " + " : " + str(message)

    levels = ['quiet', 'normal', 'verbose', 'debug']

    if levels.index(level) <= levels.index(priority):

        print message
        cmd_string = "/usr/bin/logger " + syslog_level + "\"" + message + "\""
        retcode = ""
        try:
            retcode = call(cmd_string, shell=True)
            if retcode < 0:
                print >> sys.stderr, \
                         "logger Child was terminated by signal", \
                        -retcode
            else:
                pass

        except OSError, err:
            print >> sys.stderr, \
                     "Execution of " + \
                     str(cmd_string) + \
                     " failed: ", \
                     err