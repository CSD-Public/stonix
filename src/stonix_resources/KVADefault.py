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

'''
Created on Apr 10, 2013

@author: dwalker
@change: 02/26/2014 ekkehard fixed couple of type error and converted print to
log message
@change: 03/18/2014 ekkehard changed defaults to /usr/bin/defaults
@change: 03/18/2014 ekkehard changed print to debug
'''

import re
import CommandHelper
from logdispatcher import LogPriority
from subprocess import call


class KVADefault():

    def __init__(self, path, logger, data):
        '''
        Helper class to assist with Apple Mac OS X default command.
        data should be a dictionary where the value is a list with two values
        minimum, 3 values maximum, the third value is optional.
        {key:[val1, val2, val3]:
        key - the key that is used with the defaults command
        val1 - a regular expression used to determine if the output after the
            command is run represents what we're looking for in a compliant
            system.  It is up to the implementor of this class, i.e. the
            developer to make the regex concrete and exact in order to
            accurately compare the output to the expected output.
        val2 - the actual end portion of the command that will be attached
            to the end of the full default command if the output doesn't
            represent what we're looking for in a compliant system
        val3 - a regular expression flag to increase the accuracy of your
            regex in val1 which will be used in CommandHelper object in this
            class.  This is an optional item and this class will not
            throw an error if it is ommitted.
        The default command does allow for an actual plist value to be
            attached to the end of the command rather than the space separated
            -datatype val -datatype -val scheme
        Please read the default man page but here is an example of how it
            would appear in your data structure:
            The [1] placeholder should be in double quotes along with single
            quotes immediately nested inside them in the format of:
                "\'{\"key1\" = val1;\"key2\" = val2;}';
            or can be nested such as:
                "\'{\"Enabled\" = {\"Hello\" = 1;};}\';"
        making sure to escape literal inner quotes as has been done above'''
        self.host = "-currentHost"
        self.commandlist = []
        self.logger = logger
        self.ch = CommandHelper.CommandHelper(self.logger)
        self.path = path
        self.simple = False
        self.iterator = 0
        self.data = data
        self.write = ""
        self.undo = ""
        self.plist = False
        self.nocmd = False
        self.dc = "/usr/bin/defaults"
        self.output = ""
        self.currentHost = True

    def setPath(self, path):
        '''
        Private method to set the path of the configuration file
        @author: dwalker
        @param path: the path to file to be handled
        '''
        self.path = path
        return True

    def getPath(self):
        '''
        Private method to retrieve the path of the configuration file
        @author: dwalker
        @return: Bool
        '''
        return self.path

    def setData(self, data):
        if data is None:
            return False
        elif data == "":
            return False
        else:
            self.data = data
            return True

    def getData(self):
        return self.data

    def validate(self):
        '''self.data should contain the lowest atomic key value therefore the
        form should always be {key:[val1,val2]}.  val1 can however, be a string
        depicting a dictionary in the form that apple specifies for the plist
        write command, see init pydoc text for format. If second list item is
        None, this indicates that the key shouldn't exist and if it does, a
        delete command will be run to ensure compliancy rather than a write.
        The variable self.currentHost is true by default but may and should be
        set to False in the rule that implements this class due to some
        instances not needing the -currentHost flag and in some cases the
        -currentHost flag causing issues with some systems for that
        particular command.
        @author: dwalker
        @return: Bool
        '''
        for key in self.data:
            if self.currentHost:
                cmd = [self.dc, self.host, "read", self.path, key]
            else:
                cmd = [self.dc, "read", self.path, key]
            if not self.ch.executeCommand(cmd):
                return False
            '''get output in form of list'''
            output = self.ch.getOutput()
            '''get error output in form of list'''
            error = self.ch.getError()
            '''retrieve the innerlist that was passed in with data'''
            innerlist = self.getInnerList(self.data[key])
            try:
                '''make sure implementer didn't put a blank value in either
                required position'''
                if innerlist[0] == "" or innerlist[1] == "":
                    msg = "You have provided no value to be written. Unable \
to create write command."
                    self.logger.log(LogPriority.DEBUG, msg)
                    return False
            except IndexError:
                msg = "The innerlist passed in doesn\'t contain all \
necessary values for the full function of KVADefault\n"
                raise IndexError(msg)
            if output:
                self.output += str(output) + "\n"
                try:
                    if innerlist[2]:
                        '''check to see if a regex flag was set'''
                        self.ch.setRegexFlag(innerlist[2])
                except IndexError:
                    debug = "There is no third place holder of innerlist." + \
                        "Not a problem, it is not required. Continuing\n"
                    self.logger.log(LogPriority.DEBUG, debug)
                '''the output from the default read command contained the
                output we were expecting for a compliant system, all is well,
                returning True'''
                if self.ch.findInOutput(innerlist[0], "output", "string"):
                    return True
                else:
                    return False
            elif error:
                '''when running default read, an error, always means the key
                doesn't exist'''
                self.output += str(error) + " \n"
                errorstring = self.ch.getErrorString()
                '''key doesn't exist'''
                if re.search("does not exist", errorstring):
                    '''and we want it not to exist, so this is ok'''
                    if innerlist[1] is None:
                        return True
                    else:
                        '''but we want an actual value here'''
                        return False
                else:
                    '''there was some other error, possibly a bad command'''
                    msg = "There was some error running defaults read command"
                    raise OSError(msg)
        return True
###############################################################################

    def update(self):
        '''
        Private method to set the write and undo commands associated with
        this object.  Will not run the command until the commit() method
        is run.
        @return: bool'''
        outputstr, errorstr, msg = "", "", ""
        templist, templist1, templist2 = [], [], []
        for key in self.data:
            '''since the innerlist of the dictionary value passed into the
            object (self.data) can be None or something like -int 0, and since
            the write command is being put into a list for running the command,
            the list requires all separated words to be a separate item in the
            list, therefore -int 0 has to be split into two items, which is
            the purpose of temp[]'''
            if self.currentHost:
                cmd = [self.dc, self.host, "read", self.path, key]
            else:
                cmd = [self.dc, "read", self.path, key]
                '''do a defaults read on the current key'''
            if self.ch.executeCommand(cmd):
                '''get output'''
                output = self.ch.getOutput()
                '''get output in form of string'''
                outputstr = self.ch.getOutputString()
                '''get error output'''
                error = self.ch.getError()
                '''get error output in form of string'''
                errorstr = self.ch.getErrorString()
                '''get the contents of the innerlist passed in with data'''
                innerlist = self.getInnerList(self.data[key])
                self.logger.log(LogPriority.DEBUG, "innerlist: " +
                                str(innerlist))
                try:
                    if innerlist[0] == "" or innerlist[1] == "":
                        msg = "You have provided no value to be written.  " + \
                            "Unable to create write command."
                        self.logger.log(LogPriority.DEBUG, msg)
                        return False
                except IndexError:
                    msg = "The innerlist passed in doesn\'t contain all " + \
                        "necessary values for the full function of " + \
                        "KVADefault\n"
                    raise IndexError(msg)
                '''Checking to see if innermost list, placeholder 1 contains a
                value that contains two words such as -int 0 or even full text
                strings'''
                if innerlist[1] is not None:
                    '''the plist value gets set in checkListContents method.
                    This value is false by default but true if placeholder 2 in
                    innerlist is a string of a dictionary type, thus indicating
                    the write command will use a plist to complete'''
                    if not self.plist:
                        if re.search("\s+", innerlist[1].strip()):
                            #create a list of string separated by spaces
                            templist = innerlist[1].split(" ")
                            startquote = False
                            string = ""
                            '''the purpose of this section is to split the
                            write string up by spaces however, since the string
                            can contain innerstring literals, such as,
                            -string "Disable All" we need to make sure we don't
                            split up the string "Disable All" into two separate
                            arguments'''
                            for item in templist:
                                if startquote:
                                    if re.search("\"|\'", item):
                                        '''found inter-nested quote in the
                                        string, in this case, a closing quote
                                        since we already found the opening'''
                                        templist2.append(item)
                                        startquote = False
                                        for item2 in templist2:
                                            string += item2 + " "
                                        templist1.append(string.strip())
                                        string = ""
                                    else:
                                        templist2.append(item)
                                elif re.search("\"|\'", item):
                                    '''found inter-nested quote in the string,
                                    in this case, an opening quote since it's
                                    the first one we've come across'''
                                    if re.search("\"[^\"]*\"", item) or \
                                            re.search("\'[^\']*\'", item):
                                        templist1.append(item)
                                    else:
                                        startquote = True
                                        '''setting this variable will remind
                                        us that we've already come across the
                                        opening quote so any subsequent quote
                                        should be a closing quote'''
                                        templist2.append(item)
                                else:
                                    '''it's just a normal value'''
                                    templist1.append(item)
                        else:
                            '''could just be a single value which is
                            acceptable'''
                            templist = innerlist[1]
                if output:
                    cmdlist = self.processOutput(output, outputstr, innerlist,
                                                 templist1, key)
                elif error:
                    cmdlist = self.processError(error, errorstr, innerlist,
                                                templist1, key)
        if cmdlist is True:
            return True
        self.setWriteCmd(cmdlist[0])
        self.setUndoCmd(cmdlist[1])
        return True
###############################################################################

    def processOutput(self, output, outputstr, innerlist, templist1, key):
        cmdlist = []
        undostr = ""

        '''output is a simple return value such as 0 or 1'''
        if len(output) == 1:
            if innerlist[1] is None:
                '''We were hoping for a does not exist message
                based on the innerlist value being None however an
                actual value returned, to correct this, we will
                delete it'''
                if self.currentHost:
                    write = [self.dc, self.host, "delete",
                             self.path, key]
                    undo = [self.dc, self.host, "write", self.path,
                            output[0]]
                else:
                    write = [self.dc, "delete", self.path, key]
                    undo = [self.dc, "write", self.path, output[0]]
            else:
                if re.match(innerlist[0], outputstr.strip()):
                    '''check if output from read command matches
                    our regular expression'''
                    return True
                debug = "The output doesn\'t match the regex for " + \
                    str(innerlist[0]) + "\n"
                self.logger.log(LogPriority.DEBUG, debug)
                if self.plist:
                    if self.currentHost:
                        write = self.dc + " " + self.host + \
                            " write " + self.path + " " + key + \
                            " " + innerlist[1]
                    else:
                        write = self.dc + " write " + \
                            self.path + " " + key + " " + innerlist[1]
                elif templist1:
                    '''we check to see if the temp list
                    has a value in which case it does, we know
                    the innerlist[1] value is the usual case
                    of -datatype value -datatype value ...'''
                    if self.currentHost:
                        write = [self.dc, self.host, "write", self.path, key]
                    else:
                        write = [self.dc, "write", self.path, key]
                    for item in templist1:
                        write.append(item)
                else:
                    #may not need this else portion
                    if self.currentHost:
                        write = [self.dc, self.host, "write", self.path, key,
                                 innerlist[1]]
                    else:
                        write = [self.dc, "write", self.path, key,
                                 innerlist[1]]
                if self.currentHost:
                    undo = [self.dc, self.host, "write", self.path, key,
                            output[0].strip()]
                else:
                    undo = [self.dc, "write", self.path, key,
                            output[0].strip()]
        elif len(output) > 1:
            if innerlist[1] is None:
                '''We were hoping for a does not exist message
                based on the innerlist value being None however an
                actual value returned, to correct this, we will
                delete it'''
                if self.currentHost:
                    write = [self.dc, self.host, "delete", self.path, key]
                    undo = [self.dc, self.host, "write", self.path, output[0]]
                else:
                    write = [self.dc, "delete", self.path, key]
                    undo = [self.dc, "write", self.path, output[0]]
            elif not re.match(innerlist[0], outputstr.strip()):
                debug = "The output doesn\'t match the regex for \
" + innerlist[0] + "\n"
                self.logger.log(LogPriority.DEBUG, debug)
                if re.search("\(|\)|\{|\}", outputstr):
                    if self.currentHost:
                        undostr = self.dc + " " + self.host + " write " + \
                            self.path + " " + key + " \'"
                    else:
                        undostr = self.dc + " write " + self.path + " " + \
                            key + " \'"
                    for line in output:
                        if re.match("^\{$", line.strip()) or \
                                re.match("^\($", line.strip()):
                            undostr += line.strip()
                        elif re.match("^\};$", line.strip()) or \
                                re.match("^\);$", line.strip()) or \
                                re.match("^\}$", line.strip())or \
                                re.match("^\)$", line.strip()):
                            undostr += line.strip()
                        elif re.search("=", line):
                            line = line.split("=")
                            if re.match("^\{$", line[1].strip()):
                                undostr += "\"" + line[0].strip() + "\" = {"
                            elif re.match("^\($", line[1].strip()):
                                undostr += "\"" + line[0].strip() + "\" = ("
                            else:
                                undostr += "\"" + line[0].strip() + "\" = " + \
                                    line[1].strip()
                        elif line != "":
                            if re.match("^\".*\"", line.strip()):
                                temp = line.split("\"")
                                if len(temp) == 3:
                                    if temp[2].strip() == ",":
                                        undostr += temp[1] + temp[2].strip()
                                    else:
                                        undostr += temp[1]
                            elif re.search(",", line.strip()):
                                temp = line.split(",")
                                undostr += temp[0].strip() + ","
                            else:
                                undostr += line.strip()
                    undostr += "\'"
            elif re.match(innerlist[0], outputstr):
                return True
            if self.plist:
                if self.currentHost:
                    write = self.dc + " " + self.host + " write " + \
                        self.path + " " + key + " " + innerlist[1]
                else:
                    write = self.dc + " write " + self.path + " " + key + \
                        " " + innerlist[1]
            elif templist1:
                if self.currentHost:
                    write = [self.dc, self.host, "write", self.path, key]
                else:
                    write = [self.dc, "write", self.path, key]
                for item in templist1:
                    write.append(item)

            else:
                if self.currentHost:
                    write = [self.dc, self.host, "write", self.path, key,
                             innerlist[1]]
                else:
                    write = [self.dc, "write", self.path, key, innerlist[1]]
            if undostr:
                undo = undostr
            else:
                if self.currentHost:
                    undo = [self.dc, self.host, "write", self.path, key,
                            outputstr]
                else:
                    undo = [self.dc, self.host, "write", self.path, key,
                            outputstr]
        cmdlist.append(write)
        cmdlist.append(undo)
        return cmdlist
###############################################################################

    def processError(self, error, errorstring, innerlist, templist1, key):
        self.logger.log(LogPriority.DEBUG, "there is an error!")
        '''the command run doesn't return a valid value, key may
        not exist or may have had an error running the command'''
        cmdlist = []
        '''check if the output contains a does not exist message'''
        if re.search("does not exist", errorstring):
            '''If the value of the innerlist that developer passed in is None,
            then that is ok, we didn't want/expect it to exist'''
            if innerlist[1] is None:
                self.nocmd = True
                return True
            else:
                if templist1:
                    if self.currentHost:
                        write = [self.dc, self.host, "write", self.path, key]
                    else:
                        write = [self.dc, "write", self.path, key]
                    for item in templist1:
                        write.append(item)
                else:
                    if self.currentHost:
                        write = self.dc + " " + self.host + \
                            " write " + self.path + " " + key + \
                            innerlist[1]
                    else:
                        write = self.dc + " write " + self.path + \
                            " " + key + " " + innerlist[1]
                if self.currentHost:
                    undo = [self.dc, self.host, "delete", self.path, key]
                else:
                    undo = [self.dc, "delete", self.path, key]
        else:
            '''There was some other error, could be a bad command'''
            msg = "There was some error running defaults read command"
            raise OSError(msg)
        cmdlist.append(write)
        cmdlist.append(undo)
        return cmdlist
###############################################################################

    def commit(self):
        '''
        Private method that commits the defaults write command for this
        object.
        @return: bool'''
        writecmd = self.getWriteCmd()
        if not writecmd:
            msg = "Write command was not able to be set due to passed \
dictionary not containing a write value.  Unable to run write command\n"
            self.logger.log(LogPriority.DEBUG, msg)
            return False
        if self.plist:
            self.logger.log(LogPriority.DEBUG, "write command is: " +
                            str(writecmd))
            self.logger.log(LogPriority.DEBUG, "undo command is: " +
                            str(self.getundoCmd()))
            retval = call(writecmd, shell=True, stdout=None)
            if retval == 0:
                return True
            else:
                return False
        if self.ch.executeCommand(writecmd):
            return True
        else:
            return False
###############################################################################

    def getInnerList(self, data):
        '''
        Private recursive method that returns the inner most list to compare
        desired values with actual values.
        @return: list
        @requires: dict'''
        if isinstance(data, list):
            if len(data) >= 2:
                if self.checkListContents(data):
                    return data
            else:
                msg = "Innerlist of self.data does not " + \
                    "contain at least two placeholders.  List: " + str(data)
                raise ValueError(msg)
        elif isinstance(data, dict):
            for k, v in data.iteritems():
                if isinstance(v, dict):
                    retval = self.getInnerList(v)
                    return retval
                elif isinstance(v, list):
                    if len(v) >= 2:
                        if self.checkListContents(v):
                            return v
                    else:
                        msg = "Innerlist of self.data does not " + \
                            "contain at least two placeholders.  List: " + \
                            str(v)
                        raise ValueError(msg)
                else:
                    msg = "Innermost data strtucture of self.data is not " + \
                        "a list"
                    raise TypeError(msg)
###############################################################################

    def checkListContents(self, data):
        '''
        Private method that checks to make sure the list is in correct format
        @author: dwalker
        @param data: the innerlist that should reside in the dictionary
            @requires: list
        @return: bool'''
        try:
            temp = ""
            if isinstance(data[0], str):
                if isinstance(data[1], str):
                    if re.search("\{|\}|\(|\)", data[1]):
                    #if re.search("^\{|\}$|^\(|\)$",data[1]):
                        self.plist = True
                        return True
                    elif re.search("\s+", data[1].strip()):
                        temp = data[1].split()
                    else:
                        temp = data[1].split()
                    if len(temp) > 0:
                        return True
                    else:
                        msg = "There is no value in the second placeholder of the \
    innermost list."
                        raise IndexError(msg)
                elif data[1] is None:
                    return True
                else:
                    msg = "Innerlist[1] should either be a string or None. Your \
    value is: " + str(data[1])
                    raise ValueError(msg)
            else:
                msg = "Innerlist[0] should be a string or only, " + \
                    "specifically a regex. Your value is : " + \
                    str(data[0]) + " and is type: " + str(type(data[0]))
                raise TypeError(msg)
        except IndexError:
            raise IndexError()
###############################################################################

    def setWriteCmd(self, writecmd):
        '''
        Private method to set the defaults write command assigned to this
        object.
        @author: dwalker
        @param writecmd: the command set to do a default write
            @requires: list or str
        '''
        self.write = writecmd
        self.logger.log(LogPriority.DEBUG,
                        "self.write after setting: " + str(self.write))
###############################################################################

    def getWriteCmd(self):
        '''
        Private method to retrieve the defaults write command assigned to this
        object.
        @author: dwalker
        @return: list or str
        '''
        return self.write
###############################################################################

    def setUndoCmd(self, undocmd):
        '''
        Private method to set the defaults write command to undo the changes
        made by this object
        @author: dwalker
        @param undocmd: the command set to do a write or delete, undoing
               previous write or delete command
            @requires: list or str
        '''
        self.undocmd = undocmd
###############################################################################

    def getundoCmd(self):
        '''
        Private method to retrieve the defaults write command to undo the
        changes made by this object
        @author: dwalker
        @return: list or str
        '''
        return self.undocmd
###############################################################################

    def updateData(self, data):
        '''
        Private method to update the value of self.data in case the kveditor
        implementor changes values after the rule's initial report method.
        @author: dwalker
        @param data:
            @requires: dictionary in the form {key:[val1:val2]}
        '''
        self.data = data
        return True
###############################################################################

    def getValue(self):
        '''
        Private method to retrieve self.output, a variable that should contain
        stdout and/or stderr after validate method is run
        @author: dwalker
        @return: str
        '''
        return self.output
###############################################################################

    def delete(self):
        '''
        Private method to perform a defaults delete command on the previously
        instantiated path and key
        @author: dwalker
        '''
        for key in self.data:
            if self.currentHost:
                cmd = ["defaults", "-currentHost", "delete", self.path, key]
            else:
                cmd = ["defaults", "delete", self.path, key]
            if self.ch.executeCommand(cmd):
                return True
            else:
                return False
