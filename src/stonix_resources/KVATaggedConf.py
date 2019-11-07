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
Created on Jul 23, 2013

@author: dwalker
'''
from stonix_resources.logdispatcher import LogPriority
import traceback
import re
import os

class KVATaggedConf():

    '''This class checks files for correctness that consist of a tag, usually
    in brackets such as [userdefaults], followed by nested key:value pairs
    either closed equal separated (k=v), open separated (k = v), or space
    separated (k v).  To implement this class, the calling KVEditor class
    must have already had the path set and the intent set.  The intent should
    either be a value of present or notpresent.  By default, the intent value
    is "present" The purpose of the intent is to determine whether the values
    you are setting are desired in the configuration file or not desired, where
    present = desired and notpresent = not desired, this rule also assumes
    that for the given file, the tag only appears at most, once.  If the
    specified tag appears more than once, the first appearance of the tag will
    get corrected and not any others.  This class also assumes that the tags
    are encased in square brackets. If other tags are discovered, updates will
    be made.  When passing in a dictionary it should be in the form of:
    {tag:{key:value,key:value}}.  If the intent is notpresent, the values can
    be anything since the values won't be checked anyway.
    1. When creating the KVEditor object, pass through all the parameters in
    the beginning
    2.run the create method in the KVEditor object
    3.Run validate, if Validate returns False, run update
    4.Change intent and/or data if necessary
    5.repeat steps 3 and 4 until finished checking then run commit
    6.A temporary file that you specified should exist now with corrections


    '''
###############################################################################
    def __init__(self, path, tmpPath="", intent="present", configType="", logger=""):
        self.path = path
        self.tmpPath = tmpPath
        self.contents = []
        self.intent = intent
        self.configType = configType
        self.logger = logger
        self.storeContents(path)
        self.universal = "#The following lines were added by stonix\n"
        self.tempstring = ""
###############################################################################
    def setPath(self, path):
        self.path = path
###############################################################################
    def getPath(self):
        return self.path
###############################################################################
    def setTmpPath(self, tmpPath):
        self.tmpPath = tmpPath
###############################################################################
    def getTmpPath(self):
        return self.tmpPath
###############################################################################
    def setIntent(self, intent):
        self.intent = intent
###############################################################################
    def getIntent(self):
        return self.intent

    def getValue(self, tag, dict1):
        '''will either return True, False, or a blank dictionary {}

        :param tag: 
        :param dict1: 

        '''
        if self.configType in ["openeq", "closedeq"]:
            return self.getOpenClosedValue(tag, dict1)
        elif self.configType == "space":
            return self.getSpaceValue(tag, dict1)
        elif self.configType == "spaceeq":
            return self.getSpaceEqValue(tag, dict1)

    def getOpenClosedValue(self, tag, dict1):
        '''

        :param tag: param dict1:
        :param dict1: 

        '''

        if self.contents:
            contents = self.contents
            contents2 = ""
            foundtag = False
            length = len(contents) - 1
            iter1 = 0
            missing = {}
            present = {}
            for line in contents:
                if re.search("^#", line) or re.match('^\s*$', line):
                    iter1 += 1
                elif re.search("^\[" + re.escape(tag) + "\]", line.strip()):
                    foundtag = True
                    temp = contents[iter1 + 1:]
                    iter2 = 0
                    length = len(temp) - 1
                    for line2 in temp:
                        if re.search("^#", line2) or re.match('^\s*$', line2):
                            iter2 += 1
                        elif re.search("^\[.*\]$", line2):
                            contents2 = temp[:iter2]
                            break
                        elif iter2 == length:
                            contents2 = temp[:iter2 + 1]
                        else:
                            iter2 += 1
                else:
                    iter1 += 1
            if self.intent == "present":
                if not foundtag:
                    return dict1
                if contents2:
                    for key in dict1:
                        found = False
                        for line in contents2:
                            if re.search("^#", line) or re.match('^\s*$', line):
                                continue
                            elif re.search("=", line):
                                if line.count("=") > 1:
                                    temp = line.strip().split("=", 1)
                                else:
                                    temp = line.strip().split("=")
                                if len(temp) != 2:
                                    return "invalid"
                                if re.match("^" + key + "$", temp[0].strip()):
                                    if temp[1].strip() == dict1[key]:
                                        found = True
                                        continue
                                    else:
                                        found = False
                                        break
                        if not found:
                            missing[key] = dict1[key]
                if not missing:
                    return True
                else:
                    return missing
            elif self.intent == "notpresent":
                if not foundtag:
                    return True
                if contents2:
                    for key in dict1:
                        found = False
                        for line in contents2:
                            if re.search("^#", line) or re.match('^\s*$', line):
                                continue
                            elif re.search("=", line):
                                temp = line.strip().split("=")
                                if len(temp) != 2:
                                    return "invalid"
                                if re.search("^" + key + "$", temp[0].strip()):
                                    found = True
                                    break
                                else:
                                    found = False
                                    continue
                        if found:
                            present[key] = dict1[key]
                if not present:
                    return True
                else:
                    return present
        else:
            if self.intent == "present":
                return dict1
            else:
                return True
###############################################################################
    def getSpaceValue(self, tag, dict1):
        '''

        :param tag: param dict1:
        :param dict1: 

        '''

        if self.contents:
            contents = self.contents
            foundtag = False
            length = len(contents) - 1
            iter1 = 0
            missing = {}
            present = {}
            for line in contents:
                if re.search("^#", line) or re.match('^\s*$', line):
                    iter1 += 1
                elif re.search("^\[" + re.escape(tag) + "\]", line.strip()):
                    foundtag = True
                    temp = contents[iter1 + 1:]
                    iter2 = 0
                    length = len(temp) - 1
                    for line2 in temp:
                        if re.search("^#", line2) or re.match('^\s*$', line2):
                            iter2 += 1
                        elif re.search("^\[.*\]$", line2):
                            contents2 = temp[:iter2]
                            break
                        elif iter2 == length:
                            contents2 = temp[iter2 + 1]
                        else:
                            iter2 += 1
                else:
                    iter1 += 1
            if self.intent == "present":
                if not foundtag:
                    return dict1
                if contents2:
                    for key in dict1:
                        found = False
                        for line in contents2:
                            if re.search("^#", line) or re.match('^\s*$', line):
                                continue
                            elif re.search(" ", line.strip()):
                                temp = line.strip().split(" ")
                                if len(temp) != 2:  # there were more than one blank space
                                    return "invalid"
                                if re.search("^" + re.escape(key) + "$", temp[0].strip()):
                                    if temp[1].strip() == dict1[key]:
                                        found = True
                                        continue
                                    else:
                                        found = False
                                        break
                        if not found:
                            missing[key] = dict1[key]
                if not missing:
                    return True
                else:
                    return missing
            elif self.intent == "notpresent":
                if not foundtag:
                    return True
                if contents2:
                    for key in dict1:
                        found = False
                        for line in contents2:
                            if re.search("^#", line) or re.match('^\s*$', line):
                                continue
                            elif re.search(" ", line.strip()):
                                temp = line.strip().split(" ")
                                if len(temp) != 2:
                                    return "invalid"
                                if re.search("^" + re.escape(key) + "$", temp[0].strip()):
                                    found = True
                                    break
                                else:
                                    found = False
                                    continue
                        if found:
                            present[key] = dict1[key]
                if not present:
                    return True
                else:
                    return present
        else:
            if self.intent == "present":
                return dict1
            else:
                return True
###############################################################################
    def setValue(self, fixables, removeables):
        if self.configType == "openeq":
            return self.setOpenClosedValue(fixables, removeables)
        if self.configType == "closedeq":
            return self.setOpenClosedValue(fixables, removeables)
        if self.configType == "space":
            return self.setSpaceValue(fixables, removeables)
        if self.configType == "spaceeq":
            return self.setSpaceEqValue(fixables, removeables)
###############################################################################
    def setOpenClosedValue(self, fixables, removeables):
        contents1, contents2, contents3 = [], [], []
        if fixables:
            #file is blank so just put each tag and corresponding
            #key value pairs in file
            if not self.contents:
                for tag in fixables:
                    self.contents.append("[" + tag + "]\n")
                    for k, v in list(fixables[tag].items()):
                        if self.configType == "openeq":
                            self.contents.append(k + " = " + v + "\n")
                        elif self.configType == "closedeq":
                            self.contents.append(k + "=" + v + "\n")
            else:
                #iterate through each tag value and key,value pair
                for tag in fixables:

                    #variable to track whether we found the desired tag or not
                    tagfound = False
                    #list variable that holds contents of file
                    contents = self.contents
                    #variable to keep track of place in file where we will
                    #splice contents of file after finding desired tag
                    iter1 = 0
                    #variable that contains each key value pair to be found
                    #under desired tag
                    keys = fixables[tag]
                    for line in contents:
                        #found a comment or blank space, increase place counter
                        if re.search("^#", line) or re.match('^\s*$', line):
                            iter1 += 1
                        #found the tag we're looking for
                        elif re.search("^\[" + re.escape(tag) + "\]", line.strip()):

                            #set tagfound to True
                            tagfound = True
                            #list variable that contains all lines in the file up to and
                            #including the desired tag
                            contents1 = contents[:iter1 + 1]
                            #variable that contains everything after the desired tag
                            tempcontents = contents[iter1 + 1:]
                            #variable to keep track of just the contents contained
                            #under the tag and nothing more
                            iter2 = 0
                            length = len(tempcontents) - 1
                            for line2 in tempcontents:
                                #found a comment or blank space, increase place counter
                                if re.search("^#", line2) or re.match('^\s*$', line2):
                                    iter2 += 1
                                #found the next tag in the file, stop here
                                elif re.search("^\[.*\]$", line2):
                                    #list variable that contains just key,value pairs underneath
                                    #desired tag
                                    contents2 = tempcontents[:iter2]
                                    #list variable that contains everything else after contents2
                                    contents3 = tempcontents[iter2:]
                                    break
                                elif iter2 == length:
                                    contents3 = []
                                    contents2 = tempcontents[:iter2 + 1]
                                else:
                                    iter2 += 1
                        else:
                            iter1 += 1

                    #we found the desired tag
                    if tagfound:
                        #there were key value pairs underneath tag
                        if contents2:
                            for key in keys:
                                i = 0
                                for line2 in contents2:
                                    if re.search("^#", line2) or re.match('^\s*$', line2):
                                        i += 1
                                    elif re.search("=", line2.strip()):
                                        temp = line2.strip().split("=")
                                        if re.match("^" + re.escape(key) + "$", temp[0].strip()):
                                            contents2.pop(i)
                                        i += 1
                                    else:
                                        i += 1
                            for key in keys:
                                if self.configType == "openeq":
                                    contents2.append(key + " = " + keys[key] + "\n")
                                elif self.configType == "closedeq":
                                    contents2.append(key + "=" + keys[key] + "\n")
                            self.contents = []
                            for item in contents1:
                                self.contents.append(item)
                            for item in contents2:
                                self.contents.append(item)
                            if contents3:
                                for item in contents3:
                                    self.contents.append(item)
                    else:
                        #never found the desired tag so just add tag and key,value pairs
                        self.contents.append("[" + tag + "]\n")
                        for k, v in list(fixables[tag].items()):
                            if self.configType == "openeq":
                                self.contents.append(k + " = " + v + "\n")
                            elif self.configType == "closedeq":
                                self.contents.append(k + "=" + v + "\n")
        if removeables:
            for tag in removeables:
                contents = self.contents
                length = len(contents) - 1
                iter1 = 0
                for line in contents:
                    keys = removeables[tag]
                    if re.search("^#", line) or re.match('^\s*$', line):
                        iter1 += 1
                    elif re.search("^\[" + re.escape(tag) + "\]", line.strip()):
                        contents1 = contents[:iter1 + 1]
                        tempcontents = contents[iter1 + 1:]
                        iter2 = 0
                        length = len(tempcontents) - 1
                        for line2 in tempcontents:
                            if re.search("^#", line2) or re.match('^\s*$', line2):
                                iter2 += 1
                            elif re.search("^\[.*\]$", line2):
                                contents2 = tempcontents[:iter2]
                                contents3 = tempcontents[iter2:]
                                break
                            elif iter2 == length:
                                contents3 = []
                                contents2 = tempcontents[:iter2 + 1]
                            else:
                                iter2 += 1
                    else:
                        iter1 += 1
                if contents2:
                    for key in keys:
                        i = 0
                        for line2 in contents2:
                            if re.search("^#", line2) or re.match('^\s*$', line2):
                                i += 1
                            elif re.search("=", line2.strip()):
                                temp = line2.strip().split("=")
                                if re.match("^" + re.escape(key) + "$", temp[0].strip()):
                                    contents2.pop(i)
                                i += 1
                            else:
                                i += 1
                    self.contents = []
                    for item in contents1:
                        self.contents.append(item)
                    for item in contents2:
                        self.contents.append(item)
                    if contents3:
                        for item in contents3:
                            self.contents.append(item)
        for line in self.contents:
            self.tempstring += line
        return True
###############################################################################
    def setSpaceValue(self, fixables, removeables):
        contents1, contents2, contents3 = [], [], []
        if fixables:
            if not self.contents:
                for tag in fixables:
                    self.contents.append("[" + tag + "]\n")
                    for k, v in list(fixables[tag].items()):
                        self.contents.append(k + " " + v + "\n")
            else:
                for tag in fixables:
                    contents = self.contents
                    length = len(contents) - 1
                    iter1 = 0
                    for line in contents:
                        keys = fixables[tag]
                        if re.search("^#", line) or re.match('^\s*$', line):
                            iter1 += 1
                        elif re.search("^\[" + re.escape(tag) + "\]", line.strip()):
                            contents1 = contents[:iter1 + 1]
                            tempcontents = contents[iter1 + 1:]
                            iter2 = 0
                            length = len(tempcontents) - 1
                            for line2 in tempcontents:
                                if re.search("^#", line2) or re.match('^\s*$', line2):
                                    iter2 += 1
                                elif re.search("^\[.*\]$", line2):
                                    contents2 = tempcontents[:iter2]
                                    contents3 = tempcontents[iter2:]
                                    break
                                elif iter2 == length:
                                    contents3 = []
                                    contents2 = tempcontents[:iter2 + 1]
                                else:
                                    iter2 += 1
                        else:
                            iter1 += 1
                    if contents2:
                        for key in keys:
                            i = 0
                            for line2 in contents2:
                                if re.search("^#", line2) or re.match('^\s*$', line2):
                                    i += 1
                                elif re.search(" ", line2.strip()):
                                    temp = line2.strip().split(" ")
                                    if re.match("^" + re.escape(key) + "$", temp[0].strip()):
                                        contents2.pop(i)
                                    i += 1
                                else:
                                    i += 1
                        for key in keys:
                            contents2.append(key + " " + keys[key] + "\n")
                        self.contents = []
                        for item in contents1:
                            self.contents.append(item)
                        for item in contents2:
                            self.contents.append(item)
                        if contents3:
                            for item in contents3:
                                self.contents.append(item)
        if removeables:
            for tag in removeables:
                contents = self.contents
                length = len(contents) - 1
                iter1 = 0
                for line in contents:
                    keys = removeables[tag]
                    if re.search("^#", line) or re.match('^\s*$', line):
                        iter1 += 1
                    elif re.search("^\[" + re.escape(tag) + "\]", line.strip()):
                        contents1 = contents[:iter1 + 1]
                        tempcontents = contents[iter1 + 1:]
                        iter2 = 0
                        length = len(tempcontents) - 1
                        for line2 in tempcontents:
                            if re.search("^#", line2) or re.match('^\s*$', line2):
                                iter2 += 1
                            elif re.search("^\[.*\]$", line2):
                                contents2 = tempcontents[:iter2]
                                contents3 = tempcontents[iter2:]
                                break
                            elif iter2 == length:
                                contents3 = []
                                contents2 = tempcontents[:iter2 + 1]
                            else:
                                iter2 += 1
                    else:
                        iter1 += 1
                if contents2:
                    for key in keys:
                        i = 0
                        for line2 in contents2:
                            if re.search("^#", line2) or re.match('^\s*$', line2):
                                i += 1
                            elif re.search(" ", line2.strip()):
                                temp = line2.strip().split(" ")
                                if re.match("^" + re.escape(key) + "$", temp[0].strip()):
                                    contents2.pop(i)
                                i += 1
                            else:
                                i += 1
                    self.contents = []
                    for item in contents1:
                        self.contents.append(item)
                    for item in contents2:
                        self.contents.append(item)
                    if contents3:
                        for item in contents3:
                            self.contents.append(item)
        for line in self.contents:
            self.tempstring += line
        return True
###############################################################################
    def commit(self):
        return self.writeFile(self.tmpPath, self.tempstring)
###############################################################################
    def writeFile(self, tmpfile, contents):
        '''write the string(contents) to the tmpfile

        :param tmpfile: string; full path of file to write
        :param contents: string|list; contents to write to tmpfile
        :returns: retval
        :rtype: bool
@author: Derek Walker
@change: 01/18/2018 - Breen Malmberg - fixed an attributeerror issue associated with the exception handling;
        re-write of method; added doc string

        '''

        retval = True

        parentdir = os.path.abspath(os.path.join(tmpfile, os.pardir))

        if not os.path.exists(parentdir):
            self.detailedresults += "\nUnable to write file: " + str(tmpfile)
            self.logger.log(LogPriority.DEBUG, "Unable to open specified file path: " + str(tmpfile) + ". Parent directory does not exist.")
            retval = False
            return retval
        else:
            try:
                fh = open(tmpfile, 'w')
                if isinstance(contents, list):
                    fh.writelines(contents)
                elif isinstance(contents, str):
                    fh.write(contents)
                else:
                    self.detailedresults += "\nUnable to write to file: " + str(tmpfile)
                    self.logger.log(LogPriority.DEBUG, "Unable to write specified contents. Contents must be either string or list. Given parameter contents was of type: " + str(type(contents)))
                    fh.close()
                    retval = False
                    return retval
                fh.close()
            except IOError:
                fh.close()
                self.logger.log(LogPriority.ERROR, traceback.format_exc())

        return retval

###############################################################################
    def storeContents(self, path):
        try:
            f = open(path, 'r')
        except IOError:
            self.detailedresults = "KVATaggedConf: unable to open the " \
            "specified file"
            self.detailedresults += traceback.format_exc()
            return False
        for line in f:
            self.contents.append(line)
        f.close()
###############################################################################
    def checkConfigType(self):
        for item in self.contents:
            if re.match('^#', item) or re.match(r'^\s*$', item):
                continue
            else:
                item = item.strip()
                if re.search('[a-zA-Z0-9](\s)+=(\s)+[a-zA-Z0-9]', item):
                    return  "openeq"
                if re.search('[a-zA-Z0-9]\s+[a-zA-Z0-9]', item):
                    return "space"
                if re.search('[a-zA-Z0-9]=[a-zA-Z0-9]', item):
                    return "closedeq"
        return "invalid"
