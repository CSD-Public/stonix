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
Created on May 6, 2013

@author: Derek Walker
'''

from logdispatcher import LogPriority
from stonixutilityfunctions import writeFile
import os
import traceback
import re

class KVAConf():
    '''This class checks files for correctness that consist of key:value pairs
    either in the form of closed equal separated (k=v), open separated (k = v),
    or space separated (k v).  To implement this class, the calling KVEditor
    class must have already had the path set and the intent set.  The intent
    should either be a value of 'present' or not 'present'.  The purpose of the
    intent is to determine whether the values you are setting are desired in
    configuration file or not desired, where present = desired and notpresent
    = not desired.  If the same key appears more than once, this helper class
    will ensure only one value remains with the correct value in the end.
    The value associated with a key can either be a string or a list.  When
    the value is a list, this means that someone is passing in a key value set
    where the key is allowed to be the same over and over again such as a
    blacklist file where you may see:
    blacklist bluetooth
    blacklist rivafb
    blacklist hisax
    ...
    in which the dictionary would be in the form of:
    {"blacklist:["bluetooth",
                 "rivafb",
                 "hisax"]}


    '''

    def __init__(self, path, tmpPath, intent, configType, logger):
        '''

        :param path:
        :param tmpPath:
        :param intent:
        :param configType:
        :param logger:
        '''

        self.fixables = {}
        self.removeables = {}
        self.logger = logger
        self.path = path
        self.tmpPath = tmpPath
        self.storeContents(self.path)
        self.configType = configType
        self.universal = "#The following lines were added by stonix\n"
        self.tempstring = ""
        self.intent = intent
        self.detailedresults = ""
        self.isdir = False

    def setPath(self, path):
        '''Private method to set the path of the configuration file
        @author: Derek Walker

        :param path: the path to file to be handled

        '''
        self.path = path
        self.storeContents(self.path)

    def getPath(self):
        '''Private method to retrieve the path of the configuration file
        
        @author: Derek Walker


        :returns: self.path
        :rtype: bool

        '''
        return self.path

    def setTmpPath(self, tmpPath):
        '''Private method to set the temporary path of the configuration file
        for writing before renaming to original file again
        
        @author: Derek Walker

        :param tmpPath: the path to the temporary file to be written to

        '''
        self.tmpPath = tmpPath

    def getTmpPath(self):
        '''Private method to retrieve the temporary path of the configuration
        file to be written to before renaming to original file again
        
        @author: Derek Walker


        :returns: Bool

        '''
        return self.tmpPath

    def setIntent(self, intent):
        '''Private method to set the intent of self.data.  Should either be a
        value of "present" or "notpresent" to indicate whether key value pairs
        in self.data are desired or not desired in the configuration file
        respectively.  The point of this variable is to change from present
        to notpresent when needed to set desirable and non desireable key
        value pairs back and forth until update method is run.
        
        @author: Derek Walker

        :param intent: present | notpresent

        '''
        self.intent = intent

    def getIntent(self):
        '''Private method to retrieve the current intent
        
        @author: Derek Walker


        :returns: self.intent; present | not present
        :rtype: basestring

        '''
        return self.intent

    def setConfigType(self, configType):
        '''

        :param configType: ???

        '''

        self.configType = configType
        return True

    def getConfigType(self):
        '''
        :returns: self.configType
        :rtype: ???
        '''

        return self.configType

    def validate(self, key, val):
        '''Private outer method to call submethod getOpenClosedValue() or
        getSpaceValue() depending on the value of self.configType.
        
        @author: Derek Walker

        :param key: key in a dictionary passed from calling class
        :param val: value part in dictionary passed from calling class
        :returns: Bool

        '''
        if self.configType in ['openeq', 'closedeq']:
            return self.getOpenClosedValue(key, val)
        if self.configType == 'space':
            return self.getSpaceValue(key, val)
        else:
            return "invalid"

    def getOpenClosedValue(self, key, value):
        '''Private inner method called by validate that populates self.fixables
        and/or self.removeables lists.  self.fixables list will be populated
        if configuration file has either the correct key but the wrong value
        or the key is not there at all.  A key that is commented out will be
        considered not present. self.removeables list will be populated if
        configuration file has keys that are not desired.  The value of these
        keys is irrelevant since the key shouldn't be there at all.  This
        method specifcally handles files with an equal sign separating the key
        and the val, both open and closed type
        
        @author: Derek Walker

        :param key: key in a dictionary passed from calling class
        :param val: value part in dictionary passed from calling class
        :param value: 
        :returns: Bool

        '''
        if self.contents:
            if self.intent == "present":  # self.data contains key val pairs we want in the file
                found = False
                for line in self.contents:
                    if re.match('^#', line) or re.match(r'^\s*$', line):  # ignore if comment or blank line
                        continue
                    elif re.search("=", line):  # examine line if there is an = sign
                        temp = line.split("=")  # split line into key val list [key, val]
                        if re.match("^" + key + "$", temp[0].strip()):  # it contains the current key we're looking for
                            if temp[1].strip() == value:  # and the value is correct
                                found = True  # however we continue to make sure the key doesn't appear later in the file and have the wrong value
                                continue
                            else:  # the value is wrong so we break out of the loop.  Unecessary to continue, it will be fixed in the update
                                found = False
                                break
                if found:  # return True or False value
                    return True
                else:
                    return False
            elif self.intent == "notpresent":  # self.data contains key val pairs we don't want in the file
                found = True
                for line in self.contents:
                    if re.match("^#", line) or re.match(r'^\s*$', line):  # ignore if comment or blank line
                        continue
                    elif re.search("=", line):  # examine line if there is an = sign
                        temp = line.split("=")  # split line into key val list [key, val]
                        if re.match("^" + key + "$", temp[0].strip()):  # it contains the current key we're looking for
                            found = True  # no need to check value, it's irrelevant
                            break
                return found

    def getSpaceValue(self, key, value):
        '''Private inner method called by validate that populates self.fixables
        and/or self.removeables lists.  self.fixables list will be populated
        if configuration file has either the correct key but the wrong value
        or the key is not there at all.  A key that is commented out will be
        considered not present. self.removeables list will be populated if
        configuration file has keys that are not desired.This method
        specifcally handles files where a space separates key value pairs
        within the same line.
        
        @author: Derek Walker

        :param key: key in a dictionary passed from calling class
        :param val: value part in dictionary passed from calling class
        :param value: 
        :returns: Bool

        '''
        # list that keeps track of key value pairs we didn't find that need
        # to be present and added in the fix() and commit()
        fixables = []

        #list that keeps track of key value pairs that shouldn't be present
        # but were and need to be removed in the fix() and commit()
        removeables = []
        # self.data contains key val pairs we want in the file
        if self.intent == "present":
            # if "value" is a list that means the key can be repeatable
            if isinstance(value, list):
                debug = "This key can be present multiple times: " + key + "\n"
                self.logger.log(LogPriority.DEBUG, debug)
                for item in value:
                    # this variable keeps track if at any point we found the key-value
                    foundalready = False
                    for line in self.contents:
                        # ignore if comment or blank line
                        if re.match('^#', line) or re.match(r'^\s*$', line):
                            continue
                        # we found the key, which in this case can be repeatable
                        elif re.search("^" + re.escape(key) + "\s+", line):
                            # remove any leading or traling whitespace
                            temp = line.strip()
                            # check to see if "item" in our self.data dictionary is blank or not
                            if item != "":
                                temp = re.sub("\s+", " ", temp)
                                if temp == key + " " + item:
                                    foundalready = True
                            # if it is, that means we're just looking for a special one word
                            # key with no value after
                            else:
                                if temp == key:
                                    foundalready = True
                    if not foundalready:
                        fixables.append(item)
                        debug = "didn't find key-value: " + key + " " + item + \
                            ", but should be present"
                        self.logger.log(LogPriority.DEBUG, debug)
                if fixables:
                    return fixables
                else:
                    return True
            # value must be a string, normal case
            else:
                foundalready = False
                for line in self.contents:
                    # ignore if comment or blank line
                    if re.match('^#', line) or re.match(r'^\s*$', line):
                        continue
                    # we found the key
                    elif re.search("^" + re.escape(key) + "\s+", line):
                        # remove any leading or trailing whitespace
                        temp = line.strip()
                        # check to see if "value" in our self.data dictionary is blank or not
                        if value != "":
                            temp = re.sub("\s+", " ", temp)
                            if temp == key + " " + value:
                                foundalready = True
                        else:
                            if temp == key:
                                foundalready = True
                return foundalready
        # self.data contains key val pairs we don't want in the file
        elif self.intent == "notpresent":
            # if "value" is a list that means the key can be repeatable
            if isinstance(value, list):
                # iterate through all values of repeatable key
                for item in value:
                    # this variable keeps track if at any point we found the key-value
                    foundalready = False
                    # iterate through the file's contents
                    for line in self.contents:
                        # ignore if comment or blank line
                        if re.match('^#', line) or re.match(r'^\s*$', line):
                            continue
                        # we found the key, which in this case can be repeatable
                        elif re.search("^" + re.escape(key) + "\s+", line):
                            # remove any leading or trailing whitespace
                            temp = line.strip()
                            # check to see if "item" in our self.data dictionary is blank or not
                            if item != "":
                                temp = re.sub("\s+", " ", temp)
                                if temp == key + " " + item:
                                    foundalready = True
                            # if it is, that means we're just looking for a special one word
                            # key with no value after
                            # normally the implementer in this case should not have put the "value" in a list
                            # but this will still cover it if they did
                            else:
                                if temp == key:
                                    foundalready = True
                    if foundalready:
                        removeables.append(item)
                        debug = "Found the key-value: " + key + " " + item + \
                                ", but should not be present"
                        self.logger.log(LogPriority.DEBUG, debug)
                if removeables:
                    return removeables
                else:
                    return True
            # value must be a string, normal case
            else:
                foundalready = False
                for line in self.contents:
                    # ignore is comment or blank line
                    if re.match('^#', line) or re.match(r'^\s*$', line):
                        continue
                    # we found the key
                    elif re.search("^" + re.escape(key) + "\s+", line):
                        temp = line.strip()
                        if value != "":
                            temp = re.sub("\s+", " ", temp)
                            if temp == key + " " + value:
                                foundalready = True
                        else:
                            if temp == key:
                                foundalready = True
                if foundalready:
                    debug = "Found the key-value: " + key + " " + value + \
                            ", but should not be present"
                    self.logger.log(LogPriority.DEBUG, debug)
                    return False
                else:
                    return True

    def update(self, fixables, removeables):
        '''Private outer method to call submethod setOpenClosedValue() or
        setSpaceValue() depending on the value of self.configType.
        
        @author: Derek Walker

        :param fixables: a dictionary of key val pairs desired in file
        :param removeables: a dictionary of key val pairs not desired in file
        :returns: Bool

        '''

        # changed by Breen Malmberg 03/14/2019; condensed repeated code
        if self.configType in ['openeq', 'closedeq']:
            return self.setOpenClosedValue(fixables, removeables)
        elif self.configType == 'space':
            return self.setSpaceValue(fixables, removeables)
        else:
            # changed by Breen Malmberg 03/14/2019; data type return consistency (bool)
            return False

    def setOpenClosedValue(self, fixables, removeables):
        '''Private inner method called by update that makes a list to conform
        to desireable (fixables) key val pairs and undesireable (removeables)
        key val pairs in the config file while also keeping any other
        contents intact that aren't affected.  This method specifically handles
        files with an equal sign separating the key and the val, both open
        and closed
        
        @author: Derek Walker

        :param fixables: a dictionary of key val paris desired in file
        :param removeables: a dictionary of key val paris not desired in file
        :returns: Bool

        '''
        self.storeContents(self.path)  # re-read the contents of the desired file
        contents = self.contents
        if removeables:  # we have items that need to be removed from file
            for key in removeables:
                i = 0  # variable to keep our place in the list, will be used for removing items
                for line in contents:
                    if re.search("^#", line) or re.match("^\s*$", line):  # ignore if comment or blank line
                        i += 1
                    elif re.search("=", line.strip()):  # line contains an = sign
                        temp = line.split("=")
                        if re.match("^" + key + "$", temp[0].strip()):  # found the key
                            contents.pop(i)  # not concerned with the value because we don't want the key either way
                        i += 1
                    else:
                        i += 1
        if fixables:  # we have items that either had the wrong value or don't exist in the file
            for key in fixables:
                i = 0  # variable to keep our place in the list, will be used for removing items
                for line in contents:
                    if re.search("^#", line) or re.match("^\s*$", line):  # ignore if comment or blank line
                        i += 1
                    elif re.search("=", line.strip()):  # line contains an = sign
                        temp = line.split("=")
                        if re.match("^" + key + "$", temp[0].strip()):  # found the key
                            contents.pop(i)  # we pop it out but down below we add the correct line unlike above
                        i += 1
                    else:
                        i += 1
            self.contents = []
            for line in contents:  # contents should now have a list of items we are ok with having in the file but will still be missing the fixables
                self.contents.append(line)  # make self.contents contain the correct file contents before fixing
            # self.contents.append("\n" + self.universal)  # add our universal line to show line(s) were added by stonix to self.contents
            for key in fixables:
                if self.configType == "openeq":  # construct the appropriate line and add to bottom of self.contents
                    temp = key + " = " + fixables[key] + "\n"
                    self.contents.append(temp)
                elif self.configType == "closedeq":
                    temp = key + "=" + fixables[key] + "\n"
                    self.contents.append(temp)
        return True

    def setSpaceValue(self, fixables, removeables):
        '''Private inner method called by update that makes a list to conform
        to desireable (fixables) key val pairs and undesireable (removeables)
        key val pairs in the config file while also keeping any other
        contents intact that aren't affected.  This method specifcally handles
        files where a space separates key value pairs within the same line
        
        @author: Derek Walker

        :param fixables: a dictionary of key val paris desired in file
        :param removeables: a dictionary of key val pairs not desired in file
        :returns: Bool

        '''
        # re-read the contents of the desired file
        self.storeContents(self.path)
        contents = self.contents
        # we have items that need to be removed from file
        if removeables:
            poplist = []
            for key, val in removeables.iteritems():
                # we have a list where the key can repeat itself
                if isinstance(val, list):
                    for item in val:
                        for line in contents:
                            if re.search("^#", line) or re.match("^\s*$", line):
                                continue
                            elif re.search("^" + re.escape(key) + "\s+", line):
                                temp = line.strip()
                                if val != "":
                                    temp = re.sub("\s+", " ", temp)
                                    if re.search("^" + re.escape(key) + " " + item, temp):
                                        poplist.append(line)
                                else:
                                    if re.search("^" + re.escape(key) + "$", temp):
                                        poplist.append(line)
                else:
                    for line in contents:
                        if re.search("^#", line) or re.match("^\s*$", line):
                            continue
                        elif re.search("^" + re.escape(key) + "\s+", line):
                            temp = line.strip()
                            if val != "":
                                temp = re.sub("\s+", " ", temp)
                                if re.search("^" + re.escape(key) + " " + val, temp):
                                    poplist.append(line)
                            else:
                                if re.search("^" + re.escape(key) + "$", temp):
                                    poplist.append(line)
            if poplist:
                for item in poplist:
                    try:
                        contents.remove(item)
                    except Exception:
                        continue
        if fixables:
            poplist = []
            # contents.append(self.universal)
            # in this next section we cover a situation where the key
            # may appear more than once and have wrong values, so anywhere
            # the key exists that's not repeatable, we remove it from the file
            # to ensure no conflicting key value pairs.
            for key, val in fixables.iteritems():
                # since these keys can be repeatable we won't take the same
                # precaution as unique keys.
                if not isinstance(val, list):
                    for line in contents:
                        if re.search("^#", line) or re.match("^\s*$", line):
                            continue
                        # we found the key in the file
                        elif re.search("^" + re.escape(key) + "\s+", line):
                            poplist.append(line)
            if poplist:
                for item in poplist:
                    try:
                        contents.remove(item)
                    except Exception:
                        continue
            for key, val in fixables.iteritems():
                if isinstance(val, list):
                    for item in val:
                        contents.append(key + " " + item + "\n")
                else:
                    contents.append(key + " " + val + "\n")
        self.contents = contents
        return True

    def commit(self):
        '''Private method that actually writes the configuration file as desired
        including fixables and removing desireables.  This method is called
        in the calling class that instantiated the object after the update
        methods have been called.
        
        @author: Derek Walker


        :returns: Bool

        '''
        for line in self.contents:
            self.tempstring += line
        success = writeFile(self.tmpPath, self.tempstring, self.logger)
        return success

    def storeContents(self, path):
        '''Private method that reads in the self.path variable's contents and
        stores in public variable self.contents
        
        @author: Derek Walker

        :param path: The path which contents need to be read
        @change bgonz12 - 2018/1/18 - added handling for 'path' not existing

        '''

        self.contents = []

        try:
            f = open(path, 'r')
            self.contents = f.readlines()
            f.close()

        except IOError:
            self.logger.log(LogPriority.DEBUG, "Failed to retrieve contents of file: " + str(path))

    def getValue(self):
        '''Private method that puts any items that don't exist or have the wrong
        value (fixables) and any items that do exist but shouldn't
        (removeables) in string form for retrieving.  This method is more for
        debugging to make sure KVAConf is doing the right thing during when
        reporting (validate)
        
        @author: Derek Walker


        :returns: str

        '''
        output = ""
        if self.fixables:
            output += "Keys that have incorrect values:\n" + \
                str(self.fixables) + "\n"
        if self.removeables:
            output += "Keys that need to be removed:\n" + \
                str(self.removeables) + "\n"
