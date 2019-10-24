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
Created on Mar 9, 2016

@author: dwalker
@change: 08/03/2018 - dwalker - added more documentation and fixed
        regex check to look for = with spaces around it inside
        checkSimple method and removed unecessary else portion of code
        inside validate method.
@changed: 08/15/2018 - Brandon R. Gonzales - changed a regular expression from
        "*:" to ".*:"
'''
import re
from stonix_resources.logdispatcher import LogPriority
from stonix_resources.CommandHelper import CommandHelper
from stonix_resources.environment import Environment


class KVAProfiles():

    def __init__(self, logger, path):
        self.logger = logger
        self.path = path
        self.undocmd = ""
        self.installcmd = ""
        self.osver = ""
        enviro = Environment()
        if enviro:
            self.osver = enviro.getosminorver()

    def validate(self, output, key, val):
        '''@summary: Method checks if either profile is installed and/or contents of
        profile is up to par with our security standards
        @author: dwalker

        :param output: The output from system_profiler
                SPConfigurationProfileDataType command
        :param key: The profile identifier we're looking for in the output.
                Usually takes the form of com.apple.example
        :param val: A dictionary which could contain other lists, dicts,
                and/or tuples nested within.  Example:
                {"allowsimple": ["1", "bool"],
                 "forcePIN": ["1", "bool"],
                 ...}
        :returns: bool - True or False

        '''
        '''When passed through, key should be the identifier to be found
        such as com.apple.DiscRecording and val should be the rest of the
        dictionary.'''
        retval = True
        '''In some cases val will be blank in which case we're just
        looking for the presence of the profile or more specifically
        the identifier (key)'''
        if not val:
            for line in output:
                if re.search("^" + key, line.strip()):
                    return True
            '''We never found the profile, return False'''
            debug = "The profile sub-identifier:" + key + " was not found\n"
            self.logger.log(LogPriority.DEBUG, debug)
            return False
        
        '''Go throught output and see if we can find the profile
        identifier (key)'''
        iterator1 = 0
        keyoutput = []
        keyfound = False
        for line in output:
            '''We found the profile identifier'''
            if re.search("^" + key + ":$", line.strip()):
                keyfound = True
                ''''Put all output after the identifier line into a 
                new list'''
                temp = output[iterator1 + 1:]
                iterator2 = 0
                '''Go through this new list and look for where the 
                payload section starts.  The rest of the output gets
                stored in the keyout list'''
                for line in temp:
                    if re.search("^Payload Data:", line.strip()):
                        temp = temp[iterator2 + 1:]
                        keyoutput = temp
                        break
                    else:
                        iterator2 += 1
                if keyoutput:
                    break
            else:
                iterator1 += 1
        '''Check to see if we ever found the identifier (key).
        If not, return False'''
        if not keyfound:
            debug = "Key: " + key + " was never found\n"
            self.logger.log(LogPriority.DEBUG, debug)
            return False
        '''keyoutput should just contain lines after Payload Data line'''
        if keyoutput:
            payloadblocktemp = []
            '''This next loop is getting everything inside the payload
            section stopping before the next identifier'''
            for line in keyoutput:
                if not re.search(".*:", line):
                    #line = re.sub("\s+", "", line)
                    payloadblocktemp.append(line.strip())
                else:
                    break
            payloadblock = []
            i = 0
            dontadd = False
            '''This loop is to clean up the output and squash together
            any consecutive lines that are blank values inside {} or ()'''
            while i < len(payloadblocktemp):
                if dontadd:
                    i += 1
                    dontadd = False
                    continue
                '''The next two if statements check to see if two consecutive
                lines represent an empty dictionary or tuple.  If so we want
                to combine these into one line without the ; at the end'''
                if re.search("\{$", payloadblocktemp[i]):
                    try:
                        if re.search("\};$", payloadblocktemp[i + 1]):
                            dontadd = True
                            line = re.sub(";$", "", payloadblocktemp[i + 1])
                            payloadblock.append(payloadblocktemp[i] + line)
                        else:
                            payloadblock.append(payloadblocktemp[i])
                    except IndexError:
                        debug = "File in bad format, fix will install profile\n"
                        self.logger.log(LogPriority.DEBUG, debug)
                        return False
                elif re.search("\($", payloadblocktemp[i]):
                    try:
                        if re.search("\);$", payloadblocktemp[i + 1]):
                            dontadd = True
                            line = re.sub(";$", "", payloadblocktemp[i + 1])
                            payloadblock.append(payloadblocktemp[i] + line)
                        else:
                            payloadblock.append(payloadblocktemp[i])
                    except IndexError:
                        debug = "File in bad format, fix will install profile\n"
                        self.logger.log(LogPriority.DEBUG, debug)
                        return False
                else:
                    payloadblock.append(payloadblocktemp[i])
                i += 1
            '''k is the key inside val variable (e.g. allowsimple)
            and v is the value, in this example, a list (e.g. ["1", "bool"])'''
            for k, v, in list(val.items()):
                if isinstance(v, list):
                    retval = self.checkSimple(k, v, payloadblock)
                elif isinstance(v, tuple):
                    retval = self.checkTuple(k, v, payloadblock)
                elif isinstance(v, dict):
                    retval = self.checkDict(k, v, payloadblock)
                if not retval:
                    return False
        else:
            if not val:
                return True
            else:
                debug = "There was no Payload Data for key: " + key + "\n"
                self.logger.log(LogPriority.DEBUG, debug)
                return False
        return retval    

    def checkSimple(self, k, v, payloadblock):
        '''@summary: Method that checks payloadblock contents
                for k (key) and associated v (value)
        @author: dwalker

        :param k: Not to be confused with the key in the calling
                method which was our identifier before the payload.
                This key is now the key in the inner dictionary
                passed through as val from the calling method
        :param v: Not to be confused with the value in the calling
                method which was our inner dictionary passed through
                as val. This val is now the list associated with our
                k value.
        :param payloadblock: A list of lines from our payload
                portion of the output from the system_profiler
                command
        :returns: bool - True or False

        '''
        founditem = False
        retval = True
        unsecure = False
        debug = ""
        for line in payloadblock:
            if re.search("^" + k + " = ", line.strip()):
                founditem = True
                temp = line.strip().split("=")
                try:
                    if temp[1]:
                        '''Remove any arbitrary whitespace'''
                        temp[1] = re.sub("\s", "", temp[1])
                        '''Remove semicolon at end if exists'''
                        temp[1] = re.sub(";$", "", temp[1])
                        '''If the second value inside the list v is the word
                        bool, then we want to make sure that our value found
                        after the = in our output matches what we're expecting
                        in v[0] which is either going to be a 1 or 0'''
                        if v[1] == "bool":
                            if str(temp[1].strip()) != v[0]:
                                debug += "Key: " + k + " doesn't " + \
                                    "contain the correct boolean " + \
                                    "value\n"
                                unsecure = True
                                break
                            '''If the second value inside the list v is the word
                            int, then we want to make sure that our value found
                            after the = in our output matches what we're expecting
                            in v[0] which could be any numerical integer.
                            Additionally, if it's "int", there will be a third value
                            inside the list v (v[2]) which will contain either the
                            word "more" or "less".  More indicates that if the values
                            don't match but the value in our output is a greater 
                            integer value than what we're expecting, then it's still
                            ok and vice versa with the less keyword.'''
                        elif v[1] == "int":
                            if v[2] == "more":
                                if int(temp[1].strip()) < int(v[0]):
                                    debug += "Key: " + k + " doesn't " + \
                                        "contain the correct integer " + \
                                        "value\n"
                                    unsecure = True
                                    break 
                            elif v[2] == "less":
                                if int(temp[1].strip()) > int(v[0]):
                                    debug += "Key: " + k + " doesn't " + \
                                        "contain the correct integer " + \
                                        "value\n"
                                    unsecure = True
                                    break
                            '''If the second value inside the list v is the word
                            string, then we want to make sure that our value found
                            after the = in our output matches what we're expecting
                            in v[0] which could be any string.'''
                        elif v[1] == "string":
                            if temp[1].strip() != v[0]:
                                debug += "Key: " + k + " doesn't " + \
                                    "contain the correct string value\n"
                                unsecure = True
                                break
                except IndexError:
                    debug += "Profile in bad format\n"
                    break
        if not founditem:
            debug = "Key: " + k + " not found\n"
            retval = False
        if unsecure:
            debug = "Key: " + k + " found but had an incorrect value\n"
            retval = False 
        if debug:
            self.logger.log(LogPriority.DEBUG, debug)
        return retval
    
    def checkTuple(self, k, v, payloadblock):
        '''@summary: Method that checks payloadblock contents
                for k (key) and associated v (value)
        @author: dwalker

        :param k: Not to be confused with the key in the calling
                method which was our identifier before the payload.
                This key is now the key in the inner dictionary
                passed through as val from the calling method
        :param v: Not to be confused with the value in the calling
                method which was our inner dictionary passed through
                as val. This val is now the tuple associated with
                our k value.
        :param payloadblock: A list of lines from our payload
                portion of the output from the system_profiler
                command
        :returns: bool - True or False

        '''
        retval = True
        iterator = 0
        temp, temp2 = [], []
        for line in payloadblock:
            if re.search("^" + k + "=", line):
                if re.search("\(\)$", line):
                    if str(v) == "()":
                        return True
                    else:
                        return False
                elif re.search("\($", line):
                    temp = payloadblock[iterator + 1:]
                    break
            else:
                iterator += 1
        iterator = 0
        for line in temp:
            if re.search("\)\;", line):
                temp2 = temp[:iterator]
            else:
                iterator += 1
        if temp2:
            temp = temp2
        if temp:
            replaceables = []
            for line in temp:
                if re.search("\,$", line):
                    line = re.sub("\,$", "", line)
                    replaceables.append(line)
                else:
                    replaceables.append(line)
            
            if replaceables:
                temp = replaceables
            removeables = []
            for line in temp:
                if line in v:
                    removeables.append(line)
            if removeables:
                v = list(v)
                for item in removeables:
                    v.remove(item)
                    temp.remove(item)
                v = tuple(v)
            if v:
                '''There are still items left so we didn't find them all'''
                debug = "The following tuple items weren't found for the key " + k + "\n"
                debug +=  str(v) + "\n"
                self.logger.log(LogPriority.DEBUG, debug)
                retval = False
            if temp:
                debug = "The following items were in the output that shouldn't have been\n"
                for item in temp:
                    if not re.search("\)\;|\($", item):
                        debug += str(temp) + "\n"
                        self.logger.log(LogPriority.DEBUG, debug)
                        retval = False
        else:
            debug = "key " + k + " wasn't found\n"
            self.logger.log(LogPriority.DEBUG, debug)
            retval = False
        return retval
     
    def checkDict(self, k, v, payloadblock):
        '''@summary: Method that checks payloadblock contents
                for k (key) and associated v (value)
        @author: dwalker

        :param k: Not to be confused with the key in the calling
                method which was our identifier before the payload.
                This key is now the key in the inner dictionary
                passed through as val from the calling method
        :param v: Not to be confused with the value in the calling
                method which was our inner dictionary passed through
                as val. This val is now the dict associated with
                our k value.
        :param payloadblock: A list of lines from our payload
                portion of the output from the system_profiler
                command
        :returns: bool - True or False

        '''
        retval = True
        iterator = 0
        for line in payloadblock:
            if re.search("^" + k + "=", line):
                if re.search("\{\}$", line):
                    if str(v) == "{}":
                        return True
                    else:
                        return False
                elif re.search("\{$", line):
                    temp = payloadblock[iterator + 1:]
                    break
            else:
                iterator += 1
        for k2, v2 in list(v.items()):
            if isinstance(v2, list):
                retval = self.checkSimple(k2, v2, temp)
            elif isinstance(v2, tuple):
                retval = self.checkTuple(k2, v2, temp)
            elif isinstance(v2, dict):
                retval = self.checkDict(k2, v2, temp)
            if not retval:
                return False
        return retval
    
    def setUndoCmd(self, undocmd):
        '''@summary: Mutator method to set self.undocmd to the
                passed in undo command.
        @author: dwalker

        :param undocmd: undo command passed through from
                update method

        '''
        self.undocmd = undocmd
    
    def setInstallCmd(self, installcmd):
        '''@summary: Mutator method to set self.installcmd to
                thev passed in install command.
        @author: dwalker

        :param installcmd: install command passed through from
                update method

        '''
        self.installcmd = installcmd
    
    def getUndoCmd(self):
        '''@summary: Accessor method to retrieve self.undocmd
        @author: dwalker


        :returns: self.undocmd

        '''
        return self.undocmd
    
    def getInstallCmd(self):
        '''@summary: Accessor method to retrieve self.installcmd
        @author: dwalker


        :returns: self.installcmd

        '''
        return self.installcmd
        
    def update(self):
        '''@summary: Method to set the install command for
        installing the profile for the fix method and set
        the remove command for removing the profile for the
        undo method in upper implementing classes
        @author: dwalker


        :returns: bool - True

        '''
        if int(self.osver) <= 12:
            pinstall = "/usr/bin/profiles -I -F " + self.path
            premove = "/usr/bin/profiles -R -F " + self.path
            # else use newer profiles commands
        else:
            pinstall = "/usr/bin/profiles install -path=" + self.path
            premove = "/usr/bin/profiles remove -path=" + self.path
        self.setInstallCmd(pinstall)
        self.setUndoCmd(premove)
        return True
    
    def commit(self):
        '''@summary: Method that performs the install command
                to install the appropriate profile for the
                calling rule.
        @author: dwalker


        :returns: bool - True or False

        '''
        self.ch = CommandHelper(self.logger)
        if self.installcmd:
            if not self.ch.executeCommand(self.installcmd):
                return False
            elif self.ch.getReturnCode() != 0:
                return False
            else:
                return True
        else:
            return False
        return True