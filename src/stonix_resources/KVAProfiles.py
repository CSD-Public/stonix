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
Created on Mar 9, 2016

@author: dwalker
'''
import re
from logdispatcher import LogPriority
from CommandHelper import CommandHelper


class KVAProfiles():

    def __init__(self, logger, path):
        self.logger = logger
        self.path = path
        self.undocmd = ""
        self.installcmd = ""

    def validate(self, output, key, val):
        #in instance where the profile is installed with no payload
        '''When passed through, key should be the identifier to be found
        such as com.apple.DiscRecording and val should be the rest of the
        dictionary'''
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
                if not re.search("^}$", line.strip()):
                    line = re.sub("\s+", "", line)
                    payloadblocktemp.append(line)
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
            for k, v, in val.iteritems():
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

    def checkSimple(self, k, v, keyoutput):
        founditem = False
        retval = True
        unsecure = False
        debug = ""
        for line in keyoutput:
            if re.search("^" + k + "=", line.strip()):
                founditem = True
                temp = line.strip().split("=")
                try:
                    if temp[1]:
                        temp[1] = re.sub(";$", "", temp[1])
                        if v[1] == "bool":
                            if str(temp[1].strip()) != v[0]:
                                debug += "Key: " + k + " doesn't " + \
                                    "contain the correct boolean " + \
                                    "value\n"
                                unsecure = True
                                break
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
        for k2, v2 in v.iteritems():
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
        self.undocmd = undocmd
    
    def setInstallCmd(self, installcmd):    
        self.installcmd = installcmd
    
    def getUndoCmd(self):
        return self.undocmd
    
    def getInstallCmd(self):
        return self.installcmd
        
    def update(self):
        cmd = ["/usr/bin/profiles", "-I", "-F", self.path]
        self.setInstallCmd(cmd)
        cmd = ["/usr/bin/profiles", "-R", "-F", self.path]
        self.setUndoCmd(cmd)
        return True
    
    def commit(self):
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