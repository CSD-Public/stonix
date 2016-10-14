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
#from Crypto.Util.RFC1751 import k2


class KVAProfiles():

    def __init__(self, logger):
        self.logger = logger

    def validate2(self, output, key, val):
        '''if the user's installed profile has any values that are less
        stringent than our own we should apply our profile'''
        debug = ""
        profileFound = False
        iterator = 0
        unsecure = False
        output2 = ""
        '''dont' care about the value, just the profile's existence'''
        if not val:
            for line in output:
                if re.search("^" + key, line.strip()):
                    return True
            '''We never found the profile, return False'''
            debug = "The profile sub-identifier:" + key + " was not found\n"
            self.logger.log(LogPriority.DEBUG, debug)
            return False
        else:
            '''we do care about the value along with the profile's existence'''
            for line in output:
                if re.search("^" + key + ":$", line.strip()):
                    iterator2 = 0
                    profileFound = True
                    temp = output[iterator + 1:]
                    length = len(temp) - 1
                    for line2 in temp:
                        if re.search("^\}$", line2.strip()):
                            output2 = temp[:iterator2]
                        elif iterator2 == length:
                            output2 = temp[:iterator2 + 1]
                        else:
                            iterator2 += 1
                else:
                    iterator += 1
            if not profileFound:
                debug = "The profile sub-identifier: " + key + " was not found\n"
                self.logger.log(LogPriority.DEBUG, debug)
                return False
            if output2:
                '''key2 is the value of the original key
                val2 is the datatype of it's value'''
                for key2, val2 in val.iteritems():
                    founditem = False
                    for line in output2:
                        if re.search("^" + key2 + " =", line.strip()):
                            founditem = True
                            temp = line.strip().split("=")
                            if temp[1]:
                                temp[1] = re.sub(";$", "", temp[1])
                                if val2[1] == "bool":
                                    if str(temp[1].strip()) != str(val2[0]):
                                        debug += "Key: " + key2 + " doesn't " + \
                                            "contain the correct boolean " + \
                                            "value\n"
                                        unsecure = True
                                elif val2[1] == "int":
                                    if val2[2] == "more":
                                        if int(temp[1].strip()) < int(val2[0]):
                                            debug += "Key: " + key2 + " doesn't " + \
                                                "contain the correct integer " + \
                                                "value\n"
                                            unsecure = True
                                    elif val2[2] == "less":
                                        if int(temp[1].strip()) > int(val2[0]):
                                            debug += "Key: " + key2 + " doesn't " + \
                                                "contain the correct integer " + \
                                                "value\n"
                                            unsecure = True
                            else:
                                debug += "Key: " + key2 + " doesn't contain " + \
                                    "a value at all\n"
                                unsecure = True
                    if not founditem:
                        debug += "key: " + key2 + " not found.  There may " + \
                            "be other keys that don't exist but we don't " + \
                            "need to check for those due to the nature of " + \
                            "installing secure profiles.\n"
                        unsecure = True
                    if debug:
                        self.logger.log(LogPriority.DEBUG, debug)
                    if unsecure:
                        return False
                return True
            else:
                debug = "Key: " + key + " doesn't contain any nested " + \
                    "key value pairs\n"
                self.logger.log(LogPriority.DEBUG, debug)
                return False

    def validate(self, output, key, val):
        #in instance where the profile is installed with no payload
        '''When passed through, key should be the identifier to be found
        such as com.apple.DiscRecording and val should be the rest of the
        dictionary'''
        retval = True
        if not val:
            for line in output:
                if re.search("^" + key, line.strip()):
                    return True
            '''We never found the profile, return False'''
            debug = "The profile sub-identifier:" + key + " was not found\n"
            self.logger.log(LogPriority.DEBUG, debug)
            return False
        else:
            print "\n\n\nTHE KEY WE'RE LOOKING FOR IS: \n\n"
            print key + "\n\n"
            iterator1 = 0
            keyoutput = []
            keyfound = False
            for line in output:
                if re.search("^" + key + ":$", line.strip()):
                    keyfound = True
                    print "WE FOUND THE KEY: " + str(key) + "\n\n"
                    temp = output[iterator1 + 1:]
                    print "temp value is :" + str(temp) + "\n"
                    iterator2 = 0
                    for line in temp:
                        if re.search("^Payload Data:", line.strip()):
                            print "found the payload data line\n"
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
                print "payloadblock is: " + str(payloadblock) + "\n\n\n"
#                 for k, v in val.iteritems():
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
        print "inside checkSimple method\n"
        founditem = False
        retval = True
        unsecure = False
        debug = ""
        print "The key we're looking for is " + str(k) + "\n"
        for line in keyoutput:
            print "current line: " + line + "\n"
            if re.search("^" + k + "=", line.strip()):
                print "we found the key\n"
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
                            if temp[1].strip() != v[1]:
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
        for line in payloadblock:
            if re.search("^" + k + "=", line):
                if re.search("\(\)$", line):
                    if str(v) == "()":
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