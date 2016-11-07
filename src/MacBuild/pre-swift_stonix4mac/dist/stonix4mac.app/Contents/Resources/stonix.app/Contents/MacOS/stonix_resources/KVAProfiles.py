'''
Created on Mar 9, 2016

@author: dwalker
'''
import re
from logdispatcher import LogPriority

class KVAProfiles():

    def __init__(self, logger):
        self.logger = logger
        
    def validate(self, output, key, val):
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