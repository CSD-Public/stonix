#!/usr/bin/env python
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


# ============================================================================#
#               Filename          $RCSfile: stonix/configurationitem.py,v $
#               Description       Security Configuration Script
#               OS                Linux, Mac OS X, Solaris, BSD
#               Author            Dave Kennel
#               Last updated by   $Author: $
#               Notes             Based on CIS Benchmarks, NSA RHEL
#                                 Guidelines, NIST and DISA STIG/Checklist
#               Release           $Revision: 1.0 $
#               Modified Date     $Date: 2011/09/19 14:00:00 $
# ============================================================================#
"""
Created: 2011/08/01
Author: D. Kennel
"""

import types
import re


class ConfigurationItem(object):
    '''ConfigurationItem encapsulates all of the information regarding an
    individual configuration item.

    :version:
    :author: D. Kennel
    ATTRIBUTES

       The type of data in the value field. Valid values bool, string, int,
       float, list.
       datatype  (public) Required.

       This is the key portion of the Key = Value pair
       key  (public)
       The default value for this CI
       defvalue  (public)
       Comment entered by user for this CI
       usercomment  (public)

       Instructions to the end user for this CI entry.
       instructions  (public)
       The current value for this CI
       currvalue  (public)
       Whether or not this CI should appear in the 'simple' configfile.
       Only frequently modified items should appear in the 'simple' config.
       simple (public) (bool)
       A list of valid values to be used in validating data against a list of
       known good options.
       validvalueset (public) (list)
       For cases where there are multiple possible selections from a set
       maxnumselections indicates the maximum number that can be selected.
       maxnumselections (public) (int|string)
       The regex pattern can be used with configurations that should be checked
       for conformation with an known regular expression.
       regexpattern (public) (string(valid regular expression))

    The constructor for the ConfigurationItem can take all of the properties as
    arguments at object instantiation time. So if the ConfigurationItem class
    is being used without overrides then it can be constructed thusly
    myci = configurationitem.ConfigurationItem(mykey, mydefvalue, myusercomment,
    mydatatype, myinstructions, mycurrvalue, mysimple, myvalidset,
    mynumselections, myregexpattern)

    The CI object properties can also be set via setter methods after
    instantiation. CAUTION, the getters & setters should not be used in an
    attempt to make one CI instance do double duty. This will result in broken
    behavior.

    The validation routines do not support validation of dependencies between
    multiple selection items.

    NOTE: Dict support in this code is stub support. This class does not, at
    present, support dictionaries as data types.

    NOTE: The list type is, in effect, a list of strings datatype as data
    coercion inside a list is not supported.
    '''

    def __init__(self, datatype, delimiter=' ', key='DefaultKey', defvalue=None,
                 usercomment='', instructions='''
Default Instructions: If you are seeing this text then a stonix developer
forgot to override the default instructions for this key. Please file a bug.
''', currvalue=None, simple=False, validvalueset=None,
                 maxnumselections=1, regexpattern=None):
        self.datatype = None
        validtypes = ['bool', 'string', 'int', 'float', 'list', 'dict']
        if datatype not in validtypes:
            raise ValueError(
                'Invalid datatype specified. Valid entries bool, string, int, float, list. Recieved: ' + str(datatype))
        else:
            self.datatype = datatype
        self.delimiter = delimiter
        self.key = 'DefaultKey'
        self.setkey(key)
        self.defvalue = 'DefaultValue'
        self.usercomment = ''
        self.setusercomment(usercomment)
        self.instructions = '''
Default Instructions: If you are seeing this text then a stonix developer
forgot to override the default instructions for this key. Please file a bug.
'''
        self.setinstructions(instructions)
        self.simple = False
        self.setsimple(simple)
        self.validvalueset = None
        self.setvalidvalueset(validvalueset)
        self.maxnumselections = 1
        self.setmaxnumselections(maxnumselections)
        self.regexpattern = None
        self.setregexpattern(regexpattern)
        if defvalue == None:
            if self.datatype == 'bool':
                self.defvalue = False
            elif self.datatype == 'string':
                self.defvalue = 'DefaultValue'
            elif self.datatype == 'int':
                self.defvalue = 0
            elif self.datatype == 'float':
                self.defvalue = 0.0
            elif self.datatype == 'list':
                self.defvalue = []
        else:
            self.setdefvalue(defvalue)
        self.currvalue = self.defvalue
        if self.currvalue != None:
            self.updatecurrvalue(self.currvalue, True, listdelim=self.delimiter)

    def validate(self, testvalue):
        '''The validate method attempts to validate the passed value according to
        the data type for the class. Returns a bool which is true if the value
        is valid for the CI.
        :param varies: New value for this CI
        @author: D. Kennel
        :param testvalue:
        :returns: bool : True if testvalue is valid for this CI
        '''
        valid = False

        if self.datatype == 'bool':
            valid = self.__validatebool(testvalue)
        elif self.datatype == 'string':
            valid = self.__validatestring(testvalue)
        elif self.datatype == 'int':
            valid = self.__validateint(testvalue)
        elif self.datatype == 'float':
            valid = self.__validatefloat(testvalue)
        elif self.datatype == 'list':
            valid = self.__validatelist(testvalue)
        elif self.datatype == 'dict':
            valid = self.__validatedict(testvalue)
        if valid and self.datatype == 'string' and not \
                self.regexpattern == None:
            valid = self.validateagainstregex(testvalue)
        if valid and self.datatype == 'list' and not self.validvalueset == None:
            testresults = []
            for entry in testvalue:
                result = self.validateagainstlist(entry)
                testresults.append(result)
            if False in testresults:
                valid = False
            else:
                valid = True
        if valid and not self.validvalueset == None and \
                self.datatype not in ['list', 'dict']:
            valid = self.validateagainstlist(testvalue)

        return valid

    def getkey(self):
        '''Return the Key for this configuration item. The key is the identifier
        for this configuration element as seen in the config file.
        :returns: string : CI Key
        @author: D. Kennel
        '''
        return self.key

    def getdefvalue(self):
        '''Returns the default value for this CI.
        :returns: varies : CI value
        @author: D. Kennel
        '''
        return self.defvalue

    def getdatatype(self):
        '''Returns what datatype this CI is. Common types are Boolean, String and
        List.
        :returns: string : datatype
        @author: D. Kennel
        '''
        return self.datatype

    def getusercomment(self):
        '''Returns a string that is the current value of the user comment field
        for this CI. This field may return an empty string if no comment has
        been set.
        :returns: string : user comment
        @author: D. Kennel
        '''
        return self.usercomment

    def setusercomment(self, usercomment):
        '''Set the user comment text. Ideally this should be formatted into 80
        character lines.
        :param usercomment: user comment text
        @author: D. Kennel
        '''
        self.usercomment = usercomment

    def getinstructions(self):
        '''Return a string containing instructions to the user for this CI.
        :returns: string : Instructions for this CI
        @author: D. Kennel
        '''
        return self.instructions

    def insimple(self):
        '''Return true if this configuration item should appear in a simple config
        file. Only frequently modified items should appear in the 'simple'
        config.
        :returns: bool : True if CI should be in simple
        @author: D. Kennel
        '''
        return self.simple

    def getcurrvalue(self):
        '''Returns the current value for this configuration element. Datatype
        varies and should match the return for getdatatype.
        :returns: varies : current value for this CI
        @author: D. Kennel
        '''
        return self.currvalue

    def updatecurrvalue(self, newvalue, coercing=True, listdelim=' '):
        '''Updates the current value for this CI the update will call the
        validation routine before writing the supplied value to the class
        property. This method will attempt to coerce the value of the supplied
        input to match the datatype of the CI unless the coerce parameter is
        set to False. Note that only simple, one dimensional coercions are
        supported. This method can handle converting a string to an int but it
        cannot manage converting a string to a list of integers.
        :param varies: newvalue new value for this CI
        :param coerce: Bool default = True. Whether or not to attempt to coerce
        input to match the specified datatype.
        :param string: listdelim is the list delimiter to be used when
        splitting strings into lists.
        @author: D. Kennel
        :param newvalue:
        :param coercing:  (Default value = True)
        :param listdelim:  (Default value = ' ')
        '''
        try:
            delim = listdelim
            if coercing:
                if self.datatype == 'bool' and type(newvalue) is not \
                        types.BooleanType:
                    newvalue = newvalue.lower()
                    if newvalue in ['yes', 'true']:
                        newvalue = True
                    elif newvalue in ['no', 'false']:
                        newvalue = False
                elif self.datatype == 'int' and type(newvalue) is not \
                        types.IntType:
                    newvalue = int(newvalue)
                elif self.datatype == 'float' and type(newvalue) is not \
                        types.FloatType:
                    newvalue = float(newvalue)
                elif self.datatype == 'list' and type(newvalue) is not types.ListType:
                    if not newvalue:
                        newvalue = []
                    else:
                        newvalue = re.split(delim, newvalue)
                        # newvalue = newvalue.split(listdelim)
                # else:
                # print "inside else section of updatecurrvalue method\n\n"
                # newvalue = re.split(delim, newvalue)
                # print "newvalue after splitting: " + str(newvalue) + "\n"
        except(TypeError, ValueError):
            return False
        if self.validate(newvalue):
            self.currvalue = newvalue
            return True
        else:
            return False

    def setkey(self, key):
        '''Set the Key of the CI. This is the 'name' of the CI as it appears in
        the configuration file or the GUI. This may only safely be set during
        the initial construction of the CI. Runtime changes of the Key will
        have bad side effects.
        :param string: Key
        @author: dkennel
        :param key:
        '''
        if self.__validatestring(key):
            self.key = key
        else:
            raise TypeError('Invalid type provided as Key')

    def setdefvalue(self, value):
        '''Set the default value for the CI. This must be set after the datatype
        and the type of the default value must match the datatype. If a regex
        or validvalueset has been provided then the default value must match
        those as well. This may only safely be set during the initial
        construction of the CI. Runtime changes of the default value may have
        bad side effects.
        :param value: varies
        @author: dkennel
        '''
        if self.datatype == None:
            raise TypeError('Attempted to set default value when datatype is not set.')
        if self.validate(value):
            self.defvalue = value
        else:
            raise ValueError('Could not validate submitted default value')

    def setinstructions(self, instructions):
        '''Set the instructions for the CI. The Instructions are information
        provided to the user on what the CI setting controls. It should contain
        information on acceptable values, and what the default is. This should
        only be set during the intial construction of the CI.
        :param instructions: string
        @author: dkennel
        '''
        if self.__validatestring(instructions):
            self.instructions = instructions
        else:
            raise TypeError('Invalid type provided as Instructions')

    def setsimple(self, simple):
        '''Set whether or not this CI should appear in a simple config. This
        affects the config file which can be generated in two ways simple,
        which contains only the key settings and options that have been changed
        from their default values, or full which contains all the settings.
        This option should only be set during initial CI object construction.
        :param simple: Bool - True to include in simple config
        @author: dkennel
        '''
        if self.__validatebool(simple):
            self.simple = simple
        else:
            raise TypeError('Setsimple requires a Bool.')

    def setvalidvalueset(self, valset):
        '''Set a list of valid values that the default value and any passed value
        will be checked against. This property is only safely set when the CI
        is being constructed. Runtime changes will produce bad behavior.
        :param valset: python list
        @author: dkennel
        '''
        if valset == None:
            self.validvalueset = valset
            return
        if self.datatype == None:
            raise TypeError('Attempted to set a valid value set when datatype is not set.')
        if self.__validatelist(valset):
            results = []
            for item in valset:
                if self.datatype == 'string':
                    valid = self.__validatestring(item)
                elif self.datatype == 'int':
                    valid = self.__validateint(item)
                elif self.datatype == 'float':
                    valid = self.__validatefloat(item)
                elif self.datatype == 'list':
                    valid = self.__validatestring(item)
                elif self.datatype == 'bool':
                    raise TypeError('Valid value sets make no sense with boolean data types')
                results.append(valid)
            if False in results:
                raise TypeError('Set contains an invalid type.')
        else:
            raise TypeError('Setvalidvalueset requires a List.')
        self.validvalueset = valset

    def setmaxnumselections(self, selmax):
        '''Set a maximum permissible number of selections for items being selected
        from a validvalueset. The default for this property is 1. This property
        may only be safely set during the initial CI construction. Runtime
        changes will produce bad behavior.
        :param selmax: int
        @author: dkennel
        '''
        if self.__validateint(selmax):
            if selmax > 0:
                self.maxnumselections = selmax
            else:
                raise ValueError('Setmaxnumselections must be a positive integer.')
        else:
            raise TypeError('Setmaxnumselections requires a positive integer.')

    def setregexpattern(self, pattern):
        '''Set a regular expression pattern that will be used to validate user
        input to the CI. If no pattern is provided this check will be skipped.
        This property may only be safely changed during the initial CI
        construction. Runtime changes will result in bad behavior.
        :param pattern: string
        @author: dkennel
        '''
        if pattern == None:
            self.regexpattern = pattern
            return
        if self.datatype == 'string':
            if self.__validatestring(pattern):
                self.regexpattern = pattern
            else:
                raise TypeError('Invalid type provided as regex pattern')
        else:
            raise TypeError('Setregexpattern only makes sense with string datatype')

    def validateagainstregex(self, entry):
        '''This method validates a submitted entry against the regex pattern
        stored for this CI. If there is no regex pattern stored this method
        will always return True.
        :param entry: string to be checked
        :returns: Bool - True if matched.
        @author: dkennel
        '''
        if self.regexpattern == None:
            return True
        if re.match(self.regexpattern, entry):
            return True
        else:
            return False

    def validateagainstlist(self, entry):
        '''This method will validate a submitted entry against the entries in the
        validvalueset. It expects only a single entry and does a simple
        membership check.
        :param entry: varies
        :returns: bool - True if matched.
        @author: dkennel
        '''
        if entry in self.validvalueset:
            return True
        else:
            return False

    def __validatebool(self, testvar):
        """
        This is a helper validation method used to validate boolean options.
        @return bool : True if passed a bool
        @author: D. Kennel
        """
        try:
            if type(testvar) is bool:
                return True
            else:
                return False
        except (NameError):
            # testvar was undefined
            return False

    def __validatestring(self, testvar):
        """
        This is a helper validation method used to validate string options. It
        only checks the data type not the contents.
        @return: bool : True if testvar is a string
        @author: D. Kennel
        """
        try:
            if isinstance(testvar, str):
                # if type(testvar) is bytes:
                return True
            else:
                return False
        except (NameError):
            print("Throwing an error when checking type\n")
            # testvar was undefined
            return False

    def __validatelist(self, testvar):
        """
        This is a helper validation method used to validate list options. It
        only checks the data type, not the contents.
        @return: bool : True if testvar is a list
        @author: D. Kennel
        """
        try:
            if type(testvar) is list:
                return True
            else:
                return False
        except (NameError):
            # testvar was undefined
            return False

    def __validateint(self, testvar):
        """
        This is a helper validation method used to validate integer options. It
        only checks the data type, not the contents.
        @return: bool : True if testvar is an integer
        @author: D. Kennel
        """
        try:
            if type(testvar) is int:
                return True
            else:
                return False
        except (NameError):
            # testvar was undefined
            return False

    def __validatefloat(self, testvar):
        """
        This is a helper validation method used to validate floating point
        options. It only checks the data type, not the contents.
        @return: bool : True if testvar is a floating point number
        @author: D. Kennel
        """
        try:
            if type(testvar) is float:
                return True
            else:
                return False
        except (NameError):
            # testvar was undefined
            return False

    def __validatedict(self, testvar):
        """
        This is a helper validation method used to validate dictionary options.
        It only checks the data type, not the contents.
        @return: bool : True if testvar is a dictionary
        @author: D. Kennel
        """
        try:
            if type(testvar) is dict:
                return True
            else:
                return False
        except (NameError):
            # testvar was undefined
            return False