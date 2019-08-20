#!/usr/bin/env python3
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
Created on Aug 24, 2010

@author: Eric Ball
@change: eball 2016/07/12 Original implementation
@change: rsn 2017/03/20 Adding methods for validation, fisma check and setting
                        internal os variables per the environment.
@change: 2017/11/13 ekkehard - make eligible for OS X El Capitan 10.11+
@change: 2018/06/08 ekkehard - make eligible for macOS Mojave 10.14
'''

import re
from distutils.version import LooseVersion
from .logdispatcher import LogPriority


class CheckApplicable(object):
    '''This class uses either the passed in 'environment', or operating system
    identifiation set by the caller to determine if a family or OS is
    applicable to the identified operating system id.  Also carries
    a FISMA level check as well as a user privilege level and version or
    version ranges.


    '''
    def __init__(self, environ, logger):
        self.logger = logger
        self.environ = environ
        self.applicable = None

        self.myosfamily = self.environ.getosfamily()
        self.myosversion = self.environ.getosver()
        self.myostype = self.environ.getostype()
        self.systemFismaLevel = self.environ.getsystemfismacat()
        self.noroot = None

    def isApplicableValid(self, applicable):
        '''Validate that the applicable dictionary has valid keys and valid value
        types.
        
        @author: Roy Nielsen

        :param applicable: 

        '''
        success = False
        if isinstance(applicable, dict):
            keysSuccess = []
            valueSuccess = []
            validKeys = ['type', 'os', 'family', 'noroot', 'fisma']
            for key, value in list(applicable.items()):
                if key in validKeys:
                    keysSuccess.append(True)
                else:
                    keysSuccess.append(False)
                    continue
                if key is 'type' and value in ['black', 'white']:
                    valueSuccess.append(True)
                    continue
                if key is 'family' and isinstance(value, list):
                    valueSuccess.append(True)
                    continue
                if key is 'os' and isinstance(value, dict):
                    valueSuccess.append(True)
                    continue
                if key is 'noroot' and isinstance(value, bool):
                    valueSuccess.append(True)
                    continue
                if key is 'fisma' and value in ['low', 'medium', 'high']:
                    valueSuccess.append(True)
                    continue
                valueSuccess.append(False)
            if False in keysSuccess or False in valueSuccess:
                success = False
            else:
                success = True

        return success

    def isApplicable(self, applicableDict={'default': 'default'}):
        '''This method returns true if the rule applies to the platform on which
        stonix is currently running. The method in this template class will
        return true by default. The class property applicable will be
        referenced when this method is called and should be set by classes
        inheriting from the rule class including sub-template rules and
        concrete rule implementations.
        
        The format for the applicable property is a dictionary. The dictionary
        will be interpreted as follows:
        Key    Values        Meaning
        type    black/white  Whether the rest of the entries will be
                             interpreted as a whitelist (apply to) or a
                             blacklist (do not apply to). Blacklist is the
                             default.
        family  [list, valid environment.getosfamily() return types] The listed
                             os family will be whitelisted or blacklisted
                             according to the value of the type key.
        os    [Dict: key is a valid regex string that will match against return
                            from environment.getostype(), value is a list
                            containing version numbers, the - symbol, the +
                            symbol, or the letter "r" +|- may only be combined
                            with a single version number. "r" indicates a range
                            and expects 2 version numbers.]
                            This key is for matching specific os versions.
                             To match all Mac OS 10.11 and newer:
                             os: {'Mac OS X': ['10.11', '+']}
                             To match all Mac OS 10.8 and older:
                             os: {'Mac OS X': ['10.8', '-']}
                             To match only RHEL 6:
                             os: {'Red Hat Enterprise Linux': ['6.0']}
                             To match only Mac OS X 10.11.5:
                             os: {'Mac OS X': ['10.11.5']
                             To match a series of OS types:
                             os: {'Mac OS X': ['10.11', 'r', '10.13'],
                                  'Red Hat Enterprise Linux': ['6.0', '+'],
                                  'Ubuntu: ['14.04']}
        noroot   True|False This is an option, needed on systems like OS X,
                            which are "rootless". Meaning the root user isn't
                            used like a regular user. On these systems some
                            rules aimed at the user environment may not work or
                            actually cause problems. If this option is set to
                            True (python bool) then this method will return
                            false if EUID == 0. The default is False.
        default  default    This is the default value in the template class and
                            always causes the method to return true. The
                            default only takes affect if the family and os keys
                            are not defined.
        
        An Example dictionary might look like this:
        applicable = {'type': 'white',
                           'family': Linux,
                           'os': {'Mac OS X': ['10.11', 'r', '10.14.10']}
        That example whitelists all Linux operating systems and Mac OS X from
        10.11.0 to 10.14.10.
        
        The family and os keys may be combined. Note that specifying a family
        will mask the behavior of the more specific os key.
        
        Note that version comparison is done using the distutils.version
        module. If the stonix environment module returns a 3 place version
        string then you need to provide a 3 place version string. I.E. in this
        case 10.11 only matches 10.11.0 and does not match 10.11.3 or 10.11.5.
        
        This method may be overridden if required.

        :param applicableDict:  (Default value = {'default': 'default'})
        :returns: bool :
        @author D. Kennel
        @change: 2015/04/13 added this method to template class
        @change: 2017/03/18 rsn adding fisma check as well as vaildating both
                                self.applicable and passed in applicableDict.

        '''
        applies = False

        self.logger.log(LogPriority.DEBUG,
                        'Dictionary is: ' + str(applicableDict))
        try:
            default = applicableDict['default']
            if default == 'default':
                #####
                # Use self.applicable as is
                valid = self.isApplicableValid(self.applicable)
                self.logger.log(LogPriority.DEBUG, "valid: " + str(valid))
                if valid:
                    applicable = self.applicable
        
        except KeyError:
            valid = self.isApplicableValid(applicableDict)
            applicable = applicableDict

        if not valid:
            self.logger.log(LogPriority.DEBUG, "Passed in 'applicable' has invalid contents...")
            return applies
        else:
            self.logger.log(LogPriority.DEBUG, "applicable appears to be valid.")

        # Determine whether we are a blacklist or a whitelist, default to a
        # blacklist
        if 'type' in applicable:
            listtype = applicable['type']
        else:
            listtype = 'black'
        # Set the default return as appropriate to the list type
        assert listtype in ['white', 'black'], 'Invalid list type specified: %r' % listtype
        if listtype == 'black':
            applies = True
        else:
            applies = False

        # Process the os family list
        if 'family' in applicable:
            if self.myosfamily in applicable['family']:
                if listtype == 'black':
                    applies = False
                else:
                    applies = True
                self.logger.log(LogPriority.DEBUG,
                                'Family match, applies: ' + str(applies))

        # Process the OS list
        if 'os' in applicable:
            for ostype, osverlist in applicable['os'].items():
                if re.search(ostype, self.myostype):
                    inRange = self.isInRange(osverlist)
                    if inRange:
                        if listtype == 'black':
                            applies = False
                        else:
                            applies = True

        # Perform the rootless check
        if applies and self.environ.geteuid() == 0:
            if 'noroot' in applicable:
                if applicable['noroot'] is True:
                    applies = False

        return applies

    def isInRange(self, rangeList, myversion=0):
        '''This method separates out the range-checking functionality of the
        original rule.isapplicable() method. The proper formats for a version
        list are detailed in the isapplicable docs above.

        :param rangeList: 
        :param myversion:  (Default value = 0)
        :returns: bool
        @author: David Kennel, Eric Ball

        '''
        if not myversion:
            myversion = self.myosversion
        # Process version and up
        if '+' in rangeList:
            assert len(rangeList) is 2, "Wrong number of entries for a +"
            if rangeList[1] == '+':
                baseversion = rangeList[0]
            else:
                baseversion = rangeList[1]
            if LooseVersion(self.myosversion) >= LooseVersion(baseversion):
                return True
            else:
                return False
        # Process version and lower
        elif '-' in rangeList:
            assert len(rangeList) is 2, "Wrong number of entries for a -"
            if rangeList[1] == '-':
                baseversion = rangeList[0]
            else:
                baseversion = rangeList[1]
            if LooseVersion(self.myosversion) <= LooseVersion(baseversion):
                return True
            else:
                return False
        # Process inclusive range
        elif 'r' in rangeList:
            assert len(rangeList) is 3, "Wrong number of entries for a range"
            vertmp = rangeList
            vertmp.remove('r')
            if LooseVersion(vertmp[0]) > LooseVersion(vertmp[1]):
                highver = vertmp[0]
                lowver = vertmp[1]
            elif LooseVersion(vertmp[0]) < LooseVersion(vertmp[1]):
                highver = vertmp[1]
                lowver = vertmp[0]
            else:
                raise ValueError('Range versions are the same')
            if LooseVersion(self.myosversion) <= LooseVersion(highver) \
               and LooseVersion(self.myosversion) >= LooseVersion(lowver):
                return True
            else:
                return False
        # Process explicit match
        else:
            if self.myosversion in rangeList:
                return True
            else:
                return False

    def fismaApplicable(self, checkLevel=None, systemLevel=None):
        '''Check if the passed in level matches the class variable level.
        
        @author: David Kennel, Roy Nielsen
        
        applies = False
        clevel = ""
        slevel = ""
        if checkLevel is not None and checkLevel in ['high', 'med', 'low']:
            clevel = checkLevel
        else:
            try:
                clevel = self.applicable['fisma']
            except KeyError:
                self.logger.log(LogPriority.DEBUG, traceback.format_exc())
                self.logger.log(LogPriority.DEBUG, "Can't acquire a valid checkLevel...")
                raise ValueError('checkLevel invalid: valid values are low, med, high')
        
        if systemLevel is not None and systemLevel in ['high', 'med', 'low']:
             slevel = systemLevel
        else:
            try:
                slevel = self.environ.getsystemfismacat()
            except KeyError:
                self.logger.log(LogPriority.DEBUG, traceback.format_exc())
                self.logger.log(LogPriority.DEBUG, "Can't acquire a valid checkLevel...")

        :param checkLevel:  (Default value = None)
        :param systemLevel:  (Default value = None)
        :raises if: slevel
        :raises pass: 
        :raises elif: slevel
        :raises if: clevel
        :raises applies: False
        :raises elif: slevel
        :raises if: clevel in
        :raises applies: False

        '''
        pass

    def getOsFamily(self):
        return self.myosfamily

    def getOsType(self):
        return self.myostype

    def getOsVer(self):
        return self.myosversion

    def setOsFamily(self, osfamily):
        self.myosfamily = osfamily

    def setOsType(self, ostype):
        self.myostype = ostype

    def setOsVer(self, osver):
        self.myosversion = osver

    def setSystemFismaLevel(self, level):
        self.systemFismaLevel = level

    def getSystemFismaLevel(self):
        return self.systemFismaLevel

    def setOsBasedOnEnv(self):
        '''Set the values to check against to the values
        found in the environment.


        '''
        self.myosfamily = self.environ.getosfamily()
        self.myosversion = self.environ.getosver()
        self.myostype = self.environ.getostype()
        self.fismacat = self.environ.getsystemfismacat()

