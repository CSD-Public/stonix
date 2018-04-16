#! /usr/bin/python

###############################################################################
#                                                                             #
# Copyright 2015-2017.  Los Alamos National Security, LLC. This material was  #
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
Created on Dec 14, 2017

@author: Breen Malmberg
'''

import os, re

import unittest
import environment
import logdispatcher
from logdispatcher import LogPriority


class zzzTestRuleProperties(unittest.TestCase):
    '''
    test class designed to test certain properties common
    to each rule and determine if those properties:
    1) exist
    2) have duplications
    3) are properly formatted
    '''

    def setUp(self):

        self.environ = environment.Environment()
        self.logger = logdispatcher.LogDispatcher(self.environ)
        # get list of all files in rules/ directory
        self.ruleslist = os.listdir('rules/')
        # remove any pyc files from the list
        for r in self.ruleslist:
            if re.search('\.pyc', r, re.IGNORECASE):
                self.ruleslist.remove(r)
        self.rulespath = self.environ.get_rules_path()

    def testDuplicateRuleNumbers(self):

        rulenumbers = []
        duplicates = []
        success = False

        for r in self.ruleslist:
            f = open(self.rulespath + r, 'r')
            contentlines = f.readlines()
            f.close()
            for line in contentlines:
                if re.search('self\.rulenumber =', line, re.IGNORECASE):
                    sline = line.split('=')
                    rulenumbers.append(sline[1])
        duplicates = [x for n, x in enumerate(rulenumbers) if x in rulenumbers[:n]]

        if not duplicates:
            success = True
        return success

    def testDuplicateRuleNames(self):

        rulenames = []
        duplicates = []
        success = False

        for r in self.ruleslist:
            f = open(self.rulespath + r, 'r')
            contentlines = f.readlines()
            f.close()
            for line in contentlines:
                if re.search('self\.rulename =', line, re.IGNORECASE):
                    sline = line.split('=')
                    rulenames.append(sline[1])
        duplicates = [x for n, x in enumerate(rulenames) if x in rulenames[:n]]

        if not duplicates:
            success = True
        return success

    def testPropertiesExist(self):

        success = True

        for r in self.ruleslist:
            f = open(self.rulespath + r, 'r')
            contentlines = f.readlines()
            f.close()
            
            rulenamefound = False
            rulenumberfound = False
            detailedresultsinitfound = False
            
            for line in contentlines:
                if re.search('self\.formatDetailedResults\(.initialize.\)', line, re.IGNORECASE):
                    detailedresultsinitfound = True
                if re.search('self\.rulename =', line, re.IGNORECASE):
                    rulenamefound = True
                if re.search('self\.rulenumber =', line, re.IGNORECASE):
                    rulenumberfound = True
            if not bool(rulenamefound):
                self.logger.log(LogPriority.DEBUG, "Rule: " + str(r) + " is missing self.rulename in init")
                success = False
            if not bool(rulenumberfound):
                self.logger.log(LogPriority.DEBUG, "Rule: " + str(r) + " is missing self.rulenumber in init")
                success = False
            if not bool(detailedresultsinitfound):
                self.logger.log(LogPriority.DEBUG, "Rule: " + str(r) + " is missing self.formatDetailedResults('initialize') in init")
                success = False

        return success

    def testRuleNameFormat(self):

        pass

    def testRuleNumberFormat(self):

        pass


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()