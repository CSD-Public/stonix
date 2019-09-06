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
Created on Dec 14, 2017

@author: Breen Malmberg
'''

import os, re

import unittest
from stonix_resources import environment
from stonix_resources import logdispatcher
from stonix_resources.logdispatcher import LogPriority


class zzzTestRuleProperties(unittest.TestCase):
    '''test class designed to test certain properties common
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