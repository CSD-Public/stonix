#!/usr/bin/python
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
'''
This is the test suite for stonix
@author: ekkehard j. koch, roy s. nielsen
@note: 2015-02-15 - ekkehard - original implementation
'''
import unittest
import os
import re
import sys
import time
import traceback
import optparse
from stonix_resources.environment import Environment
from stonix_resources.configuration import Configuration
from stonix_resources.StateChgLogger import StateChgLogger
from stonix_resources.logdispatcher import LogDispatcher
from stonix_resources.logdispatcher import LogPriority

class ConsoleAndFileWriter():
    '''
    This class provides an object that can be passed to
    unittest.TextTestRunner as a stream, providing both
    stderr out to the console and output to a logfile
    @author: Eric Ball
    @note: None
    @change: 2015-03-12 - EB - Original implementation
    '''
    
    def __init__(self, filename):
        self.filename = filename
        self.fo = open(filename, "w")
        
    def write(self, wstring):
        sys.stderr.write(wstring)
        self.fo.write(wstring)
        
    def flush(self):
        sys.stderr.flush()
        self.fo.flush()

class test_rules_and_unit_test (unittest.TestCase):
    '''
    This class is designed to make sure there is a unit test
    for every rule and a rule for every unit test
    @author: ekkehard j. koch
    @note: Make sure it can handle entire rule testing suite
    @change: 2015-02-25 - ekkehard - Original Implementation
    '''

    def setUp(self):
        success = True
        self.ruleDictionary = RuleDictionary()
        return success

    def tearDown(self):
        success = True
        return success

    def runTest(self):
        '''
        This is to check all os x rules
        @author: ekkehard j. koch
        @note: Make sure it can handle entire rule scenario
        '''
        success = True
        if success:
            success = self.zzz_for_every_rule()
        if success:
            success = self.rule_for_every_zzz()
        return success

    def zzz_for_every_rule(self):
        success = True
        self.ruleDictionary.gotoFirstRule()
        while not (self.ruleDictionary.getCurrentRuleItem() == None):
            moduletestfound = self.ruleDictionary.getHasUnitTest()
            name = self.ruleDictionary.getRuleName()
            messagestring = "No unit test available for rule " + str(name)
            self.assertTrue(moduletestfound, messagestring)
            self.ruleDictionary.gotoNextRule()
        return success

    def rule_for_every_zzz(self):
        success = True
        self.ruleDictionary.gotoFirstRule()
        while not (self.ruleDictionary.getCurrentRuleItem() == None):
            moduletestfound = self.ruleDictionary.getHasRule()
            name = self.ruleDictionary.getTestName()
            messagestring = "No rule available for unit test " + str(name)
            self.assertTrue(moduletestfound, messagestring)
            self.ruleDictionary.gotoNextRule()
        return success


class FrameworkDictionary():
    
    def __init__(self):
        self.unittestprefix = 'zzzTestFramework'
        self.initlist = ['__init__.py', '__init__.pyc', '__init__.pyo']
        self.environ = Environment()
        self.environ.setdebugmode(False)
        self.environ.setverbosemode(True)
        self.effectiveUserID = self.environ.geteuid()
        self.config = Configuration(self.environ)
        self.logdispatch = LogDispatcher(self.environ)
        self.statechglogger = StateChgLogger(self.logdispatch, self.environ)
        self.scriptPath = self.environ.get_script_path()
        self.stonixPath = self.environ.get_resources_path()
        self.rulesPath = self.environ.get_rules_path()
        self.frameworkpath = self.stonixPath + "/"
        self.frameworkdictionary = {}
        self.keys = None
        self.key = None
        self.keyIndexNumber = 0
        self.keysNumberOf = 0
        self.dictinaryItem = None
        self.initializeDictionary()

    def gotoFirstItem(self):
        self.keyIndexNumber = 0
        self.keys = sorted(self.frameworkdictionary.keys())
        self.keysNumberOf = len(self.keys)
        self.key = self.keys[self.keyIndexNumber]
        self.dictinaryItem = self.frameworkdictionary[self.key]

    def gotoNextItem(self):
        self.keyIndexNumber = self.keyIndexNumber + 1
        self.keys = sorted(self.frameworkdictionary.keys())
        self.keysNumberOf = len(self.keys)
        if (self.keysNumberOf - 1) < self.keyIndexNumber:
            self.keyIndexNumber = 0
            self.dictinaryItem = None
        else:
            self.key = self.keys[self.keyIndexNumber]
            self.dictinaryItem = self.frameworkdictionary[self.key]

    def getCurrentItem(self):
        return self.dictinaryItem
    
    def getTestPath(self):
        return self.dictinaryItem["path"]
        
    def getTestName(self):
        return self.dictinaryItem["name"]
        
    def initializeDictionary(self):
        '''
        Fill in all the rule information
        @author: ekkehard j. koch
        @note: None
        '''
        success = True
        messagestring = "--------------------------------- start"
        self.logdispatch.log(LogPriority.INFO, str(messagestring))
        self.validrulefiles = []
        self.modulenames = []
        self.classnames = []
        rulefiles = os.listdir(str(self.frameworkpath))
        for rfile in rulefiles:
            rule_class = None
            if rfile in self.initlist:
                continue
            elif re.search("\.py$", rfile):
                modulename = rfile.replace('.py', '')
                if modulename.startswith(self.unittestprefix):
                    self.initializeDictoniaryItem(modulename)
                    self.dictinaryItem["name"] = modulename
                    self.dictinaryItem["found"] = True
            else:
                continue
        return success
        
    def initializeDictoniaryItem(self, name):
        success = True
        item = {"name": "",
                "path": self.frameworkpath,
                "found": False,
                "errormessage": []}
        self.frameworkdictionary[name] = item
        self.dictinaryItem = self.frameworkdictionary[name]
        return success


class RuleDictionary ():
    '''
    This class is designed encapsulate the dictionary object for
    rules.
    @author: ekkehard j. koch
    @note: None
    @change: 2015-02-25 - ekkehard - Original Implementation
    '''
    
    def __init__(self):
        self.unittestprefix = 'zzzTestRule'
        self.initlist = ['__init__.py', '__init__.pyc', '__init__.pyo']
        self.environ = Environment()
        self.environ.setdebugmode(False)
        self.environ.setverbosemode(True)
        self.effectiveUserID = self.environ.geteuid()
        self.config = Configuration(self.environ)
        self.logdispatch = LogDispatcher(self.environ)
        self.statechglogger = StateChgLogger(self.logdispatch, self.environ)
        self.scriptPath = self.environ.get_script_path()
        self.stonixPath = self.environ.get_resources_path()
        self.rulesPath = self.environ.get_rules_path()
        self.unittestpath = self.scriptPath + "/"
        self.ruledictionary = {}
        self.keys = None
        self.key = None
        self.keyIndexNumber = 0
        self.keysNumberOf = 0
        self.dictinaryItem = None
        self.initializeRuleInfo()
        self.initializeRuleUnitTestData()
        self.initializeRuleContextData()

    def gotoFirstRule(self):
        self.keyIndexNumber = 0
        self.keys = sorted(self.ruledictionary.keys())
        self.keysNumberOf = len(self.keys)
        self.key = self.keys[self.keyIndexNumber]
        self.dictinaryItem = self.ruledictionary[self.key]

    def gotoNextRule(self):
        self.keyIndexNumber = self.keyIndexNumber + 1
        self.keys = sorted(self.ruledictionary.keys())
        self.keysNumberOf = len(self.keys)
        if (self.keysNumberOf - 1) < self.keyIndexNumber:
            self.keyIndexNumber = 0
            self.dictinaryItem = None
        else:
            self.key = self.keys[self.keyIndexNumber]
            self.dictinaryItem = self.ruledictionary[self.key]
    
    def getCorrectEffectiveUserid(self):
        return self.ruledictionary[self.key]["rulecorrecteffectiveuserid"]

    def getCurrentRuleItem(self):
        return self.dictinaryItem
    
    def getIsApplicable(self):
        return self.ruledictionary[self.key]["ruleisapplicable"]
    
    def getHasRule(self):
        return self.ruledictionary[self.key]["rulefound"]
    
    def getHasUnitTest(self):
        return self.ruledictionary[self.key]["unittestfound"]
            
    def getRuleName(self):
        return self.ruledictionary[self.key]["rulename"]
    
    def getRuleNumber(self):
        return self.ruledictionary[self.key]["rulenumber"]
        
    def getTestName(self):
        return self.ruledictionary[self.key]["unittestname"]

    def initializeRuleInfo(self):
        '''
        Fill in all the rule information
        @author: ekkehard j. koch
        @note: None
        '''
        success = True
        messagestring = "--------------------------------- start"
        self.logdispatch.log(LogPriority.INFO, str(messagestring))
        self.validrulefiles = []
        self.modulenames = []
        self.classnames = []
        rulefiles = os.listdir(str(self.rulesPath))
        for rfile in rulefiles:
            rule_class = None
            if rfile in self.initlist:
                continue
            elif re.search("\.py$", rfile):
                rulename = rfile.replace('.py', '')
                rulefilename = rfile
                ruleclassname = 'rules.' + rulename + '.' + rulename
                ruleclasspath = self.rulesPath + "/" + rfile
                parts = ruleclassname.split(".")
                rulemoduleimportstring = "stonix_resources." + \
                ".".join(parts[:-1])
                ruleinstanciatecommand = "rule_class = mod." + ruleclassname
                unittestname = self.unittestprefix + rulename
                unittestfilename = self.unittestprefix + rfile
                unittestclasspath = self.unittestpath + unittestfilename
                unittestclassname = unittestname + "." + unittestname
                unittestmoduleimportstring = unittestname
                unittestinstanciatecommand = "unittest_class = mod." + \
                unittestclassname
                self.initializeDictoniaryItem(rulename)
                self.ruledictionary[rulename]["rulename"] = rulename
                self.ruledictionary[rulename]["ruleclassname"] = ruleclassname
                self.ruledictionary[rulename]["ruleclasspath"] = ruleclasspath
                self.ruledictionary[rulename]["rulefilename"] = rulefilename
                self.ruledictionary[rulename]["ruleclassname"] = ruleclassname
                self.ruledictionary[rulename]["rulemoduleimportstring"] = rulemoduleimportstring
                self.ruledictionary[rulename]["ruleinstanciatecommand"] = ruleinstanciatecommand
                self.ruledictionary[rulename]["ruleobject"] = None
                self.ruledictionary[rulename]["ruleisapplicable"] = True
                self.ruledictionary[rulename]["rulecorrecteffectiveuserid"] = True
                self.ruledictionary[rulename]["rulefound"] = True
                self.ruledictionary[rulename]["unittestname"] = unittestname
                self.ruledictionary[rulename]["unittestclasspath"] = unittestclasspath
                self.ruledictionary[rulename]["unittestfilename"] = unittestfilename
                self.ruledictionary[rulename]["unittestclassname"] = unittestclassname
                self.ruledictionary[rulename]["unittestmoduleimportstring"] = unittestmoduleimportstring
                self.ruledictionary[rulename]["unittestinstanciatecommand"] = unittestinstanciatecommand
                self.ruledictionary[rulename]["unittestobject"] = None
                self.ruledictionary[rulename]["unittestfound"] = False
                self.ruledictionary[rulename]["errormessage"] = []
                try:
                    mod = __import__(rulemoduleimportstring)
                except Exception:
                    trace = traceback.format_exc()
                    messagestring = "Error importing rule: " + rulename + " " + \
                    rulemoduleimportstring + " - " + trace
                    self.ruledictionary[rulename]["errormessage"].append(messagestring)
                    self.logdispatch.log(LogPriority.ERROR, messagestring)
                    continue
                try:
                    exec(ruleinstanciatecommand)
#                    rule_class = getattr(mod, classimportname)
#                    exec("rule_class = mod.rules." + name + "." + name)
                except Exception:
                    trace = traceback.format_exc()
                    messagestring = "Error importing rule: " + rulename + " " + \
                    rulemoduleimportstring + " - " + trace
                    self.logdispatch.log(LogPriority.ERROR,
                                         "Error finding rule class reference: "
                                         + trace)
                continue
                try:
                    self.rule = rule_class(self.config,
                                           self.environ,
                                           self.logdispatch,
                                           self.statechglogger)
                    self.ruledictionary[rulename]["ruleobject"] = self.rule
                except Exception:
                    trace = traceback.format_exc()
                    messagestring = "Error initializing rule: " + rulename + \
                    " - " + trace
                    self.ruledictionary[rulename]["errormessage"].append(messagestring)
                    self.logdispatch.log(LogPriority.ERROR, messagestring)
                    continue
            else:
                continue
        return success

    def initializeRuleUnitTestData(self):
        '''
        Fill in all the unit test data
        @author: ekkehard j. koch
        @note: None
        '''
        success = True
        messagestring = "--------------------------------- start"
        self.logdispatch.log(LogPriority.INFO, str(messagestring))
        ruletestfiles = os.listdir(str(self.unittestpath))
        for rtfile in ruletestfiles:
            if rtfile in self.initlist:
                continue
            elif re.search("\.py$", rtfile):
                if rtfile.startswith(self.unittestprefix):
                    unittestmodule = rtfile.replace('.py', '')
                    module = unittestmodule.replace(self.unittestprefix, "")
                    if self.findDictonaryItem(module):
                        self.dictinaryItem["unittestfound"] = True
                    else:
                        self.dictinaryItem["rulename"] = module
                        self.dictinaryItem["rulefound"] = False
                        self.dictinaryItem["unittestname"] = unittestmodule
                        self.dictinaryItem["unittestfound"] = True
                else:
                    continue
        return success

    def initializeRuleContextData(self):
        '''
        Make sure you have all the contextual data for rules
        @author: ekkehard j. koch
        @note: None
        '''
        success = True
        messagestring = "--------------------------------- start"
        self.logdispatch.log(LogPriority.INFO, str(messagestring))
        keys = sorted(self.ruledictionary.keys())
        for key in keys:
            ruleclassname = self.ruledictionary[key]["ruleclassname"]
            classimportname = "." + ruleclassname
            rulename = self.ruledictionary[key]["rulename"]
            ruleclasspath = self.ruledictionary[key]["ruleclasspath"]
            rule_class = self.ruledictionary[key]["ruleobject"]
            rulemoduleimportstring = \
            self.ruledictionary[key]["rulemoduleimportstring"]
            ruleclasspath = \
            self.ruledictionary[key]["ruleclasspath"]
            ruleinstanciatecommand = \
            self.ruledictionary[key]["ruleinstanciatecommand"]
            try:
                mod = __import__(rulemoduleimportstring)
            except Exception:
                trace = traceback.format_exc()
                messagestring = "Error importing rule: " + rulename + " " + \
                rulemoduleimportstring + " - " + trace
                self.ruledictionary[key]["errormessage"].append(messagestring)
                self.logdispatch.log(LogPriority.ERROR, messagestring)
                continue
            try:
                exec(ruleinstanciatecommand)
#                rule_class = getattr(mod, classimportname)
#                exec("rule_class = mod.rules." + rulename + "." + rulename)
            except Exception:
                trace = traceback.format_exc()
                messagestring = "Error importing rule: " + rulename + " " + \
                rulemoduleimportstring + " - " + trace
                self.logdispatch.log(LogPriority.ERROR,
                                     "Error finding rule class reference: "
                                     + trace)
                continue
            try:
                self.rule = rule_class(self.config,
                                       self.environ,
                                       self.logdispatch,
                                       self.statechglogger)
                rulenumber = self.rule.getrulenum()
                self.ruledictionary[key]["rulenumber"] = rulenumber
                messagestring = str(key) + "(" + str(rulenumber) + ") initialized!"
                isapplicable = self.rule.isapplicable()
                isRootRequired = self.rule.getisrootrequired()
                if not isapplicable:
                    self.ruledictionary[key]["ruleisapplicable"] = False
                    messagestring = messagestring + " is not applicable."
                else:
                    self.ruledictionary[key]["ruleisapplicable"] = True
                    messagestring = messagestring + " is applicable."
                if self.effectiveUserID == 0 and isRootRequired:
                    self.ruledictionary[key]["rulecorrecteffectiveuserid"] = True
                    messagestring = messagestring + " is running in " + \
                    "correct context."
                elif not self.effectiveUserID == 0 and not isRootRequired:
                    self.ruledictionary[key]["rulecorrecteffectiveuserid"] = True
                    messagestring = messagestring + " is running in " + \
                    "correct context."
                else:
                    self.ruledictionary[key]["rulecorrecteffectiveuserid"] = False
                    messagestring = messagestring + " is not running in " + \
                    "correct context."
                self.logdispatch.log(LogPriority.INFO, str(messagestring))
            except Exception:
                trace = traceback.format_exc()
                messagestring = "Error initializing rule: " + rulename + \
                " - " + trace
                self.ruledictionary[key]["errormessage"].append(messagestring)
                self.logdispatch.log(LogPriority.ERROR, messagestring)
                continue
        return success

    def findDictonaryItem(self, rulename):
        self.dictinaryItem = self.ruledictionary[rulename]
        if self.dictinaryItem == None:
            success = False
        else:
            success = True
        return success

    def initializeDictoniaryItem(self, rulename):
        success = True
        item = {"rulename": "",
                "rulenumber": 0,
                "ruleclassname": "",
                "ruleclasspath": "",
                "rulefilename": "",
                "ruleclassname": "",
                "rulemoduleimportstring": "",
                "ruleinstanciatecommand": "",
                "ruleobject": "",
                "ruleisapplicable": False,
                "rulecorrecteffectiveuserid": False,
                "rulefound": False,
                "unittestname": "",
                "unittestclasspath": "",
                "unittestfilename": "",
                "unittestclassname": "",
                "unittestmoduleimportstring": "",
                "unittestinstanciatecommand": "",
                "unittestobject": None,
                "unittestfound": False,
                "errormessage": []}
        self.ruledictionary[rulename] = item
        self.dictinaryItem = self.ruledictionary[rulename]
        return success
    
    def ruleReport(self):
        success = True
        messagestring = "start --------------------------------------------"
        self.logdispatch.log(LogPriority.INFO, str(messagestring))
        self.gotoFirstRule()
        messagestring = "stonixtest rule tested: --------------------------------------------------"
        self.logdispatch.log(LogPriority.INFO, str(messagestring))
        while not (self.getCurrentRuleItem() == None):
            ruleName = self.getRuleName()
            ruleNumber = self.getRuleNumber()
            ruleTestName = self.getTestName()
            ruleCorrectEffectiveUserid = self.getCorrectEffectiveUserid()    
            ruleIsApplicable = self.getIsApplicable()
            if ruleIsApplicable and ruleCorrectEffectiveUserid:
                messagestring = str(ruleName) + "(" + str(ruleNumber) + "):" + \
                str(ruleTestName) + " - isApplicable=" + \
                str(ruleIsApplicable) + " - CorrectEffectiveUserid=" + \
                str(ruleCorrectEffectiveUserid) + ";"
                self.logdispatch.log(LogPriority.INFO, str(messagestring))
            self.gotoNextRule()
        self.gotoFirstRule()
        messagestring = "stonixtest rule not tested: --------------------------------------------------"
        self.logdispatch.log(LogPriority.INFO, str(messagestring))
        while not (self.getCurrentRuleItem() == None):
            ruleName = self.getRuleName()
            ruleNumber = self.getRuleNumber()
            ruleTestName = self.getTestName()
            ruleCorrectEffectiveUserid = self.getCorrectEffectiveUserid()    
            ruleIsApplicable = self.getIsApplicable()
            if not(ruleIsApplicable) or not(ruleCorrectEffectiveUserid):
                messagestring = str(ruleName) + "(" + str(ruleNumber) + "):" + \
                str(ruleTestName) + " - isApplicable=" + \
                str(ruleIsApplicable) + " - CorrectEffectiveUserid=" + \
                str(ruleCorrectEffectiveUserid) + ";"
                self.logdispatch.log(LogPriority.INFO, str(messagestring))
            self.gotoNextRule()
        messagestring = "end --------------------------------------------"
        self.logdispatch.log(LogPriority.INFO, str(messagestring))
        return success


def assemble_suite():
    '''
    This sets up the test suite
    @author: ekkehard j. koch
    @note: Make sure it can handle entire rule scenario
    '''
# Build rule dictionary
    ruleDictionary = RuleDictionary()
# Initialize test suite
    suite = unittest.TestSuite()
# Add all the tests for rules
    suite.addTest(test_rules_and_unit_test())
# Iterate through rules
    ruleDictionary.gotoFirstRule()
    while not (ruleDictionary.getCurrentRuleItem() == None):
# Get Rule Information
        ruleName = ruleDictionary.getRuleName()
        ruleNumber = ruleDictionary.getRuleNumber()
        ruleTestName = ruleDictionary.getTestName()
        ruleCorrectEffectiveUserid = ruleDictionary.getCorrectEffectiveUserid()    
        ruleIsApplicable = ruleDictionary.getIsApplicable()
# Make Sure this rule sould be testing
        if ruleCorrectEffectiveUserid and ruleIsApplicable:
            try:
# Import the unit test
                ruleTestToRun = __import__(ruleTestName)
# Get unit test object
                ruleTestToRun = getattr(ruleTestToRun, ruleTestName)
# Add rule unit test to the test suite
                suite.addTest(unittest.makeSuite(ruleTestToRun))
            except Exception, err: 
                print "stonixtest error: " + str(ruleName) + "(" + str(ruleNumber) + ") Exception: " + str(err)
            finally:
                ruleDictionary.gotoNextRule()
        else:
            ruleDictionary.gotoNextRule()
# Build the framework dictionary
    frameworkDictionary = FrameworkDictionary()
# Iterate through framework Unit Tests
    frameworkDictionary.gotoFirstItem()
    while not (frameworkDictionary.getCurrentItem() == None):
        frameworkTestName = frameworkDictionary.getTestName()
        frameworkTestPath = frameworkDictionary.getTestPath()
        frameworkCompleteTestPath = frameworkTestPath + frameworkTestName
        try:
# Import the unit test
            fameworkTestToRun = __import__(frameworkCompleteTestPath)
# Get unit test object
            fameworkTestToRun = getattr(fameworkTestToRun, frameworkTestName)
# Add rule unit test to the test suite
            suite.addTest(unittest.makeSuite(fameworkTestToRun))
        except Exception, err: 
                print "stonixtest error: " + str(frameworkTestName) + "Exception: " + str(err) + "\n"
        frameworkDictionary.gotoNextItem()
    ruleDictionary.ruleReport()
    return suite


# Make sure this works from the command line as well as in debbug mode
if __name__ == '__main__' or __name__ == 'stonixtest':
    parser = optparse.OptionParser()
    parser.add_option("-l", "--log", action="store_true", dest="logauto",
                      default=False, help="Log failures using default log"
                      + " file name")
    parser.add_option("-n", "--namelog", action="store", dest="ttrlog",
                      help="Log failures using the specified file name",
                      metavar="LOGNAME")
    options, __ = parser.parse_args()
    if options.logauto:
        ttrlog = time.strftime('%Y%m%d-%H%M%S') + ".log"
    elif options.ttrlog:
        ttrlog = options.ttrlog
    
# Set Up test environment
    if "ttrlog" in locals():
        runner = unittest.TextTestRunner(ConsoleAndFileWriter(ttrlog))
    else:
        runner = unittest.TextTestRunner()
# Set Up test suite
    testsuite = assemble_suite()
    result = runner.run(testsuite)
# Exit code is equal to number of test failures
    exit(len(result.failures))