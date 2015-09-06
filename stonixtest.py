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
from _curses import ERR
'''
This is the test suite for stonix
@author: ekkehard j. koch, roy s. nielsen
@note: 2015-02-15 - ekkehard - original implementation
@note: 2015-05-26 - roy - changing for new test directory structure
@note: 2015-09-04 - roy - Adding method for running single, or just a few
                          tests at the command line.
@note: 2015-09-06 - roy - Added flexibility for finding tests to run, created
                          functions instead of very deep nesting.
'''
import os
import re
import src
import sys
import glob
import time
import optparse
import unittest
import traceback

from optparse import Option, OptionValueError

from src.tests.lib.logdispatcher_mock import LogPriority
from src.tests.lib.logdispatcher_mock import LogDispatcher
from src.stonix_resources.environment import Environment
from src.stonix_resources.configuration import Configuration
from src.stonix_resources.StateChgLogger import StateChgLogger

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
        self.realpath = os.path.dirname(os.path.realpath(__file__))
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
    
    def getModuleName(self):
        return self.dictinaryItem["modulename"]

    def getTestClassName(self):
        return self.dictinaryItem['moduleclassname']
    
    def getFrameworkList(self):
        return self.frameworkList
        
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
        testdirs = ["src/tests/framework/unit_tests", 
                    "src/tests/framework/network_tests",
                    "src/tests/framework/interactive_tests"]
        for mydir in testdirs:
            rulefiles = os.listdir(str(mydir))
            for rfile in rulefiles:
                rule_class = None
                if re.search(self.unittestprefix + ".*\.py$", rfile):
                    modulename = rfile.replace('.py', '')
                    if modulename.startswith(self.unittestprefix):
                        self.initializeDictoniaryItem(modulename)
                        #self.dictinaryItem["name"] = ".".join(mydir.split("/")) + "." + modulename
                        self.dictinaryItem["name"] = modulename
                        self.dictinaryItem['moduleclassname'] = ".".join(mydir.split("/")) + "." + modulename
                        #self.dictinaryItem['moduleclassname'] = ".".join(mydir.split("/")[1:]) + "." + modulename
                        self.dictinaryItem["modulename"] = modulename
                        self.dictinaryItem["path"] = self.realpath + "/" + mydir + "/" + rfile
                        self.dictinaryItem["found"] = True
                        """
                        print "\n###==-     -==###"
                        print "\tmodule:          " + str(modulename)
                        print "\tname:            " + str(self.dictinaryItem["name"])
                        print "\tmoduleclassname: " + str(self.dictinaryItem["moduleclassname"])
                        print "\tpath:            " + str(self.dictinaryItem["path"])
                        print "###==-     -==###\n"
                        """
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
    
    def __init__(self, rule=True, unit=True, network=True, interactive=True):
        self.framework = framework
        self.rule = rule
        self.unit = unit
        self.network = network
        self.interactive = interactive
        
        self.print_inputs()
        
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
        self.ruleList = []
        self.keys = None
        self.key = None
        self.keyIndexNumber = 0
        self.keysNumberOf = 0
        self.dictinaryItem = None
        self.realpath = os.path.dirname(os.path.realpath(__file__))
        self.rulesPath = self.realpath + "/src/stonix_resources/rules/"
        self.initializeRuleInfo()
        self.initializeRuleUnitTestData()
        self.initializeRuleContextData()

    def print_inputs(self):
        print "\n###==-     -==###"
        print "framework: " + str(self.framework)
        print "rule     : " + str(self.rule)
        print "unit     : " + str(self.unit)
        print "network  : " + str(self.network)
        print "interactive: " + str(self.interactive)
        print "###==-     -==###\n"

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


    def getTestClassName(self):
        return self.ruledictionary[self.key]["unittestclassname"]
    
    def getRuleList(self):
        return self.ruleList

    def getRuleFileNames(self):
        '''
        Get a list of applicable files for testing
        
        @author: Roy Nielsen
        @note: none
        '''
        applicable_tests = []
        runit = []
        rnetwork = []
        rinteractive = []
        test = ""
        
        if self.rule and self.unit:
            try:
                testpath = self.realpath + "/src/tests/rules/unit_tests"
                runit = os.listdir(testpath)
            except Exception, err:
                print "Exception: " + str(err)
                raise err
            
        if self.rule and self.network:
            try:
                testpath = self.realpath + "/src/tests/rules/network_tests"
                rnetwork = os.listdir(testpath)
            except Exception, err:
                print "Exception: " + str(err)
                raise err
            
        if self.rule and self.interactive:
            try:
                testpath = self.realpath + "/src/tests/rules/interactive_tests"
                rinteractive = os.listdir(testpath)
            except Exception, err:
                print "Exception: " + str(err)
                raise err

        for test in runit:
            if re.search("zzz.*.py$", test):
                applicable_tests.append(test)
        for test in rnetwork:
            if re.search("zzz.*.py$", test):
                applicable_tests.append(test)
        for test in rinteractive:
            if re.search("zzz.*.py$", test):
                applicable_tests.append(test)
        
        print "leaving conglomeration of tests: " + str(applicable_tests)
        return applicable_tests

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
        print "\n\t\t" + str(self.rulesPath) + "\n"
        rulefiles = os.listdir(str(self.rulesPath))
        unittestfiles = self.getRuleFileNames()
        print "rulefiles: " + str(rulefiles)
        for rfile in rulefiles:
            rule_class = None
            if rfile in self.initlist or re.search(".+pyc$", rfile):
                continue
            elif re.search(".+py$", rfile, re.IGNORECASE):
                #rulename = rfile.replace('.py', '')
                rulename = os.path.splitext(rfile)[0]
                rulefilename = rfile
                ruleclassname = 'src.stonix_resources.rules.' + rulename
                ruleclasspath = self.rulesPath + rulefilename
                parts = ruleclassname.split(".")
                rulemoduleimportstring = ruleclassname
                ruleinstanciatecommand = "rule_class = mod." + rulename
                """
                print "------------"
                print "\n\trulename: " + str(rulename)
                print "\truleclassname: " + str(ruleclassname)
                print "\truleclasspath: " + str(ruleclasspath)
                print "\trulemoduleimportstring: " + str(rulemoduleimportstring)
                print "\trulefilename: " + str(rulefilename)
                print "\trulemoduleimportstring: " + str(rulemoduleimportstring)
                print "ruleinstanciatecommand: " + str(ruleinstanciatecommand)
                print "\tpwd: " + str(os.getcwd()) 
                print "------------"
                """
                if os.path.isfile("src/tests/rules/unit_tests/" + self.unittestprefix + str(rulefilename)):
                    class_prefix = "src.tests.rules.unit_tests." 
                    self.unittestpath = "src/tests/rules/unit_tests/"
                elif os.path.isfile("src/tests/rules/network_tests/" + self.unittestprefix + str(rulefilename)):
                    class_prefix = "src.tests.rules.netowrk_tests." 
                    self.unittestpath = "src/tests/rules/network_tests/"
                elif os.path.isfile("src/tests/rules/interactive/" + self.unittestprefix + str(rulefilename)):
                    class_prefix = "tests.rules.interactive_tests." 
                    self.unittestpath = "src/tests/rules/interactive_tests/"
                else:
                    print "continuing . . ."
                    continue
                
                unittestname = self.unittestprefix + rulename
                unittestfilename = self.unittestprefix + rfile
                unittestclasspath = self.unittestpath + unittestfilename
                
                unittestclassname = class_prefix + unittestname
                unittestmoduleimportstring = unittestclassname
                unittestinstanciatecommand = "unittest_class = mod." + \
                                              unittestname
                ''' #print "------------"
                print "\n\tunittestname: " + str(unittestname)
                print "\tunittestclassname: " + str(unittestclassname)
                print "\tunittestclasspath: " + str(unittestclasspath)
                print "\tunittestmoduleimportstring: " + str(unittestmoduleimportstring)
                print "\tunittestfilename: " + str(unittestfilename)
                print "\tunittestmoduleimportstring: " + str(unittestmoduleimportstring)
                print "\tunittestinstanciatecommand: " + str(unittestinstanciatecommand)
                print "\tpwd: " + str(os.getcwd())
                print "------------" '''
                
                self.initializeDictoniaryItem(rulename)
                self.ruledictionary[rulename]["rulename"] = rulename
                self.ruledictionary[rulename]["ruleclassname"] = ruleclassname
                self.ruledictionary[rulename]["ruleclasspath"] = ruleclasspath
                self.ruledictionary[rulename]["rulefilename"] = rulefilename
                self.ruledictionary[rulename]["rulemoduleimportstring"] = rulemoduleimportstring
                self.ruledictionary[rulename]["ruleinstanciatecommand"] = ruleinstanciatecommand
                self.ruledictionary[rulename]["ruleobject"] = None
                self.ruledictionary[rulename]["ruleisapplicable"] = True
                self.ruledictionary[rulename]["rulecorrecteffectiveuserid"] = True
                self.ruledictionary[rulename]["rulefound"] = True
                
                self.ruledictionary[rulename]["unittestname"] = unittestname
                self.ruledictionary[rulename]["unittestclassname"] = unittestclassname
                self.ruledictionary[rulename]["unittestclasspath"] = unittestclasspath
                self.ruledictionary[rulename]["unittestfilename"] = unittestfilename
                self.ruledictionary[rulename]["unittestmoduleimportstring"] = unittestmoduleimportstring
                self.ruledictionary[rulename]["unittestinstanciatecommand"] = unittestinstanciatecommand
                self.ruledictionary[rulename]["unittestobject"] = None
                self.ruledictionary[rulename]["unittestfound"] = False
                self.ruledictionary[rulename]["errormessage"] = []
                '''
                print "\ntest: " + str(self.ruledictionary[rulename]) + "\n"
                
                print "\n\n\t" + os.getcwd()
                
                for key in self.ruledictionary[rulename]:
                    print "\t" + str(key) + " => " + str(self.ruledictionary[rulename][key])
                print "\n\n"
                '''
                
                try:
                    #print "------------"
                    #print "\n\trulename: " + str(rulename)
                    #print "\truleclassname: " + str(ruleclassname)
                    #####
                    # A = "dot" path to the library we want to import from
                    # B = Module inside library we want to import
                    # basically perform a "from A import B
                    mod = __import__(ruleclassname, fromlist=[rulename])
                    #print "\n\truleToTest: " + str(mod)                    
                    #print "------------"
                    #####
                    # Add the import to a list, to later "map" to a test suite
                    self.ruleList.append(mod)
                    
                except Exception:
                    trace = traceback.format_exc()
                    messagestring = "Error importing rule: " + rulename + " " + \
                                     rulemoduleimportstring + " - " + trace
                    self.ruledictionary[rulename]["errormessage"].append(messagestring)
                    self.logdispatch.log(LogPriority.ERROR, messagestring)
                    continue
                
                
                try:
                    exec(ruleinstanciatecommand)
                    #rule_class = getattr(mod, rulemoduleimportstring)
                    #exec("rule_class = mod." + ruleclassname)
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
                mod = __import__(ruleclassname, fromlist=[rulename])
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

def isCorrectEffectiveUserId(checkRootRequired=9999999):
    """
    Check to see if the user is the one expected to run the test
    
    @author: Roy Nielsen
    """
    success = False
    currentId = os.geteuid()
    if currentId and not checkRootRequired:
        # Matching user mode
        success = True
    elif not currentId and checkRootRequired:
        # Matching root mode
        success = True
        
    return success

def isRuleInBounds(fname=""):
    """
    Loads the rule passed in and checks if it "is applicable" and running
    in the correct user context.
    
    @param: Filename of the rule to check
    @returns: True = rule is in bounds, False = out of bounds
    
    @author: Roy Nielsen
    """
    ruleIsInBounds = False
    
    #print "\n\n\tFile: " + str(root + "/" + fname)
    toTestFileName = fname.split("/")[-1]
    # get the name of the test without the ".py"
    toTestName = ".".join(toTestFileName.split(".")[:-1])
    # Create a class path with the testName
    toTestClassName = ".".join(fname.split("/")[:-1]) + "." + toTestName
    
    #print "\n\tTestFileName  : " + str(toTestFileName)
    #print "  \tTestName      : " + str(toTestName)
    #print "  \tTestClassName : " + str(toTestClassName) + "\n"

    # Make Sure this rule sould be testing
    try:
        #####
        # A = "dot" path to the library we want to import from
        # B = Module inside library we want to import
        # basically perform a "from A import B
        toTestToRunMod = __import__(toTestClassName, fromlist=[toTestName])
        
    except Exception, err: 
        print "stonixtest error: " + str(toTestName) + " Exception: " + str(err)
    else:
    
        # Define a class/function or set of classes/functions to instantiate, 
        # must be in a list/array
        mod2import = [toTestName]
        
        # Import specific class - the "top level" module ie:
        #   the imported file is now the "top level" module
        tmp_test_mod = __import__(toTestClassName, None, None, mod2import)
        
        # set a variable to the module class
        tmpex = "toTestClass = tmp_test_mod." + str(toTestName)
        
        exec(tmpex)
        
        environ = Environment()
        config = Configuration(environ)
        logdispatcher = LogDispatcher(environ)
        stchgr = StateChgLogger(logdispatcher, environ)
        
        get_attrs = toTestClass(config, environ, logdispatcher, stchgr)
        
        # Acquire result of method            
        is_root_required = get_attrs.getisrootrequired()
        
        # Does the running user match if root is required?
        toTestCorrectEffectiveUserid = isCorrectEffectiveUserId(is_root_required)

        # check if is applicable to this system
        toTestIsApplicable = get_attrs.isapplicable()

        #print "IsApplicable: " + str(toTestIsApplicable)
        #print "UID works   : " + str(toTestCorrectEffectiveUserid)

        # Make Sure this rule sould be testing
        if toTestCorrectEffectiveUserid and toTestIsApplicable:
            ruleIsInBounds = True
        
    return ruleIsInBounds


def processRuleTest(filename=""):
    """
    Processing a rule to make sure it is applicable to the system and make
    sure it is running in the right user context.
    
    @param: a filename to match test with rule for validation and loading
    @return: a loaded module
    
    @author: Roy Nielsen
    """
    #print "\n\n\tFile: " + str(filename)
    found = True
    returnMod = None
    classToTest = None
    
    # Get the filename of the test, without the path
    testFileName = filename.split("/")[-1]
    # get the name of the test without the ".py"
    testName = ".".join(testFileName.split(".")[:-1])
    # Create a class path with the testName
    testClassName = ".".join(filename.split("/")[:-1]) + "." + testName
    
    #print "\n\tTestFileName  : " + str(testFileName)
    #print "  \tTestName      : " + str(testName)
    #print "  \tTestClassName : " + str(testClassName) + "\n"

    # Make Sure this rule sould be testing
    try:
        #####
        # A = "dot" path to the library we want to import from
        # B = Module inside library we want to import
        # basically perform a "from A import B
        testToRunMod = __import__(testClassName, fromlist=[testName])
        
    except Exception, err: 
        print "stonixtest error: " + str(testName) + " Exception: " + str(err)
    else:
        # check if we're running in the correct context - get the 
        # name associated with the test
        try:
            classToTestRegex = re.match("^zzzTestRule(.+)$", testName)
        except Exception, err:
           print "Exception trying to match regex . . ."
           print str(err)
           raise err                        
        else:
            try:
                classToTest = classToTestRegex.group(1) + ".py"
            except:
                classToTest = None
    
    #print "ClassToTest: " + str(classToTest)
    #print "----------=====##        ##=====----------"
    
    if classToTest:
        # load the rule to make sure it is running in the right
        # context and it is applicable to the platform
        for root, dirnames, filenames in os.walk("src/stonix_resources"):
            myfile = ""
            for myfile in filenames:
                #print "\n\n\tFile: " + str(myfile)
                if re.match("^%s$"%classToTest, myfile):
                    
                    if isRuleInBounds(root + "/" + classToTest):
                        returnMod = testToRunMod
                    else:
                        returnMod = None
                        
    return returnMod

def processFrameworkTest(filename=""):
    """
    Attempting to import the test, will return the loaded module, or None
    if the module couldn't be loaded.
    
    @param: a filename to load
    @return: a loaded module, or None if the module couldn't be loaded
    
    @author: Roy Nielsen
    """
    modToReturn = None

    if filename:
            
        #print "\n\n\tFile: " + str(root + "/" + myfile)
        relpath = str(filename)
        # get the name of the test without the ".py"
        testName = filename.split("/")[-1].split(".py")[0]
        # Create a class path with the testName
        testClassName = ".".join(relpath.split("/")[:-1]) + "." + testName
        
        #print "\n\tTestFileName  : " + str(myfile)
        #print "  \tTestName      : " + str(testName)
        #print "  \tTestClassName : " + str(testClassName) + "\n"

        # Make Sure this rule sould be testing
        try:
            #####
            # A = "dot" path to the library we want to import from
            # B = Module inside library we want to import
            # basically perform a "from A import B
            modToReturn = __import__(testClassName, fromlist=[testName])
            
        except Exception, err: 
            print "stonixtest error: " + str(testName) + " Exception: " + str(err)
            modToReturn = None
            
    return modToReturn
    
         
def assemble_list_suite(modules = []):
    """
    Only process the list of passed in tests...
    
    Will only run <Rulename>, not the test name zzzTestRule<Rulename>.
    
    @param: modules - a list of modules to test.
    
    @author: Roy Nielsen
    """
    testList = []

    #print str(modules)
    
    # - if modules list is passed in
    if modules and isinstance(modules, list) :
        
        suite = None
        
        # loop through list
        for module in modules :
            #print "\n\n\tModule: " + str(module)
            # import the test
            
            # determine if it is a framework or rule test
            if re.search("amework", module):
                prefix = "framework"
            elif re.search("ule", module):
                prefix = "rules"
            else:
                prefix = ""
                
            if re.match("^rules$", prefix):
                #Find the path to the test
                for root, dirnames, filenames in os.walk("src/tests/" + prefix):
                    myfile = ""
                    for myfile in filenames:
                        regex = "^" + str(module) + ".*"
                        if re.match(regex, myfile):
                            testToRunMod = processRuleTest(root + "/" + myfile)
                            #print "******************************************"
                            #print "Checking out " + str(module)
                            # Make Sure this rule sould be running
                            if testToRunMod:
                                #####
                                # Add the import to a list, to later "map" to a test suite
                                testList.append(testToRunMod)
                                #print "Adding test to suite..."   
                            #print " *****************************************"
            elif re.match("^framework$", prefix):
                #Find the path to the test
                for root, dirnames, filenames in os.walk("src/tests/" + prefix):
                    myfile = ""
                    for myfile in filenames:
                        #print "\n\n\tmodname: " + str(module)
                        #print "\tFile   : " + str(myfile)
                        #print "\tRelPath: " + str(root + "/" + myfile)
                        regex = "^" + str(module) + ".*"
                        if re.match(regex, myfile):
                            #print "******************************************"
                            #print "Checking out " + str(myfile)
                            testToRunMod = processFrameworkTest(root + "/" + myfile)
                            
                            if testToRunMod:
                                #####
                                # Add the import to a list, to later "map" to a test suite
                                testList.append(testToRunMod)     
                                #print "Adding test to suite..."   
                            #print " *****************************************"
            
            else:
                raise "Error attempting insert test into test list..."
            
    #####
    # Set up the test loader function
    load = unittest.defaultTestLoader.loadTestsFromModule

    #####
    # Define a test suite based on the testList.
    suite = unittest.TestSuite(map(load, testList))

    return suite
    
    
def assemble_suite(framework=True, rule=True, unit=True, network=True, interactive=False):
    '''
    This sets up the test suite
    @author: ekkehard j. koch
    @note: Make sure it can handle entire rule scenario
    '''
    testList = []
    
    if rule:
    
        # Build the full rule dictionary
        ruleDictionary = RuleDictionary(rule, unit, network, interactive)
    
        # Iterate through rules
        ruleDictionary.gotoFirstRule()
    
        #print "\n\n\n\n\n\t\tTrying to import rule tests\n\n"
        while not (ruleDictionary.getCurrentRuleItem() == None):
            # Get Rule Information
            ruleName = ruleDictionary.getRuleName()
            ruleTestClassName = ruleDictionary.getTestClassName()
            ruleNumber = ruleDictionary.getRuleNumber()
            ruleTestName = ruleDictionary.getTestName()
            ruleCorrectEffectiveUserid = ruleDictionary.getCorrectEffectiveUserid()    
            ruleIsApplicable = ruleDictionary.getIsApplicable()
            
            # Make Sure this rule sould be testing
            if ruleCorrectEffectiveUserid and ruleIsApplicable:
                try:
                    #####
                    # A = "dot" path to the library we want to import from
                    # B = Module inside library we want to import
                    # basically perform a "from A import B
                    ruleTestToRun = __import__(ruleTestClassName, fromlist=[ruleTestName])
                    
                    #####
                    # Add the import to a list, to later "map" to a test suite
                    testList.append(ruleTestToRun)
                
                except Exception, err: 
                    print "stonixtest error: " + str(ruleName) + "(" + str(ruleNumber) + ") Exception: " + str(err)
                finally:
                    ruleDictionary.gotoNextRule()
            else:
                ruleDictionary.gotoNextRule()
    
        #print "\n\t\t Imported rule tests\n\n\n\n\n"
    else:
        print "\n Not running rule tests\n"


    if framework:

        # Build the framework dictionary
        frameworkDictionary = FrameworkDictionary()
        
        # Iterate through framework Unit Tests
        frameworkDictionary.gotoFirstItem()
        frameworkList = []
        modules = []
        while not (frameworkDictionary.getCurrentItem() == None):
            frameworkTestName = frameworkDictionary.getTestName()
            frameworkTestPath = frameworkDictionary.getTestPath()
            frameworkTestClassName = frameworkDictionary.getTestClassName()
            frameworkTestModuleName = frameworkDictionary.getModuleName()
            #frameworkCompleteTestPath = frameworkTestPath + frameworkTestName
            frameworkCompleteTestPath = frameworkTestPath
            frameworkCompleteTestName = frameworkTestName + "." + frameworkTestModuleName
            """
            print "----------------------------"
            print "\tFTN:  " + str(frameworkTestName)
            print "\tFTCN: " + str(frameworkTestClassName)
            print "\tFTP:  " + str(frameworkTestPath)
            print "\tFCTP: " + str(frameworkCompleteTestPath) 
            print "\tFTCN: " + str(frameworkCompleteTestName)
            print "----------------------------"
            """
            
            try:
                #####
                # A = "dot" path to the library we want to import from
                # B = Module inside library we want to import
                # basically perform a "from A import B
                fameworkTestToRun = __import__(frameworkTestClassName, fromlist=[frameworkTestName])
                
                #####
                # Add the import to a list, to later "map" to a test suite
                testList.append(fameworkTestToRun)
                
            except Exception, err: 
                    print "stonixtest error: " + str(frameworkTestClassName) + " Exception: " + str(err) + "\n"
                    #raise(err)
            frameworkDictionary.gotoNextItem()
    else:
        print "\n Not running framework tests.\n"
    
    #####
    # Set up the test loader function
    load = unittest.defaultTestLoader.loadTestsFromModule

    #####
    # Define a test suite based on the testList.
    suite = unittest.TestSuite(map(load, testList))

    # Add all the tests for rules
    suite.addTests(unittest.makeSuite(test_rules_and_unit_test))

    if rule:
        ruleDictionary.ruleReport()
    return suite

# Get all of the possible options passed in to OptionParser that are passed
# in with the -m or --modules flag
class ModulesOption(Option):

    ACTIONS = Option.ACTIONS + ("extend",)
    STORE_ACTIONS = Option.STORE_ACTIONS + ("extend",)
    TYPED_ACTIONS = Option.TYPED_ACTIONS + ("extend",)
    ALWAYS_TYPED_ACTIONS = Option.ALWAYS_TYPED_ACTIONS + ("extend",)

    def take_action(self, action, dest, opt, value, values, parser):
        if action == "extend":
            lvalue = value.split(",")
            values.ensure_value(dest, []).extend(lvalue)
        else:
            Option.take_action(
                self, action, dest, opt, value, values, parser)
            
            
# Make sure this works from the command line as well as in debbug mode
if __name__ == '__main__' or __name__ == 'stonixtest':
    """
    Main program
    
    """
    VERSION="0.8.20"
    description = "Test framework for Stonix."
    parser = optparse.OptionParser(option_class=ModulesOption,
                          usage='usage: %prog [OPTIONS]',
                          version='%s' % (VERSION),
                          description=description)
    
    parser.add_option("-l", "--log", action="store_true", dest="logauto",
                      default=False, help="Log failures using default log"
                      + " file name")

    parser.add_option("-n", "--namelog", action="store", dest="ttrlog",
                      help="Log failures using the specified file name",
                      metavar="LOGNAME")

    parser.add_option("-r", "--rule", action="store_true", dest="rule",
                      default=False, help="Run the Rule tests.  Will not" + \
                                          " work when combined with -f.")

    parser.add_option("--network", action="store_true", dest="network",
                      default=False, help="Run the network category of tests")

    parser.add_option("--unit", action="store_true", dest="unit",
                      default=False, help="Run the unit test category of tests")

    parser.add_option("-i", "--interactive", action="store_true", dest="interactive",
                      default=False, help="Log failures using default log")

    parser.add_option("-f", "--framework", action="store_true", dest="framework",
                      default=False, help="Run the Framework tests.  Will not" + \
                                          " work when combined with -r.")

    parser.add_option("-a", "--all-automatable", action="store_true", dest="all",
                      default=True, help="Run all unit and network tests - " + \
                      "interactive tests not included")

    parser.add_option("--rule-test-consistency", action="store_true", dest="consistency",
                      default=False, help="Check to make sure there is a " + \
                      "test for every rule and a rule for every rule test")

    parser.add_option('-m', '--modules', action="extend", type="string", 
                      dest='modules', help="Use to run a single or " + \
                      "multiple unit tests at once.  Use the test name.")
   
    if len(sys.argv) == 1:
        parser.parse_args(['--help'])
    
    options, __ = parser.parse_args()
    
    if options.logauto:
        ttrlog = time.strftime('%Y%m%d-%H%M%S') + ".log"
    elif options.ttrlog:
        ttrlog = options.ttrlog

    network=options.network
                
    unit = options.unit
    
    interactive = options.interactive

    if options.rule:
        rule=options.rule
        framework = False
    else:
        rule=None
    
    if options.framework:
        framework = options.framework
        rule = False
    else:
        framework = None

    if not options.framework and not options.rule:
        rule = True
        framework = True

    if options.framework and options.rule:
        print "Sorry, -f and -r are mutually exclusive."
        sys.exit(255)

    if not rule and not framework and not all:
        print "Need to choose rule or framework or all. . ."

    if options.all:
        unit=True
        network=True
        framework=True
        rule=True
        consistency = True

    modules = options.modules

    consistency = options.consistency

    # Set Up test environment
    if "ttrlog" in locals():
        runner = unittest.TextTestRunner(ConsoleAndFileWriter(ttrlog))
    else:
        runner = unittest.TextTestRunner()

    # Set Up test suite
    if modules:
        # only process tests passed in via the -m flag
        testsuite = assemble_list_suite(modules)
    elif consistency:
        #####
        # Define a test suite based on the testList.
        testsuite = unittest.TestSuite()
        
        test2run = test_rules_and_unit_test()
        # Add all the tests for rules
        testsuite.addTest(test2run)

    else:

        testsuite = assemble_suite(framework, rule, unit, network, interactive)
    
    # Run the test suite
    result = runner.run(testsuite)

    # Exit code is equal to number of test failures
    exit(len(result.failures))

