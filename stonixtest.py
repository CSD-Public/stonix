#!/usr/bin/python
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
This is the test suite for stonix
@author: ekkehard j. koch, roy s. nielsen, Eric Ball
@change: 2015/02/15 ekkehard - original implementation
@change: 2015/05/26 roy - changing for new test directory structure
@change: 2015/09/04 roy - Adding method for running single, or just a few
                          tests at the command line.
@change: 2015/09/06 roy - Added flexibility for finding tests to run, created
                          functions instead of very deep nesting.
@change: 2015/10/03 roy - Adding "utils" category of tests, for testing
                          functions (stonixutils) rather than classes or class
                          methods. Also cutting down logdispatcher chatter
@change: 2016/11/08 eball PEP8 cleanup, added default UT path
@change: 2016/12/19 eball Refactored large portions of stonixtest
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

from src.tests.lib.logdispatcher_lite import LogDispatcher, LogPriority
from src.stonix_resources.environment import Environment
from src.stonix_resources.configuration import Configuration
from src.stonix_resources.StateChgLogger import StateChgLogger


class ConsoleAndFileWriter():
    '''This class provides an object that can be passed to
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


def name_test_template(moduletestfound, reportstring):
    '''The name_test_template provides a method that can be used, via monkey
    patching, to add test cases to the test_ruleNtestConsistency class
    dynamically from within the ConsistencyCheck class.
    @author: Roy Nielsen, Eric Ball

    :param moduletestfound: boolean indicating if a test was found for a given
        module
    :param reportstring: string to print if the test assertion fails

    '''
    def checkConsistency(self):
        self.assert_value(moduletestfound, reportstring)
    return checkConsistency


class test_ruleNtestConsistency(unittest.TestCase):

    def setUp(self):
        self.environ = Environment()
        self.logdispatcher = LogDispatcher(self.environ)

    def assert_value(self, moduletestfound, reportstring):
        self.assertTrue(moduletestfound, reportstring)


class ConsistencyCheck():
    '''This class is designed to make sure there is a unit test
    for every rule and a rule for every unit test
    @author: ekkehard j. koch
    @note: Make sure it can handle entire rule testing suite
    @change: 2015-02-25 - ekkehard - Original Implementation


    '''

    def __init__(self):
        self.ruleDictionary = RuleDictionary()
        self.tests4rules = []
        self.rules4tests = []
        self.tests = {}

        self.zzz_for_every_rule()
        self.rule_for_every_zzz()

        self.tests["tests4rules"] = self.tests4rules
        self.tests["rules4tests"] = self.rules4tests

        self.test_ruleNtestConsistency = test_ruleNtestConsistency

        self.set_up_tests()

    def set_up_tests(self):
        '''Run tests based on the data structure that has the test data'''
        for behavior, test_cases in list(self.tests.items()):
            for test_case_data in test_cases:
                moduletestfound, name, _ = test_case_data
                my_test_name = "test_{0}_{1}_{2}".format(str(behavior),
                                                         str(name),
                                                         str(moduletestfound))
                my_test_case = name_test_template(test_case_data[0],
                                                  test_case_data[2])
                setattr(self.test_ruleNtestConsistency, my_test_name,
                        my_test_case)

    def getTest(self):
        return self.test_ruleNtestConsistency

    def zzz_for_every_rule(self):
        self.ruleDictionary.gotoFirstRule()
        while not (self.ruleDictionary.getCurrentRuleItem() is None):
            moduletestfound = self.ruleDictionary.getHasUnitTest()
            name = self.ruleDictionary.getRuleName()
            messagestring = "No unit test available for rule " + str(name)
            data_set = (moduletestfound, name, messagestring)
            self.tests4rules.append(data_set)
            self.ruleDictionary.gotoNextRule()

    def rule_for_every_zzz(self):
        self.ruleDictionary.gotoFirstRule()
        while not (self.ruleDictionary.getCurrentRuleItem() is None):
            moduletestfound = self.ruleDictionary.getHasRule()
            name = self.ruleDictionary.getTestName()
            messagestring = "No rule available for unit test " + str(name)
            data_set = (moduletestfound, name, messagestring)
            self.rules4tests.append(data_set)
            self.ruleDictionary.gotoNextRule()


class FrameworkDictionary():

    def __init__(self, modules=[]):
        self.unittestprefix = 'zzzTestFramework'
        self.initlist = ['__init__.py', '__init__.pyc', '__init__.pyo']
        # logger & environ - a global variable that has applicable verbose and
        # debug values
        global Environ
        self.environ = ENVIRON
        self.effectiveUserID = self.environ.geteuid()
        global SYSCONFIG
        self.config = SYSCONFIG
        global LOGGER
        self.logdispatch = LOGGER
        global STATECHANGELOGGER
        self.statechglogger = STATECHANGELOGGER
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
        self.initializeDictionary(modules)

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
        return self.frameworkdictionary

    def initializeDictionary(self, modules):
        '''Fill in all the rule information
        @author: ekkehard j. koch
        @note: None

        :param modules: 

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
                if (modules and rfile[:-3] in modules) or (not modules and
                   re.search(self.unittestprefix + ".*\.py$", rfile)):
                    modulename = rfile.replace('.py', '')
                    if modulename.startswith(self.unittestprefix):
                        self.initializeDictoniaryItem(modulename)
                        self.dictinaryItem["name"] = modulename
                        self.dictinaryItem['moduleclassname'] = \
                            ".".join(mydir.split("/")) + "." + modulename
                        self.dictinaryItem["modulename"] = modulename
                        self.dictinaryItem["path"] = self.realpath + "/" + \
                            mydir + "/" + rfile
                        self.dictinaryItem["found"] = True

                        self.logdispatch.log(LogPriority.DEBUG, "\n###==-   " +
                                                                "  -==###")
                        self.logdispatch.log(LogPriority.DEBUG, "\tmodule: " +
                                             "         " + str(modulename))
                        self.logdispatch.log(LogPriority.DEBUG, "\tname:   " +
                                             "         " +
                                             str(self.dictinaryItem["name"]))
                        self.logdispatch.log(LogPriority.DEBUG,
                                             "\tmoduleclassname: " +
                                             str(self.dictinaryItem["moduleclassname"]))
                        self.logdispatch.log(LogPriority.DEBUG,
                                             "\tpath:            " +
                                             str(self.dictinaryItem["path"]))
                        self.logdispatch.log(LogPriority.DEBUG,
                                             "###==-     -==###\n")
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


class UtilsDictionary():

    def __init__(self, modules=[]):
        self.unittestprefix = 'zzzTestUtils'
        self.initlist = ['__init__.py', '__init__.pyc', '__init__.pyo']
        # logger & environ - a global variable that has applicable verbose and
        # debug values
        self.environ = Environment()
        self.effectiveUserID = self.environ.geteuid()
        self.environ.setdebugmode(debug_mode)
        self.environ.setverbosemode(verbose_mode)
        self.config = Configuration(self.environ)
        self.logdispatch = LogDispatcher(self.environ)
        self.statechglogger = StateChgLogger(self.logdispatch, self.environ)
        self.scriptPath = self.environ.get_script_path()
        self.stonixPath = self.environ.get_resources_path()
        self.realpath = os.path.dirname(os.path.realpath(__file__))
        self.rulesPath = self.environ.get_rules_path()
        self.frameworkpath = self.stonixPath + "/"
        self.utilsDictionary = {}
        self.keys = None
        self.key = None
        self.keyIndexNumber = 0
        self.keysNumberOf = 0
        self.dictinaryItem = None
        self.initializeDictionary(modules)

    def gotoFirstItem(self):
        self.keyIndexNumber = 0
        self.keys = sorted(self.utilsDictionary.keys())
        self.keysNumberOf = len(self.keys)
        self.key = self.keys[self.keyIndexNumber]
        self.dictinaryItem = self.utilsDictionary[self.key]

    def gotoNextItem(self):
        self.keyIndexNumber = self.keyIndexNumber + 1
        self.keys = sorted(self.utilsDictionary.keys())
        self.keysNumberOf = len(self.keys)
        if (self.keysNumberOf - 1) < self.keyIndexNumber:
            self.keyIndexNumber = 0
            self.dictinaryItem = None
        else:
            self.key = self.keys[self.keyIndexNumber]
            self.dictinaryItem = self.utilsDictionary[self.key]

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
        return self.utilsDictionary

    def initializeDictionary(self, modules):
        '''Fill in all the rule information
        @author: ekkehard j. koch
        @note: None

        :param modules: 

        '''
        success = True
        messagestring = "--------------------------------- start"
        self.logdispatch.log(LogPriority.INFO, str(messagestring))
        self.validrulefiles = []
        self.modulenames = []
        self.classnames = []
        testdirs = ["src/tests/utils/unit_tests",
                    "src/tests/utils/network_tests",
                    "src/tests/utils/interactive_tests"]
        for mydir in testdirs:
            rulefiles = os.listdir(str(mydir))
            for rfile in rulefiles:
                if (modules and rfile[:-3] in modules) or (not modules and
                   re.search(self.unittestprefix + ".*\.py$", rfile)):
                    modulename = rfile.replace('.py', '')
                    if modulename.startswith(self.unittestprefix):
                        self.initializeDictoniaryItem(modulename)
                        self.dictinaryItem["name"] = modulename
                        self.dictinaryItem['moduleclassname'] = \
                            ".".join(mydir.split("/")) + "." + modulename
                        self.dictinaryItem["modulename"] = modulename
                        self.dictinaryItem["path"] = self.realpath + "/" + \
                            mydir + "/" + rfile
                        self.dictinaryItem["found"] = True

                        LOGGER.log(LogPriority.DEBUG, "\n###==-     -==###")
                        LOGGER.log(LogPriority.DEBUG,
                                   "\tmodule:          " + str(modulename))
                        LOGGER.log(LogPriority.DEBUG, "\tname:            " +
                                   str(self.dictinaryItem["name"]))
                        LOGGER.log(LogPriority.DEBUG, "\tmoduleclassname: " +
                                   str(self.dictinaryItem["moduleclassname"]))
                        LOGGER.log(LogPriority.DEBUG, "\tpath:            " +
                                   str(self.dictinaryItem["path"]))
                        LOGGER.log(LogPriority.DEBUG, "###==-     -==###\n")

                else:
                    continue
        return success

    def initializeDictoniaryItem(self, name):
        success = True
        item = {"name": "",
                "path": self.frameworkpath,
                "found": False,
                "errormessage": []}
        self.utilsDictionary[name] = item
        self.dictinaryItem = self.utilsDictionary[name]
        return success


class RuleDictionary ():
    '''This class is designed encapsulate the dictionary object for
    rules.
    @author: ekkehard j. koch
    @note: None
    @change: 2015-02-25 - ekkehard - Original Implementation


    '''
    def __init__(self, unit=True, network=True, interactive=True, modules=[]):
        self.unit = unit
        self.network = network
        self.interactive = interactive

        self.print_inputs()

        self.unittestprefix = 'zzzTestRule'
        self.initlist = ['__init__.py', '__init__.pyc', '__init__.pyo']
        global ENVIRON
        self.environ = ENVIRON
        self.effectiveUserID = self.environ.geteuid()
        global SYSCONFIG
        self.config = SYSCONFIG
        global LOGGER
        self.logdispatch = LOGGER
        global STATECHANGELOGGER
        self.statechglogger = STATECHANGELOGGER
        self.scriptPath = self.environ.get_script_path()
        self.stonixPath = self.environ.get_resources_path()
        self.rulesPath = self.environ.get_rules_path()
        self.unittestpath = self.scriptPath + "/"
        self.unittestpaths = []
        self.ruledictionary = {}
        self.ruleList = []
        self.keys = None
        self.key = None
        self.keyIndexNumber = 0
        self.keysNumberOf = 0
        self.dictinaryItem = None
        self.realpath = os.path.dirname(os.path.realpath(__file__))
        self.rulesPath = self.realpath + "/src/stonix_resources/rules/"
        self.initializeRuleInfo(modules)
        self.initializeRuleContextData()

    def print_inputs(self):
        print("\n###==-     -==###")
        print("unit     : " + str(self.unit))
        print("network  : " + str(self.network))
        print("interactive: " + str(self.interactive))
        print("###==-     -==###\n")

    def gotoFirstRule(self):
        self.keyIndexNumber = 0
        self.keys = sorted(list(self.ruledictionary.keys()), reverse=True)
        self.keysNumberOf = len(self.keys)
        self.key = self.keys[self.keyIndexNumber]
        self.dictinaryItem = self.ruledictionary[self.key]

    def gotoNextRule(self):
        self.keyIndexNumber = self.keyIndexNumber + 1
        self.keys = sorted(list(self.ruledictionary.keys()), reverse=True)
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
        '''Get a list of applicable files for testing
        
        @author: Roy Nielsen
        @note: none


        '''
        applicable_tests = []
        runit = []
        rnetwork = []
        rinteractive = []

        if self.unit:
            try:
                testpath = self.realpath + "/src/tests/rules/unit_tests"
                runit = os.listdir(testpath)
            except Exception as err:
                self.logdispatch.log(LogPriority.ERROR,
                                     "Exception: " + str(err))

        if self.network:
            try:
                testpath = self.realpath + "/src/tests/rules/network_tests"
                rnetwork = os.listdir(testpath)
            except Exception as err:
                self.logdispatch.log(LogPriority.ERROR,
                                     "Exception: " + str(err))

        if self.interactive:
            try:
                testpath = self.realpath + "/src/tests/rules/interactive_tests"
                rinteractive = os.listdir(testpath)
            except Exception as err:
                self.logdispatch.log(LogPriority.ERROR,
                                     "Exception: " + str(err))

        allTests = runit + rnetwork + rinteractive
        for test in allTests:
            if re.search("zzz.*.py$", test):
                applicable_tests.append(test)

        self.logdispatch.log(LogPriority.DEBUG,
                             "RuleDictionary.getRuleFileNames " +
                             "returning tests: " + str(applicable_tests))
        return applicable_tests

    def initializeRuleInfo(self, modules):
        '''Fill in all the rule information
        @author: ekkehard j. koch
        @note: None

        :param modules: 

        '''
        success = True
        messagestring = "--------------------------------- start"
        self.logdispatch.log(LogPriority.INFO, str(messagestring))
        self.validrulefiles = []
        self.modulenames = []
        self.classnames = []
        self.logdispatch.log(LogPriority.DEBUG,
                             "\n\t\t" + str(self.rulesPath) + "\n")
        rulefiles = os.listdir(str(self.rulesPath))
        if modules:
            modRules = {}
            rfilesTemp = []
            for mod in modules:
                if re.search("zzzTestRule", mod):
                    try:
                        modRules[mod] = mod[11:]
                    except IndexError:
                        self.logdispatch.log(LogPriority.ERROR,
                                             "IndexError during rule init")
                        continue
                    rfilename = modRules[mod] + ".py"
                    if rfilename in rulefiles:
                        rfilesTemp.append(rfilename)
                    else:
                        self.logdispatch.log(LogPriority.WARNING, rfilename +
                                             " not found in rule files")
            rulefiles = rfilesTemp
        self.logdispatch.log(LogPriority.DEBUG, "rulefiles: " + str(rulefiles))
        for rfile in rulefiles:
            rule_class = None
            if rfile in self.initlist or re.search(".+pyc$", rfile):
                continue
            elif re.search(".+py$", rfile, re.IGNORECASE):
                rulename = os.path.splitext(rfile)[0]
                rulefilename = rfile
                ruleclassname = 'src.stonix_resources.rules.' + rulename
                ruleclasspath = self.rulesPath + rulefilename
                rulemoduleimportstring = ruleclassname

                LOGGER.log(LogPriority.DEBUG, "------------")
                LOGGER.log(LogPriority.DEBUG, "\n\trulename: " +
                                              str(rulename))
                LOGGER.log(LogPriority.DEBUG, "\truleclassname: " +
                                              str(ruleclassname))
                LOGGER.log(LogPriority.DEBUG, "\truleclasspath: " +
                                              str(ruleclasspath))
                LOGGER.log(LogPriority.DEBUG, "\trulemoduleimportstring: " +
                                              str(rulemoduleimportstring))
                LOGGER.log(LogPriority.DEBUG, "\trulefilename: " +
                                              str(rulefilename))
                LOGGER.log(LogPriority.DEBUG, "\trulemoduleimportstring: " +
                                              str(rulemoduleimportstring))
                LOGGER.log(LogPriority.DEBUG, "\tpwd: " + str(os.getcwd()))
                LOGGER.log(LogPriority.DEBUG, "------------")

                self.initializeDictoniaryItem(rulename)
                self.ruledictionary[rulename]["rulename"] = rulename
                self.ruledictionary[rulename]["ruleclassname"] = ruleclassname
                self.ruledictionary[rulename]["ruleclasspath"] = ruleclasspath
                self.ruledictionary[rulename]["rulefilename"] = rulefilename
                self.ruledictionary[rulename]["rulemoduleimportstring"] = \
                    rulemoduleimportstring
                self.ruledictionary[rulename]["ruleobject"] = None
                self.ruledictionary[rulename]["ruleisapplicable"] = True
                self.ruledictionary[rulename]["rulecorrecteffectiveuserid"] = \
                    True
                self.ruledictionary[rulename]["rulefound"] = True

                if os.path.isfile("src/tests/rules/unit_tests/" +
                                  self.unittestprefix + str(rulefilename)):
                    class_prefix = "src.tests.rules.unit_tests."
                    self.unittestpath = "src/tests/rules/unit_tests/"
                elif os.path.isfile("src/tests/rules/network_tests/" +
                                    self.unittestprefix + str(rulefilename)):
                    class_prefix = "src.tests.rules.network_tests."
                    self.unittestpath = "src/tests/rules/network_tests/"
                elif os.path.isfile("src/tests/rules/interactive/" +
                                    self.unittestprefix + str(rulefilename)):
                    class_prefix = "tests.rules.interactive_tests."
                    self.unittestpath = "src/tests/rules/interactive_tests/"
                else:
                    class_prefix = "src.tests.rules.unit_tests."
                    self.unittestpath = "src/tests/rules/unit_tests/"

                if self.unittestpath not in self.unittestpaths:
                    self.unittestpaths.append(self.unittestpath)

                unittestname = self.unittestprefix + rulename
                unittestfilename = self.unittestprefix + rfile
                unittestclasspath = self.unittestpath + unittestfilename
                if os.path.exists(unittestclasspath):
                    self.ruledictionary[rulename]["unittestfound"] = True
                else:
                    self.ruledictionary[rulename]["unittestfound"] = False

                unittestclassname = class_prefix + unittestname
                unittestmoduleimportstring = unittestclassname
                unittestinstanciatecommand = "unittest_class = mod." + \
                                             unittestname
                LOGGER.log(LogPriority.DEBUG, "------------")
                LOGGER.log(LogPriority.DEBUG,
                           "\n\tunittestname: " + str(unittestname))
                LOGGER.log(LogPriority.DEBUG,
                           "\tunittestclassname: " + str(unittestclassname))
                LOGGER.log(LogPriority.DEBUG,
                           "\tunittestclasspath: " + str(unittestclasspath))
                LOGGER.log(LogPriority.DEBUG,
                           "\tunittestmoduleimportstring: " +
                           str(unittestmoduleimportstring))
                LOGGER.log(LogPriority.DEBUG,
                           "\tunittestfilename: " + str(unittestfilename))
                LOGGER.log(LogPriority.DEBUG,
                           "\tunittestmoduleimportstring: " +
                           str(unittestmoduleimportstring))
                LOGGER.log(LogPriority.DEBUG, "\tpwd: " + str(os.getcwd()))
                LOGGER.log(LogPriority.DEBUG, "------------")

                self.ruledictionary[rulename]["unittestname"] = unittestname
                self.ruledictionary[rulename]["unittestclassname"] = \
                    unittestclassname
                self.ruledictionary[rulename]["unittestclasspath"] = \
                    unittestclasspath
                self.ruledictionary[rulename]["unittestfilename"] = \
                    unittestfilename
                self.ruledictionary[rulename]["unittestmoduleimportstring"] = \
                    unittestmoduleimportstring
                self.ruledictionary[rulename]["unittestinstanciatecommand"] = \
                    unittestinstanciatecommand
                self.ruledictionary[rulename]["unittestobject"] = None
                self.ruledictionary[rulename]["errormessage"] = []

                try:
                    # "from ruleclassname import rulename"
                    mod = __import__(ruleclassname, fromlist=[rulename])
                    self.ruleList.append(mod)
                except Exception:
                    trace = traceback.format_exc()
                    messagestring = "Error importing rule: " + rulename + " " + \
                                    rulemoduleimportstring + " - " + trace
                    self.ruledictionary[rulename]["errormessage"].append(messagestring)
                    self.logdispatch.log(LogPriority.ERROR, messagestring)
                    continue
                try:
                    # To dynamically instantiate rules without having their
                    # class names, we use exec to instantiate based on a string
                    # E.g. rule_class = mod.AuditFirefoxUsage
                    # In this way, instantiating rule_class(...) is equivalent
                    # to AuditFirefoxUsage(...)
                    exec("rule_class = mod." + rulename)
                except Exception:
                    trace = traceback.format_exc()
                    messagestring = "Error importing rule: " + rulename + " " + \
                                    rulemoduleimportstring + " - " + trace
                    self.logdispatch.log(LogPriority.ERROR,
                                         "Error finding rule class reference: "
                                         + trace)
                    continue
                try:
                    self.ruledictionary[rulename]["ruleobject"] = \
                        rule_class(self.config,
                                   self.environ,
                                   self.logdispatch,
                                   self.statechglogger)
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

    def initializeRuleContextData(self):
        '''Make sure you have all the contextual data for rules
        @author: ekkehard j. koch
        @note: None


        '''
        success = True
        messagestring = "--------------------------------- start"
        self.logdispatch.log(LogPriority.INFO, str(messagestring))
        keys = sorted(list(self.ruledictionary.keys()), reverse=True)
        for key in keys:
            messagestring = ""
            rulename = self.ruledictionary[key]["rulename"]
            try:
                rule = self.ruledictionary[key]["ruleobject"]
                self.ruledictionary[key]["rulenumber"] = rule.getrulenum()
                isapplicable = rule.isapplicable()
                isRootRequired = rule.getisrootrequired()
                if not isapplicable:
                    self.ruledictionary[key]["ruleisapplicable"] = False
                    messagestring = messagestring + " is not applicable."
                else:
                    self.ruledictionary[key]["ruleisapplicable"] = True
                    messagestring = messagestring + " is applicable."
                if self.effectiveUserID == 0:
                    self.ruledictionary[key]["rulecorrecteffectiveuserid"] = \
                        True
                    messagestring = messagestring + " is running in " + \
                        "correct context."
                elif not self.effectiveUserID == 0 and not isRootRequired:
                    self.ruledictionary[key]["rulecorrecteffectiveuserid"] = \
                        True
                    messagestring = messagestring + " is running in " + \
                        "correct context."
                else:
                    self.ruledictionary[key]["rulecorrecteffectiveuserid"] = \
                        False
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
        if self.dictinaryItem is None:
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
        messagestring = "stonixtest rule tested: " + \
                        "--------------------------------------------------"
        self.logdispatch.log(LogPriority.INFO, str(messagestring))
        while self.getCurrentRuleItem() is not None:
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
        messagestring = "stonixtest rule not tested: " + \
                        "--------------------------------------------------"
        self.logdispatch.log(LogPriority.INFO, str(messagestring))
        while self.getCurrentRuleItem() is not None:
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


def assemble_suite(framework=True, rule=True, utils=True, unit=True,
                   network=True, interactive=False, modules=[]):
    '''This sets up the test suite
    @author: ekkehard j. koch
    @note: Make sure it can handle entire rule scenario

    :param framework:  (Default value = True)
    :param rule:  (Default value = True)
    :param utils:  (Default value = True)
    :param unit:  (Default value = True)
    :param network:  (Default value = True)
    :param interactive:  (Default value = False)
    :param modules:  (Default value = [])

    '''
    testList = []
    # If using modules, use module names to set test types
    if modules:
        framework = False
        rule = False
        utils = False
        unit = True
        network = True
        interactive = True
        for module in modules:
            if re.search("^zzzTestRule", module):
                rule = True
            elif re.search("^zzzTestFramework", module):
                framework = True
            elif re.search("^zzzTestUtils", module):
                utils = True

    if rule:
        # Build the full rule dictionary
        ruleDictionary = RuleDictionary(unit, network, interactive, modules)

        # Iterate through rules
        try:
            ruleDictionary.gotoFirstRule()
        except IndexError:
            # IndexErrors will only occur here if the dictionary is empty
            LOGGER.log(LogPriority.ERROR, "RuleDictionary is empty")
            rule = False
        else:
            while ruleDictionary.getCurrentRuleItem() is not None:
                # Get Rule Information
                ruleName = ruleDictionary.getRuleName()
                ruleTestClassName = ruleDictionary.getTestClassName()
                ruleNumber = ruleDictionary.getRuleNumber()
                ruleTestName = ruleDictionary.getTestName()
                ruleCorrectEffectiveUserid = \
                    ruleDictionary.getCorrectEffectiveUserid()
                ruleIsApplicable = ruleDictionary.getIsApplicable()

                # Make Sure this rule should be testing
                if ruleCorrectEffectiveUserid and ruleIsApplicable:
                    try:
                        #####
                        # A = "dot" path to the library we want to import from
                        # B = Module inside library we want to import
                        # basically perform a "from A import B
                        ruleTestToRun = __import__(ruleTestClassName,
                                                   fromlist=[ruleTestName])

                        #####
                        # Add the import to a list, to later "map" to a test
                        # suite
                        testList.append(ruleTestToRun)

                    except Exception as err:
                        LOGGER.log(LogPriority.DEBUG, "stonixtest error: " +
                                   str(ruleName) + "(" + str(ruleNumber) +
                                   ") Exception: " + str(err))
                    finally:
                        ruleDictionary.gotoNextRule()
                else:
                    ruleDictionary.gotoNextRule()

    else:
        LOGGER.log(LogPriority.DEBUG, "\n Not running rule tests\n")

    if framework:

        # Build the framework dictionary
        frameworkDictionary = FrameworkDictionary(modules)

        # Iterate through framework Unit Tests
        try:
            frameworkDictionary.gotoFirstItem()
        except:
            # IndexErrors will only occur here if the dictionary is empty
            LOGGER.log(LogPriority.ERROR,
                       "FrameworkDictionary is empty")
            framework = False
        else:
            while frameworkDictionary.getCurrentItem() is not None:
                frameworkTestName = frameworkDictionary.getTestName()
                frameworkTestPath = frameworkDictionary.getTestPath()
                frameworkTestClassName = frameworkDictionary.getTestClassName()
                frameworkTestModuleName = frameworkDictionary.getModuleName()
                frameworkCompleteTestPath = frameworkTestPath
                frameworkCompleteTestName = frameworkTestName + "." + \
                    frameworkTestModuleName

                LOGGER.log(LogPriority.DEBUG, "----------------------------")
                LOGGER.log(LogPriority.DEBUG,
                           "\tFTN:  " + str(frameworkTestName))
                LOGGER.log(LogPriority.DEBUG,
                           "\tFTCN: " + str(frameworkTestClassName))
                LOGGER.log(LogPriority.DEBUG,
                           "\tFTP:  " + str(frameworkTestPath))
                LOGGER.log(LogPriority.DEBUG,
                           "\tFCTP: " + str(frameworkCompleteTestPath))
                LOGGER.log(LogPriority.DEBUG,
                           "\tFTCN: " + str(frameworkCompleteTestName))
                LOGGER.log(LogPriority.DEBUG, "----------------------------")

                try:
                    #####
                    # A = "dot" path to the library we want to import from
                    # B = Module inside library we want to import
                    # basically perform a "from A import B
                    fameworkTestToRun = __import__(frameworkTestClassName,
                                                   fromlist=[frameworkTestName])

                    #####
                    # Add the import to a list, to later "map" to a test suite
                    testList.append(fameworkTestToRun)

                except Exception as err:
                    debug = "stonixtest error: " + \
                        str(frameworkTestClassName) + " Exception: " + \
                        str(err) + "\n"
                    LOGGER.log(LogPriority.DEBUG, debug)
                frameworkDictionary.gotoNextItem()
    else:
        LOGGER.log(LogPriority.DEBUG, "\n Not running framework tests.\n")

    if utils:

        # Build the framework dictionary
        utilsDictionary = UtilsDictionary(modules)

        # Iterate through framework Unit Tests
        try:
            utilsDictionary.gotoFirstItem()
        except:
            # IndexErrors will only occur here if the dictionary is empty
            LOGGER.log(LogPriority.ERROR,
                       "UtilsDictionary is empty")
            utils = False
        else:
            while utilsDictionary.getCurrentItem() is not None:
                utilsTestName = utilsDictionary.getTestName()
                utilsTestPath = utilsDictionary.getTestPath()
                utilsTestClassName = utilsDictionary.getTestClassName()
                utilsTestModuleName = utilsDictionary.getModuleName()
                utilsCompleteTestPath = utilsTestPath
                utilsCompleteTestName = utilsTestName + "." + \
                    utilsTestModuleName

                LOGGER.log(LogPriority.DEBUG, "----------------------------")
                LOGGER.log(LogPriority.DEBUG, "\tFTN:  " + str(utilsTestName))
                LOGGER.log(LogPriority.DEBUG,
                           "\tFTCN: " + str(utilsTestClassName))
                LOGGER.log(LogPriority.DEBUG, "\tFTP:  " + str(utilsTestPath))
                LOGGER.log(LogPriority.DEBUG,
                           "\tFCTP: " + str(utilsCompleteTestPath))
                LOGGER.log(LogPriority.DEBUG,
                           "\tFTCN: " + str(utilsCompleteTestName))
                LOGGER.log(LogPriority.DEBUG, "----------------------------")

                try:
                    #####
                    # A = "dot" path to the library we want to import from
                    # B = Module inside library we want to import
                    # basically perform a "from A import B
                    utilsTestToRun = __import__(utilsTestClassName,
                                                fromlist=[utilsTestName])

                    #####
                    # Add the import to a list, to later "map" to a test suite
                    testList.append(utilsTestToRun)

                except Exception as err:
                    debug = "stonixtest error: " + \
                        str(frameworkTestClassName) + " Exception: " + \
                        str(err) + "\n"
                    LOGGER.log(LogPriority.DEBUG, debug)
                utilsDictionary.gotoNextItem()
    else:
        LOGGER.log(LogPriority.DEBUG, "\n Not running utils tests.\n")

    #####
    # Set up the test loader function
    load = unittest.defaultTestLoader.loadTestsFromModule

    #####
    # Define a test suite based on the testList.
    suite = unittest.TestSuite(list(map(load, testList)))

    if rule and not modules:
        # Add the test for every rule and rule for every test... test.
        anotherTest = ConsistencyCheck()
        suite.addTests(unittest.makeSuite(anotherTest.getTest()))

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

VERSION = "0.9.5"
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
                  default=False, help="Run the Rule tests.  Will not" +
                                      " work when combined with -f and -u.")

parser.add_option("-u", "--utils", action="store_true", dest="utils",
                  default=False, help="Run the function tests.  Will not" +
                                      " work when combined with -f and -r.")

parser.add_option("-s", "--skip", action="store_true",
                  dest="skip_syslog", default=False,
                  help="Skip syslog logging so we don't fill up the logs." +
                       "This will leave an incremental log by default in " +
                       "/tmp/<uid>.stonixtest.<log number>, where log number" +
                       " is the order of the last ten stonixtest runs.")

parser.add_option("--network", action="store_true", dest="network",
                  default=False, help="Run the network category of tests")

parser.add_option("--unit", action="store_true", dest="unit",
                  default=False, help="Run the unit test category of tests")

parser.add_option("-i", "--interactive", action="store_true",
                  dest="interactive", default=False,
                  help="Log failures using default log")

parser.add_option("-f", "--framework", action="store_true", dest="framework",
                  default=False, help="Run the Framework tests.  Will not" +
                                      " work when combined with -r and -u.")

parser.add_option("-a", "--all-automatable", action="store_true", dest="all",
                  default=False, help="Run all unit and network tests - " +
                  "interactive tests not included")

parser.add_option("--rule-test-consistency", action="store_true",
                  dest="consistency", default=False,
                  help="Check to make sure there is a " +
                  "test for every rule and a rule for every rule test")

parser.add_option("-v", "--verbose", action="store_true",
                  dest="verbose", default=False,
                  help="Print status messages")

parser.add_option("-d", "--debug", action="store_true", dest="debug",
                  default=False, help="Print debug messages")

parser.add_option('-m', '--modules', action="extend", type="string",
                  dest='modules', help="Use to run a single or " +
                  "multiple unit tests at once.  Use the test name.")

if len(sys.argv) == 1:
    parser.parse_args(['--help'])

options, __ = parser.parse_args()

if options.logauto:
    ttrlog = time.strftime('%Y%m%d-%H%M%S') + ".log"
elif options.ttrlog:
    ttrlog = options.ttrlog

network = options.network

unit = options.unit

interactive = options.interactive

if options.rule and not options.framework and not options.utils:
    rule = options.rule
    framework = False
    utils = False
    options.all = False

elif options.framework and not options.rule and not options.utils:
    framework = options.framework
    rule = False
    utils = False
    options.all = False

elif not options.framework and not options.rule and options.utils:
    utils = options.utils
    rule = False
    framework = False
    options.all = False

if not options.framework and not options.rule and not options.utils:
    rule = True
    framework = True
    utils = True

if options.framework and options.rule and not options.utils or \
   options.framework and not options.rule and options.utils or \
   not options.framework and options.rule and options.utils or \
   options.framework and options.rule and options.utils:
    print("Sorry, -f and -r and -u are mutually exclusive.")
    sys.exit(255)

if options.all:
    unit = True
    network = True
    framework = True
    utils = True
    rule = True
    consistency = True

debug_mode = options.debug
verbose_mode = options.verbose

ENVIRON = Environment()
ENVIRON.setdebugmode(debug_mode)
ENVIRON.setverbosemode(verbose_mode)
LOGGER = LogDispatcher(ENVIRON)
SYSCONFIG = Configuration(ENVIRON)
STATECHANGELOGGER = StateChgLogger(LOGGER, ENVIRON)


def setUpModule():
    '''Function made available to the whole module - holds globals
    instanciated once for all unittests contained within the module.
    
    @author: Roy Nielsen


    '''
    global ENVIRON
    global LOGGER
    global SYSCONFIG
    global STATECHANGELOGGER


# Make sure this works from the command line as well as in debbug mode
if __name__ == '__main__' or __name__ == 'stonixtest':
    """
    Main program

    """
    logger = LOGGER
    logger.initializeLogs(syslog=options.skip_syslog)
    logger.markSeparator()
    logger.markStartLog()
    logger.logEnv()

    logger.log(LogPriority.DEBUG, "---==# Done initializing logger...#==---")

    modules = options.modules

    consistency = options.consistency

    # Set Up test environment
    if "ttrlog" in locals():
        runner = unittest.TextTestRunner(ConsoleAndFileWriter(ttrlog))
    else:
        runner = unittest.TextTestRunner(stream=sys.stdout)

    # Set Up test suite
    if modules:
        # only process tests passed in via the -m flag
        testsuite = assemble_suite(modules=modules)
    elif consistency:
        #####
        # Define a test suite based on the testList.
        testsuite = unittest.TestSuite()

        # Add the test for every rule and rule for every test... test.
        test2run = ConsistencyCheck()
        testsuite.addTests(unittest.makeSuite(test2run.getTest()))
    else:
        testsuite = assemble_suite(framework, rule, utils,
                                   unit, network, interactive)

    # Run the test suite
    result = runner.run(testsuite)

    logger.markEndLog()
    logger.markSeparator()
    logger.rotateLog()

    # Exit code is equal to number of test failures
    exit(len(result.failures))
