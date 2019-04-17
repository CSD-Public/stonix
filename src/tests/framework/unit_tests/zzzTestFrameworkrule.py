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

Test suite for the rule.py base class.
@change: 09/24/2010 dkennel Original Implementation
@change: 03/19/2014 pep8 compliance
@change: 2015/01/13 dkennel refactor of isApplicable() and associated test
@change: 2016-02-10 roy adding sys.path.append for both test framework and 
                        individual test runs.
@change: 2017/11/13 ekkehard - make eligible for OS X El Capitan 10.11+
@author: dkennel

'''
import re
import sys
import unittest

sys.path.append("../../../..")
import src.stonix_resources.rule as rule
import src.stonix_resources.environment as environment
import src.tests.lib.logdispatcher_lite as logdispatcher
import src.stonix_resources.StateChgLogger as StateChgLogger
import src.stonix_resources.configuration as configuration


class zzzTestFramework(unittest.TestCase):

    def setUp(self):
        myenv = environment.Environment()
        config = configuration.Configuration(myenv)
        logger = logdispatcher.LogDispatcher(myenv)
        state = StateChgLogger.StateChgLogger(logger, myenv)
        self.to = rule.Rule(config, myenv, logger, state)

    def tearDown(self):
        pass

    def testgetrulenum(self):
        '''GetRuleNum, Test that a valid rule number is returned '''
        self.failUnless(re.search('[0-9]', str(self.to.getrulenum())))

    def testgetrulename(self):
        '''GetRuleName, Test that a valid rule name was returned'''
        self.failUnless(re.search('[A-Za-z]', self.to.getrulename()))

    def testgetmandatory(self):
        '''GetMandatory, Test that a bool is returned'''
        self.failIf(self.to.getmandatory() not in [True, False])

    def testiscompliant(self):
        '''iscompliant, test that a valid bool is returned'''
        self.failIf(self.to.iscompliant() not in [True, False])

    def testgetisrootrequired(self):
        '''getisrootrequired, Test that a valid bool is returned'''
        self.failIf(self.to.getisrootrequired() not in [True, False])

    def testgethelptext(self):
        '''gethelptext, test to see that the prototype help string is
        returned'''
        self.failUnless(re.search('This is the default help text',
                                  self.to.gethelptext()))

    def testgetdetailedresults(self):
        '''getdetailedresults, should return the prototype text.'''
        self.failUnless(re.search('This is the default detailed results text',
                                  self.to.getdetailedresults()))

    def testgetrulesuccess(self):
        '''getrulesuccess, in concrete rules this returns a bool. '''
        self.failIf(self.to.getrulesuccess() not in [True, False])

    def testcheckconfigopts(self):
        '''checkconfigopts, in the base class this always returns true'''
        self.failUnlessEqual(self.to.checkconfigopts(), True)

    def testisdatabaserule(self):
        '''isdatabaserule, should return a bool indicating whether or not
        the rule is a db rule. The base class should return False'''
        self.failUnlessEqual(self.to.isdatabaserule(), False)

    def testisapplicable(self):
        '''isapplicable, in concrete rules should return a bool indicating
        whether or not the rule applies to the current platform. In the base
        class it always returns True.'''
        self.failUnlessEqual(self.to.isapplicable(), True)
        environ = environment.Environment()
        myfamily = environ.getosfamily()
        if environ.geteuid() == 0:
            root = True
        else:
            root = False
        myostype = environ.getostype()
        myver = environ.getosver()
        if re.search('Red Hat Enterprise Linux', myostype):
            self.to.applicable = {'type': 'black', 'family': 'linux'}
            self.failUnlessEqual(self.to.isapplicable(), False)
            self.to.applicable = {'type': 'white', 'family': 'linux'}
            self.failUnlessEqual(self.to.isapplicable(), True)
            # FIXME Assertion error testing commented out. Unittest fails
            # to recognize the raised error correctly. This may be due to
            # differing import paths.
            #self.to.applicable = {'type': 'brown', 'family': 'linux'}
            #self.assertRaises(AssertionError, self.to.isapplicable())
            self.to.applicable = {'type': 'white',
                                  'os': {'Red Hat Enterprise Linux': ['6.0', '+']}}
            self.failUnlessEqual(self.to.isapplicable(), True)
            self.to.applicable = {'type': 'black',
                                  'os': {'Red Hat Enterprise Linux': ['6.0', '+']}}
            self.failUnlessEqual(self.to.isapplicable(), False)
            if not root:
                self.to.applicable = {'type': 'white',
                                      'os': {'Red Hat Enterprise Linux': ['6.0', '+']},
                                      'noroot': True}
                self.failUnlessEqual(self.to.isapplicable(), True)
            else:
                self.to.applicable = {'type': 'white',
                                      'os': {'Red Hat Enterprise Linux': ['6.0', '+']},
                                      'noroot': True}
                self.failUnlessEqual(self.to.isapplicable(), False)
#             self.to.applicable = {'type': 'white',
#                                   'os' :{'Red Hat Enterprise Linux': ['6.0', '+', '7.0']}}
#             self.assertRaises(AssertionError, self.to.isapplicable())
            self.to.applicable = {'type': 'white',
                                  'os': {'Red Hat Enterprise Linux': ['7.9', '-']}}
            self.failUnlessEqual(self.to.isapplicable(), True)
            self.to.applicable = {'type': 'black',
                                  'os': {'Red Hat Enterprise Linux': ['7.9', '-']}}
            self.failUnlessEqual(self.to.isapplicable(), False)
#             self.to.applicable = {'type': 'white',
#                                   'os' :{'Red Hat Enterprise Linux': ['7.0', '-', '6.0']}}
#             self.assertRaises(AssertionError, self.to.isapplicable())
            self.to.applicable = {'type': 'white',
                                  'os': {'Red Hat Enterprise Linux': ['7.9', 'r', '5.0']}}
            self.failUnlessEqual(self.to.isapplicable(), True)
            self.to.applicable = {'type': 'black',
                                  'os': {'Red Hat Enterprise Linux': ['7.9', 'r', '5.0']}}
            self.failUnlessEqual(self.to.isapplicable(), False)

#             self.to.applicable = {'type': 'white',
#                                   'os' :{'Red Hat Enterprise Linux': ['7.0', 'r']}}
#             self.assertRaises(AssertionError, self.to.isapplicable())
            if myver == '7.1':
                self.to.applicable = {'type': 'white',
                                      'os': {'Red Hat Enterprise Linux': ['7.1']}}
                self.failUnlessEqual(self.to.isapplicable(), True)
                self.to.applicable = {'type': 'black',
                                      'os': {'Red Hat Enterprise Linux': ['7.1']}}
                self.failUnlessEqual(self.to.isapplicable(), False)
                self.to.applicable = {'type': 'white',
                                      'os': {'Red Hat Enterprise Linux': ['7.1', '6.0']}}
                self.failUnlessEqual(self.to.isapplicable(), True)
                self.to.applicable = {'type': 'black',
                                      'os': {'Red Hat Enterprise Linux': ['7.1', '6.0']}}
                self.failUnlessEqual(self.to.isapplicable(), False)
                self.to.applicable = {'type': 'white',
                                      'os': {'Red Hat Enterprise Linux': ['6.0']}}
                self.failUnlessEqual(self.to.isapplicable(), False)
                self.to.applicable = {'type': 'black',
                                      'os': {'Red Hat Enterprise Linux': ['6.0']}}
                self.failUnlessEqual(self.to.isapplicable(), True)
            if myver == '6.0':
                self.to.applicable = {'type': 'white',
                                      'os': {'Red Hat Enterprise Linux': ['6.0']}}
                self.failUnlessEqual(self.to.isapplicable(), True)
                self.to.applicable = {'type': 'black',
                                      'os' :{'Red Hat Enterprise Linux': ['6.0']}}
                self.failUnlessEqual(self.to.isapplicable(), False)
                self.to.applicable = {'type': 'white',
                                      'os' :{'Red Hat Enterprise Linux': ['7.0', '6.0']}}
                self.failUnlessEqual(self.to.isapplicable(), True)
                self.to.applicable = {'type': 'black',
                                      'os' :{'Red Hat Enterprise Linux': ['7.0', '6.0']}}
                self.failUnlessEqual(self.to.isapplicable(), False)
                self.to.applicable = {'type': 'white',
                                      'os' :{'Red Hat Enterprise Linux': ['7.0']}}
                self.failUnlessEqual(self.to.isapplicable(), False)
                self.to.applicable = {'type': 'black',
                                      'os' :{'Red Hat Enterprise Linux': ['7.0']}}
                self.failUnlessEqual(self.to.isapplicable(), True)

        if re.search('Mac OS X', myostype):
            self.to.applicable = {'type': 'black', 'family': 'darwin'}
            self.failUnlessEqual(self.to.isapplicable(), False)
            self.to.applicable = {'type': 'white', 'family': 'darwin'}
            self.failUnlessEqual(self.to.isapplicable(), True)
            if root:
                self.to.applicable = {'type': 'black', 'family': 'darwin',
                                      'noroot': True}
                self.failUnlessEqual(self.to.isapplicable(), False)
            else:
                self.to.applicable = {'type': 'white', 'family': 'darwin',
                                      'noroot': True}
                self.failUnlessEqual(self.to.isapplicable(), True)
            #self.to.applicable = {'type': 'brown', 'family': 'linux'}
            #self.assertRaises(AssertionError, self.to.isapplicable())
            self.to.applicable = {'type': 'white',
                                  'os' :{'Mac OS X': ['10.11', '+']}}
            self.failUnlessEqual(self.to.isapplicable(), True)
            self.to.applicable = {'type': 'black',
                                  'os' :{'Mac OS X': ['10.11', '+']}}
            self.failUnlessEqual(self.to.isapplicable(), False)
#             self.to.applicable = {'type': 'white',
#                                   'os' :{'Mac OS X': ['10.9', '+', '7.0']}}
#             self.assertRaises(AssertionError, self.to.isapplicable())
            self.to.applicable = {'type': 'white',
                                  'os' :{'Mac OS X': ['10.11.10', '-']}}
            self.failUnlessEqual(self.to.isapplicable(), True)
            self.to.applicable = {'type': 'black',
                                  'os' :{'Mac OS X': ['10.11.10', '-']}}
            self.failUnlessEqual(self.to.isapplicable(), False)
#             self.to.applicable = {'type': 'white',
#                                   'os' :{'Mac OS X': ['7.0', '-', '10.9']}}
#             self.assertRaises(AssertionError, self.to.isapplicable())
            self.to.applicable = {'type': 'white',
                                  'os' :{'Mac OS X': ['10.10.10', 'r', '10.8']}}
            self.failUnlessEqual(self.to.isapplicable(), True)
            self.to.applicable = {'type': 'black',
                                  'os' :{'Mac OS X': ['10.10.10', 'r', '10.8']}}
            self.failUnlessEqual(self.to.isapplicable(), False)
#             self.to.applicable = {'type': 'white',
#                                   'os' :{'Mac OS X': ['7.0', 'r']}}
#             self.assertRaises(AssertionError, self.to.isapplicable())
            if myver == '10.10.3':
                self.to.applicable = {'type': 'white',
                                      'os' :{'Mac OS X': ['10.10.3']}}
                self.failUnlessEqual(self.to.isapplicable(), True)
                self.to.applicable = {'type': 'black',
                                      'os' :{'Mac OS X': ['10.10.3']}}
                self.failUnlessEqual(self.to.isapplicable(), False)
                self.to.applicable = {'type': 'white',
                                      'os' :{'Mac OS X': ['10.10.3', '10.9']}}
                self.failUnlessEqual(self.to.isapplicable(), True)
                self.to.applicable = {'type': 'black',
                                      'os' :{'Mac OS X': ['10.10.3', '10.9']}}
                self.failUnlessEqual(self.to.isapplicable(), False)
                self.to.applicable = {'type': 'white',
                                      'os' :{'Mac OS X': ['10.9']}}
                self.failUnlessEqual(self.to.isapplicable(), False)
                self.to.applicable = {'type': 'black',
                                      'os' :{'Mac OS X': ['10.9']}}
                self.failUnlessEqual(self.to.isapplicable(), True)
            if myver == '10.9.5':
                self.to.applicable = {'type': 'white',
                                      'os' :{'Mac OS X': ['10.9.5']}}
                self.failUnlessEqual(self.to.isapplicable(), True)
                self.to.applicable = {'type': 'black',
                                      'os' :{'Mac OS X': ['10.9.5']}}
                self.failUnlessEqual(self.to.isapplicable(), False)
                self.to.applicable = {'type': 'white',
                                      'os' :{'Mac OS X': ['10.10.3', '10.9.5']}}
                self.failUnlessEqual(self.to.isapplicable(), True)
                self.to.applicable = {'type': 'black',
                                      'os' :{'Mac OS X': ['10.10.3', '10.9.5']}}
                self.failUnlessEqual(self.to.isapplicable(), False)
                self.to.applicable = {'type': 'white',
                                      'os' :{'Mac OS X': ['10.10.3']}}
                self.failUnlessEqual(self.to.isapplicable(), False)
                self.to.applicable = {'type': 'black',
                                      'os' :{'Mac OS X': ['10.10.3']}}
                self.failUnlessEqual(self.to.isapplicable(), True)

    def testgetcurrstate(self):
        '''getcurrstate in concrete rules is not valid until report() has been
        called. In the base class it always returns notconfigured.'''
        self.failUnlessEqual(self.to.getcurrstate(), 'notconfigured')

    def testgettargetstate(self):
        '''gettargetstate should return "configured" unless it has been set
        otherwise.'''
        self.failUnlessEqual(self.to.gettargetstate(), 'configured')

    def testsettargetstate(self):
        '''To test the set target state function we call the setter and then
        read back the new value with the getter.'''
        self.to.settargetstate('notconfigured')
        self.failUnlessEqual(self.to.gettargetstate(), 'notconfigured')

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
