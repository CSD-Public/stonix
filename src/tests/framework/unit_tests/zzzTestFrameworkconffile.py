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
Created on Dec 14, 2011


@author: dkennel
@change: 2015-02-26 - Reformatted to work with stonixtest
@change: 2016-02-10 roy - adding sys.path.append for both test framework and 
                          individual test runs.
'''
import os
import sys
import unittest

sys.path.append("../../../..")
import src.stonix_resources.environment as environment
import src.stonix_resources.conffile as conffile
import src.tests.lib.logdispatcher_lite as logdispatcher


class zzzTestFrameworkconffile(unittest.TestCase):

    def setUp(self):
        # create sample test files
        env = environment.Environment()
        logger = logdispatcher.LogDispatcher(env)
        tdsource = {'key1': 'val1', 'key2': 'val2', 'key3': 'val3'}
        self.td2source = {'key1': 'val1', 'key2': 'val2', 'key3': 'val6'}
        tcopeneq = open('test1.conf', 'a')
        tcclosedeq = open('test2.conf', 'a')
        tcspace = open('test3.conf', 'a')
        for key in tdsource:
            line1 = key + ' = ' + tdsource[key] + '\n'
            tcopeneq.write(line1)
            line2 = key + '=' + tdsource[key] + '\n'
            tcclosedeq.write(line2)
            line3 = key + ' ' + tdsource[key] + '\n'
            tcopeneq.write(line1)
            tcclosedeq.write(line2)
            tcspace.write(line3)
        tcopeneq.close()
        tcclosedeq.close()
        tcspace.close()
        self.to_openeq = conffile.ConfFile('test1.conf', 'test1.conf.tmp',
                                           'openeq', tdsource, env, logger)
        self.to_closedeq = conffile.ConfFile('test2.conf', 'test2.conf.tmp',
                                             'closedeq', tdsource, env, logger)
        self.to_space = conffile.ConfFile('test3.conf', 'test3.conf.tmp',
                                          'space', tdsource, env, logger)
    def tearDown(self):
        os.remove('test1.conf')
        os.remove('test2.conf')
        os.remove('test3.conf')

    def testOpenEqIsPresent(self):
        self.failUnless( self.to_openeq.ispresent() )
        
    def testClosedEqIsPresent(self):
        self.failUnless( self.to_closedeq.ispresent() )
        
    def testSpaceIsPresent(self):
        self.failUnless( self.to_space.ispresent() )
        
    def testOpenEqAudit(self):
        self.failUnless( self.to_openeq.audit() )
        
    def testClosedEqAudit(self):
        self.failUnless( self.to_openeq.audit() )
        
    def testSpaceAudit(self):
        self.failUnless( self.to_space.audit() )


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()