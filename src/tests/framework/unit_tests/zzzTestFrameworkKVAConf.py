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
Created on Jun 13, 2013


@author: dwalker
@change: roy - adding sys.path.append for both test framework and individual
               test runs.
'''
import unittest
import sys

sys.path.append("../../../..")
import src.stonix_resources.KVEditorStonix as KVEditorStonix
from src.stonix_resources.environment import Environment
from src.stonix_resources.logdispatcher import LogDispatcher
from src.stonix_resources.StateChgLogger import StateChgLogger


class zzzTestFrameworkKVAConf(unittest.TestCase):

    def setUp(self):
        kvpath = "/tmp/kvaconfUT"
        open(kvpath, "w").write("I'm a test file!")
        kvpath2 = "/tmp/sysctl.bak"
        open(kvpath2, "w").write("I'm another test file!")

        env = Environment()
        logger = LogDispatcher(env)
        scl = StateChgLogger(logger, env)
        self.editor = KVEditorStonix.KVEditorStonix(scl, logger, "conf",
                                                    kvpath, kvpath + ".tmp",
                                                    {}, "present", "openeq")

    def tearDown(self):
        pass

    def testSimple(self):
        self.assertTrue(self.editor.setPath("/tmp/sysctl.bak"))
        self.assertTrue(self.editor.setTmpPath("/tmp/sysctl.bak.tmp"))
        self.assertTrue(self.editor.setData(
            {'net.ipv4.conf.all.secure_redirects': '0',
             'net.ipv4.conf.all.accept_redirects': '0',
             'net.ipv4.conf.all.rp_filter': '1',
             'net.ipv4.conf.all.log_martians': '1',
             'net.ipv4.conf.all.accept_source_route': '0',
             'net.ipv4.conf.default.accept_redirects': '0',
             'net.ipv4.conf.default.secure_redirects': '0',
             'net.ipv4.conf.default.rp_filter': '1',
             'net.ipv4.conf.default.accept_source_route': '0',
             'net.ipv4.icmp_ignore_bogus_error_responses': '1',
             'net.ipv4.tcp_syncookies': '1',
             'net.ipv4.icmp_echo_ignore_broadcasts': '1',
             'net.ipv4.tcp_max_syn_backlog': '4096'}))
        self.assertFalse(self.editor.report())
        self.assertTrue(self.editor.fix())
        self.assertTrue(self.editor.commit())
        self.assertTrue(self.editor.report())

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
