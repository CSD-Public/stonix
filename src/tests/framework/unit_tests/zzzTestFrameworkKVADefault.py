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

#!/usr/bin/python
'''
Created on 04/29/2012


@author: ekkehard
@change: 2015/10/15 eball Refactored KVEditor unit test to KVADefault test
@change: roy - adding sys.path.append for both test framework and individual
               test runs.'''
import unittest
import sys

sys.path.append("../../../..")
import src.stonix_resources.KVEditorStonix as KVEditorStonix
from src.stonix_resources.environment import Environment
from src.tests.lib.logdispatcher_lite import LogDispatcher
from src.stonix_resources.StateChgLogger import StateChgLogger
from src.stonix_resources.localize import APPLESOFTUPDATESERVER


class zzzTestFrameworkKVADefault(unittest.TestCase):

    def tearDown(self):
        pass

    def setUp(self):
        kvtype = "defaults"
        data = {"CatalogURL": [APPLESOFTUPDATESERVER, APPLESOFTUPDATESERVER],
                "LastResultCode": ["100", "100"]}
        path = "/Library/Preferences/com.apple.SoftwareUpdate"
        self.environ = Environment()
        if not self.environ.getosfamily() == "darwin":
            return
        self.logger = LogDispatcher(self.environ)
        stchglogger = StateChgLogger(self.logger, self.environ)
        self.editor = KVEditorStonix.KVEditorStonix(stchglogger, self.logger,
                                                    kvtype, path,
                                                    path + ".tmp", data,
                                                    "present", "openeq")

    def testSimple(self):
        if not self.environ.getosfamily() == "darwin":
            return

        data = {"GuestEnabled": "0"}
        self.assertTrue(self.editor.setData(data))
        self.assertEqual(data, self.editor.getData())

        path = "/Library/Preferences/com.apple.loginwindow.plist"
        self.assertTrue(self.editor.setPath(path))
        self.assertEqual(path, self.editor.getPath())

if __name__ == "__main__":
    unittest.main()
