#!/usr/bin/python
'''
Created on 04/29/2012

###############################################################################
#                                                                             #
# Copyright 2015-2019.  Los Alamos National Security, LLC. This material was       #
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
