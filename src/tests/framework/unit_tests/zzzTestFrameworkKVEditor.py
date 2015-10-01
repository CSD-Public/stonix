#!/usr/bin/python
'''
Created on 04/29/2012

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

@author: ekkehard
'''
#import KVEditor
import time
import unittest
import src.stonix_resources.KVEditorStonix as KVEditorStonix
from src.stonix_resources.environment import Environment as Environment
from src.tests.lib.logdispatcher_lite import LogDispatcher as LogDispatcher
from src.stonix_resources.StateChgLogger import StateChgLogger as StateChgLogger
from src.stonix_resources.localize import APPLESOFTUPDATESERVER as APPLESOFTUPDATESERVER


class zzzTestFrameworkKVEditor(unittest.TestCase):
    def tearDown(self):
        pass
    def setUp(self):
        #path = "/Library/Preferences/com.apple.SoftwareUpdate.plist"
        kvtype = "defaults"
        data = {"CatalogURL":[APPLESOFTUPDATESERVER, APPLESOFTUPDATESERVER],
                "LastResultCode":["100","100"]}
#         data = {"NAT":{"-dict Enabled":["-int 0","Enabled = 0;"],
#                        "-dict Start":["-string off","Start = off"]}}
        #path = "/Library/Preferences/SystemConfiguration/com.apple.nat"
        path = "/Library/Preferences/com.apple.SoftwareUpdate"
        self.environ = Environment()
        self.logger = LogDispatcher(self.environ)
        stchglogger = StateChgLogger(self.logger,self.environ)
        self.editor = KVEditorStonix.KVEditorStonix(stchglogger,kvtype,path,"",data,"","",self.logger,262)
        #self.editor.create()
    def testSimple(self):
        self.editor.report()
        self.editor.fix()
        self.editor.commit()
        time.sleep(10)
        self.editor.undo()
#     def setUp(self):
#         path = "/Library/Preferences/com.apple.SoftwareUpdate.plist"
#         kvtype = "defaults"
#         data = ""
#         self.environ = Environment()
#         self.logger = LogDispatcher(self.environ)
#         stchglogger = StateChgLogger(self.logger,self.environ)
#         self.editor = KVEditorStonix.KVEditorStonix(stchglogger,kvtype,path,"",data,"","")
#         self.editor.create()
#     def testSimple(self):
#         self.editor.report()
#         self.editor.setEventID("0042001")
#         self.editor.fix()
#         self.editor.commit()
#     '''for kveditorstonix defaults'''
if __name__ == "__main__":
    unittest.main()