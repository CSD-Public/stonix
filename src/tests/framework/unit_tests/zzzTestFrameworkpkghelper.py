#!/usr/bin/python
'''
Created on Jul 31, 2012

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

@author: dwalker
'''

import unittest
import src.stonix_resources.pkghelper as pkghelper
from src.tests.lib.logdispatcher_mock import LogPriority,LogDispatcher
import src.stonix_resources.environment as environment

class zzzTestFrameworkpkghelper(unittest.TestCase):
    
    def setUp(self):
        print "in set up method...\n"
        self.enviro = environment.Environment()
        self.logger = LogDispatcher(self.enviro)
        self.helper = pkghelper.Pkghelper(self.logger,self.enviro)
    def tearDown(self):
        pass
    def testInstall(self):
        print "inside test Install method...\n"
        self.failUnless(self.helper.install("php"))
        self.failUnless(self.helper.check("php"))
    def testRemove(self):
        print "inside remove method...\n"
        self.failUnless(self.helper.remove("php"))
        self.failIf(self.helper.check("php"))   
    def testCheck1(self):
        print "inside test check method...\n"
        self.helper.install("php")
        self.failUnless(self.helper.check("php"))
        self.helper.remove("php")
        self.failIf(self.helper.check("php"))
if __name__ == "__main__":
    unittest.main()