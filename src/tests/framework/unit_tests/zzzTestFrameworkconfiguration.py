'''
Created on Jul 18, 2011

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

@author: dkennel
'''
import unittest
import os
import src.stonix_resources.environment as environment
import src.stonix_resources.configuration as configuration


class zzzTestFrameworkconfiguration(unittest.TestCase):

    def setUp(self):
        if not os.path.exists("/etc/stonix.conf"):
            open("/etc/stonix.conf", "w")
        self.env = environment.Environment()
        self.to = configuration.Configuration(self.env)

    def tearDown(self):
        pass

    def testConfValueSetGet(self):
        self.to.setconfvalue('UnitTest', 'unit', True)
        self.assertTrue(self.to.getconfvalue('UnitTest', 'unit'))

    def testSetCommentText(self):
        self.to.setcommenttxt('UnitTest', '# Unit test comment\n')

    def testSetSimple(self):
        self.to.setsimple('UnitTest', True)
        self.to.setsimple('UnitTest', False)

    def testUserComment(self):
        self.to.setusercomment('UnitTest', 'unit', 'Unit test user comment')
        self.assertEqual(self.to.getusercomment('UnitTest', 'unit'),
                         'Unit test user comment')


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
