#!/usr/bin/python
'''
Created on Jul 13, 2011

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
import os
import re
import pwd
import unittest
import src.stonix_resources.environment as environment

class zzzTestFrameworkenvironment(unittest.TestCase):

    def setUp(self):
        self.to = environment.Environment()
    
    def tearDown(self):
        pass
    
    def testGetostype(self):
        validtypes = ['Red Hat Enterprise Linux Workstation release 6.0 (Santiago)',
                      'Red Hat Enterprise Linux Workstation release 6.3 (Santiago)',
                      'Red Hat Enterprise Linux Server release 7.0 (Maipo)',
                      'Mac OS X']
        self.failIf( self.to.getostype() not in validtypes )
    
    def testGetosfamily(self):
        validfamilies = ['linux', 'darwin', 'solaris', 'freebsd']
        self.failIf( self.to.getosfamily() not in validfamilies )

    def testGetosver(self):
        self.failUnless(re.search('([0-9]{1,3})|(([0-9]{1,3})\.([0-9]{1,3}))',
                                  self.to.getosver()))
    
    def testGetipaddress(self):
        self.failUnless(re.search('(([0-9]{1,3}\.){3}[0-9]{1,3})',
                                  self.to.getipaddress()))
    
    def testGetmacaddr(self):
        self.failUnless(re.search('(([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2})', 
                                  self.to.getmacaddr()))
        
    def testGeteuid(self):
        uid = os.geteuid()
        self.failUnless(self.to.geteuid() == uid)
        
    def testSetGetInstall(self):
        self.to.setinstallmode(True)
        self.failUnlessEqual(self.to.getinstallmode(), True)
        self.to.setinstallmode(False)
        self.failUnlessEqual(self.to.getinstallmode(), False)
        
    def testSetGetVerbose(self):
        self.to.setverbosemode(True)
        self.failUnlessEqual(self.to.getverbosemode(), True)
        self.to.setverbosemode(False)
        self.failUnlessEqual(self.to.getverbosemode(), False)
        
    def testSetGetDebug(self):
        self.to.setdebugmode(True)
        self.failUnlessEqual(self.to.getdebugmode(), True)
        self.to.setdebugmode(False)
        self.failUnlessEqual(self.to.getdebugmode(), False)
        
    def testGetEuidHome(self):
        self.failUnlessEqual(self.to.geteuidhome(),
                             pwd.getpwuid(os.geteuid())[5])
        
    def testGetPropNum(self):
        self.failUnless(re.search('[0-9]{7}', self.to.get_property_number()))
        print 'PN: ' + self.to.get_property_number()
        
    def testGetSysSerNo(self):
        self.assertTrue(self.to.get_system_serial_number())
        print 'SysSer: ' + self.to.get_system_serial_number()
        
    def testGetChassisSerNo(self):
        self.assertTrue(self.to.get_chassis_serial_number())
        print 'Ser: ' + self.to.get_chassis_serial_number()
        
    def testGetSysMfg(self):
        mfg = self.to.get_system_manufacturer()
        print 'SysMFG: ' + mfg
        self.assertTrue(mfg)
    
    def testGetChassisMfg(self):
        mfg = self.to.get_chassis_manfacturer()
        print 'MFG: ' + mfg
        self.assertTrue(mfg)
        
    def testGetSysUUID(self):
        uuid = self.to.get_sys_uuid()
        print 'UUID: ' + uuid
        self.assertTrue(uuid)
        
    def testIsMobile(self):
        self.assertFalse(self.to.ismobile(),
                         'This should fail on mobile systems')
        
    def testSetNumRules(self):
        num = 20
        self.to.setnumrules(num)
        self.failUnlessEqual(self.to.getnumrules(), num)
        
    def testSetNumRulesErr(self):
        self.assertRaises(TypeError, self.to.setnumrules, 'foo')
        self.assertRaises(ValueError, self.to.setnumrules, -1)

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()