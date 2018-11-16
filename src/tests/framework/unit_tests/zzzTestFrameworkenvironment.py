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
@change: 2015/10/23 eball Updated deprecated unit test methods, added dummy
                          PN file creation
@change: 2016-02-10 roy  adding sys.path.append for both test framework and 
                         individual test runs.
'''
import os
import re
import pwd
import sys
import unittest
from unittest.case import SkipTest
if os.geteuid() == 0:
    try:
        import dmidecode
        DMI = True
    except(ImportError):
        DMI = False
else:
    DMI = False
sys.path.append("../../../..")
import src.stonix_resources.environment as environment


class zzzTestFrameworkenvironment(unittest.TestCase):

    def setUp(self):
        print "in setUp method\n\n"
        self.to = environment.Environment()
        self.created = False
        if not os.path.exists("/etc/property-number"):
            open("/etc/property-number", "w").write("0123456798")
            self.created = True
        print "after checking if that path exists\n"
        self.euid = os.geteuid()
        print "self.euid: " + str(self.euid) + "\n\n"

    def tearDown(self):
        if self.created:
            os.remove("/etc/property-number")

    def testGetostype(self):
        validtypes = 'Red Hat Enterprise Linux|Debian|Ubuntu|CentOS|Fedora|' + \
                     'openSUSE|Mac OS X'
        print 'OS Type: ' + self.to.getostype()
        self.assertTrue(re.search(validtypes, self.to.getostype()))

    def testGetosfamily(self):
        validfamilies = ['linux', 'darwin', 'solaris', 'freebsd']
        self.assertTrue(self.to.getosfamily() in validfamilies)

    def testGetosver(self):
        self.assertTrue(re.search('([0-9]{1,3})|(([0-9]{1,3})\.([0-9]{1,3}))',
                                  self.to.getosver()))

    def testGetipaddress(self):
        self.assertTrue(re.search('(([0-9]{1,3}\.){3}[0-9]{1,3})',
                                  self.to.getipaddress()))

    def testGetmacaddr(self):
        self.assertTrue(re.search('(([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2})',
                                  self.to.getmacaddr()))

    def testGeteuid(self):
        uid = os.geteuid()
        self.assertTrue(self.to.geteuid() == uid)

    def testSetGetInstall(self):
        self.to.setinstallmode(True)
        self.assertTrue(self.to.getinstallmode())
        self.to.setinstallmode(False)
        self.assertFalse(self.to.getinstallmode())

    def testSetGetVerbose(self):
        self.to.setverbosemode(True)
        self.assertTrue(self.to.getverbosemode())
        self.to.setverbosemode(False)
        self.assertFalse(self.to.getverbosemode())

    def testSetGetDebug(self):
        self.to.setdebugmode(True)
        self.assertTrue(self.to.getdebugmode())
        self.to.setdebugmode(False)
        self.assertFalse(self.to.getdebugmode())

    def testGetEuidHome(self):
        self.assertEqual(self.to.geteuidhome(),
                             pwd.getpwuid(os.geteuid())[5])

    def testGetPropNum(self):
        self.assertTrue(re.search('[0-9]{7}', self.to.get_property_number()))
        print 'PN: ' + self.to.get_property_number()

    def testGetSysSerNo(self):
        self.assertTrue(self.to.get_system_serial_number())
        print 'SysSer: ' + self.to.get_system_serial_number()

    def testGetChassisSerNo(self):
        chassisserial = '0'
        if DMI:
            if self.euid == 0:
                try:
                    chassis = dmidecode.chassis()
                    for key in chassis:
                        chassisserial = chassis[key]['data']['Serial Number']
                except(IndexError, KeyError):
                    # got unexpected data back from dmidecode
                    pass
                unittestchassisserial = chassisserial.strip()
                envchassisserial = self.to.get_chassis_serial_number()
                self.assertEqual(unittestchassisserial, envchassisserial)
                print 'Ser: ' + self.to.get_chassis_serial_number()
            else:
                msg =  "Not running as root, Chassis serial number " + \
                "information not availble\n"
                self.skipTest(msg)
        else:
            msg = "dmidecode module not available for import. " + \
                "Unable to retrieve serial chassis number\n"
            self.skipTest(msg)
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
        self.assertEqual(self.to.getnumrules(), num)

    def testSetNumRulesErr(self):
        self.assertRaises(TypeError, self.to.setnumrules, 'foo')
        self.assertRaises(ValueError, self.to.setnumrules, -1)

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
