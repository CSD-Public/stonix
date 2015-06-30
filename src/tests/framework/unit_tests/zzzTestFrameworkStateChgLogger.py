#! /usr/bin/env python
'''
Created on Aug 24, 2012

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
import shutil
import unittest
import src.stonix_resources.environment as environment
import src.tests.lib.logdispatcher_mock as logdispatcher
import src.stonix_resources.StateChgLogger as StateChgLogger


class zzzTestFrameworkStateChgLogger(unittest.TestCase):

    def setUp(self):
        self.environ = environment.Environment()
        self.environ.setdebugmode(True)
        self.logger = logdispatcher.LogDispatcher(self.environ)
        if os.path.exists('/usr/share/stonix/eventlog'):
            os.remove('/usr/share/stonix/eventlog')
        self.testobj = StateChgLogger.StateChgLogger(self.logger, self.environ)
        self.srcfile = '/etc/stonixtest.conf'
        self.dstfile = '/etc/stonixtest.conf.tmp'
        self.mktestfiles()

    def tearDown(self):
        self.testobj.closelog()
        try:
            os.remove(self.srcfile)
            os.remove(self.dstfile)
        except OSError:
            pass

    def mktestfiles(self):
        whandle = open(self.srcfile, 'w')
        whandle2 = open(self.dstfile, 'w')
        self.srcconf = """# conf file comment v 1.0
key1 = orange
key2 = lemon
key3 = watermelon
"""
        dstconf = """# conf file comment v 1.0
key1 = orange
key2 = yellow
key3 = red
key4 = True
"""
        for line in self.srcconf:
            whandle.write(line)
        whandle.close()
        for line in dstconf:
            whandle2.write(line)
        whandle2.close()

    def testEventStoreFetch(self):
        mytype = 'perm'
        mystart = '0,0,420'
        myend = '0,0,416'
        myid = '9999001'
        mydict = {'eventtype': mytype,
                  'startstate': mystart,
                  'endstate': myend}
        self.testobj.recordchgevent(myid, mydict)
        retdict = self.testobj.getchgevent(myid)
        self.failUnless(retdict == mydict)

    def testRevertFileChange(self):
        self.mktestfiles()
        eventid = '9999001'
        patchpath = '/usr/share/stonix/diffdir/etc/stonixtest.conf.patch-' + eventid
        archivepath = '/usr/share/stonix/archive/etc/stonixtest.conf.ovf'
        self.failUnless(self.testobj.recordfilechange(self.srcfile,
                                                      self.dstfile, eventid))
        self.failUnless(os.path.exists(patchpath), 'Patch not created')
        self.failUnless(os.path.exists(archivepath), 'Archive not created')
        shutil.copyfile(self.dstfile, self.srcfile)
        self.testobj.revertfilechanges(self.srcfile, eventid)
        rhandle = open(self.srcfile)
        data = rhandle.read()
        self.failUnless(data == self.srcconf,
                        'Conf mismatch in' + self.srcfile)

    def testRevertFileDelete(self):
        self.mktestfiles()
        eventid = '9999005'
        archivepath = '/usr/share/stonix/archive/etc/stonixtest.conf.ovf'
        if os.path.exists(archivepath):
            os.remove(archivepath)
        self.failUnless(self.testobj.recordfiledelete(self.srcfile, eventid))
        shutil.copyfile(self.dstfile, self.srcfile)
        self.failUnless(self.testobj.recordfiledelete(self.srcfile, eventid))
        self.failUnless(self.testobj.recordfiledelete(self.srcfile, eventid))
        self.failUnless(os.path.exists(archivepath), 'Archive not created')
        os.remove(self.srcfile)
        self.failUnless(self.testobj.revertfiledelete(self.srcfile))

    def testEventStoreDelete(self):
        mytype = 'perm'
        mystart = '0,0,420'
        myend = '0,0,416'
        myid = '9999002'
        mydict = {'eventtype': mytype,
                  'startstate': mystart,
                  'endstate': myend}
        self.testobj.recordchgevent(myid, mydict)
        self.failUnless(self.testobj.deleteentry(myid))

    def testEventSearch(self):
        mytype = 'perm'
        mystart = '0,0,420'
        myend = '0,0,416'
        myid = '9999003'
        mydict = {'eventtype': mytype,
                  'startstate': mystart,
                  'endstate': myend}
        self.testobj.recordchgevent(myid, mydict)

        mytype1 = 'perm'
        mystart1 = '0,0,420'
        myend1 = '0,0,416'
        myid1 = '9999004'
        mydict1 = {'eventtype': mytype1,
                  'startstate': mystart1,
                  'endstate': myend1}
        self.testobj.recordchgevent(myid1, mydict1)

        mytype2 = 'perm'
        mystart2 = '0,0,420'
        myend2 = '0,0,416'
        myid2 = '0888001'
        mydict2 = {'eventtype': mytype2,
                  'startstate': mystart2,
                  'endstate': myend2}
        self.testobj.recordchgevent(myid2, mydict2)

        myexpected = ['9999003', '9999004']
        myreturn = self.testobj.findrulechanges('9999')
        found = 0
        for event in myreturn:
            if event in myexpected:
                found = found + 1
        self.failIf(len(myreturn) < 2, 'expected number of results not found')
        self.failUnless(found == 2, 'expected results not found')
        self.failIf(myid2 in myreturn, 'Search limit error')

        expected = '0888001'
        myruleid = 888
        myreturn2 = self.testobj.findrulechanges(myruleid)
        self.failUnlessEqual(expected, myreturn2[0],
                             'expected event id not returned')

if __name__ == "__main__":
    # import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
