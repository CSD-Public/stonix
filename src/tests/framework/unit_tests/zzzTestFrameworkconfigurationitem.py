#!/usr/bin/python -d

'''
Created on Sep 21, 2011

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
@change: 2016-02-10 roy - adding sys.path.append for both test framework and 
                          individual test runs.
'''
import sys
import unittest

sys.path.append("../../../..")
import src.stonix_resources.configurationitem as configurationitem


class zzzTestFrameworkconfigurationitem(unittest.TestCase):

    def setUp(self):
        strkey = 'stringkey'
        strdefval = 'stringdefaultval'
        strucomment = 'String user comment'
        strdatatype = 'string'
        strinst = 'String instructions'
        strcurval = 'strcurval'
        strsimple = True
        self.tostr = configurationitem.ConfigurationItem(strdatatype,
                                                         strkey,
                                                         strdefval,
                                                         strucomment,
                                                         strinst,
                                                         strcurval,
                                                         strsimple)

        boolkey = 'boolkey'
        booldefval = True
        boolucomment = 'bool user comment'
        booldatatype = 'bool'
        boolinst = 'bool instructions'
        boolcurval = True
        boolsimple = False
        self.tobool = configurationitem.ConfigurationItem(booldatatype,
                                                          boolkey,
                                                          booldefval,
                                                          boolucomment,
                                                          boolinst,
                                                          boolcurval,
                                                          boolsimple)

        intkey = 'intkey'
        intdefval = 1
        intucomment = 'int user comment'
        intdatatype = 'int'
        intinst = 'int instructions'
        intcurval = 2
        intsimple = False
        self.toint = configurationitem.ConfigurationItem(intdatatype,
                                                         intkey,
                                                          intdefval,
                                                          intucomment,
                                                          intinst,
                                                          intcurval,
                                                          intsimple)

        floatkey = 'floatkey'
        floatdefval = 3.5
        floatucomment = 'float user comment'
        floatdatatype = 'float'
        floatinst = 'float instructions'
        floatcurval = 4.2
        floatsimple = False
        self.tofloat = configurationitem.ConfigurationItem(floatdatatype,
                                                           floatkey,
                                                          floatdefval,
                                                          floatucomment,
                                                          floatinst,
                                                          floatcurval,
                                                          floatsimple)

        listkey = 'listkey'
        listdefval = ['one', 'two']
        self.lista = listdefval
        listucomment = 'list user comment'
        listdatatype = 'list'
        listinst = 'list instructions'
        listcurval = ['one', 'two', 'three']
        self.listb = listcurval
        listsimple = False
        self.tolist = configurationitem.ConfigurationItem(listdatatype,
                                                          listkey,
                                                          listdefval,
                                                          listucomment,
                                                          listinst,
                                                          listcurval,
                                                          listsimple)

        mydict = {}
        mydict['a'] = 1
        mydict['b'] = 2
        self.dicta = mydict
        dictkey = 'dictkey'
        dictdefval = mydict
        dictucomment = 'dict user comment'
        dictdatatype = 'dict'
        dictinst = 'dict instructions'
        mydict['c'] = 3
        self.dictb = mydict
        dictcurval = mydict
        dictsimple = False
        self.todict = configurationitem.ConfigurationItem(dictdatatype,
                                                          dictkey,
                                                          dictdefval,
                                                          dictucomment,
                                                          dictinst,
                                                          dictcurval,
                                                          dictsimple)

        self.tonew1 = configurationitem.ConfigurationItem('bool')
        self.tonew2 = configurationitem.ConfigurationItem('string')
        self.tonew3 = configurationitem.ConfigurationItem('list')
        self.tonew4 = configurationitem.ConfigurationItem('int')
        self.tonew5 = configurationitem.ConfigurationItem('float')

    def tearDown(self):
        pass

    def testStrGetKey(self):
        self.failUnlessEqual(self.tostr.getkey(), 'stringkey')

    def testStrGetDefValue(self):
        self.failUnlessEqual(self.tostr.getdefvalue(), 'stringdefaultval')

    def testStrGetDataType(self):
        self.failUnlessEqual(self.tostr.getdatatype(), 'string')

    def testStrGetInstructions(self):
        self.failUnlessEqual(self.tostr.getinstructions(),
                             'String instructions')

    def testStrInSimple(self):
        self.failUnlessEqual(self.tostr.insimple(), True)

    def testStrGetSetUC(self):
        self.failUnlessEqual(self.tostr.getusercomment(),
                             'String user comment')
        self.tostr.setusercomment('New user comment')
        self.failUnlessEqual(self.tostr.getusercomment(),
                             'New user comment')

    def testStrGetSetCurVal(self):
        self.failUnlessEqual(self.tostr.getcurrvalue(),
                             'strcurval')
        self.tostr.updatecurrvalue('wowza')
        self.failUnlessEqual(self.tostr.getcurrvalue(),
                             'wowza')

    # Testing bools
    def testBoolGetKey(self):
        self.failUnlessEqual(self.tobool.getkey(), 'boolkey')

    def testBoolGetDefValue(self):
        self.failUnlessEqual(self.tobool.getdefvalue(), True)

    def testBoolGetDataType(self):
        self.failUnlessEqual(self.tobool.getdatatype(), 'bool')

    def testBoolGetInstructions(self):
        self.failUnlessEqual(self.tobool.getinstructions(),
                             'bool instructions')

    def testBoolInSimple(self):
        self.failUnlessEqual(self.tobool.insimple(), False)

    def testBoolGetSetUC(self):
        self.failUnlessEqual(self.tobool.getusercomment(),
                             'bool user comment')
        self.tobool.setusercomment('New user comment')
        self.failUnlessEqual(self.tobool.getusercomment(),
                             'New user comment')

    def testBoolGetSetCurVal(self):
        self.failUnlessEqual(self.tobool.getcurrvalue(),
                             True)
        self.tobool.updatecurrvalue(False)
        self.failUnlessEqual(self.tobool.getcurrvalue(),
                             False)

    # Testing ints
    def testIntGetKey(self):
        self.failUnlessEqual(self.toint.getkey(), 'intkey')

    def testIntGetDefValue(self):
        self.failUnlessEqual(self.toint.getdefvalue(), 1)

    def testIntGetDataType(self):
        self.failUnlessEqual(self.toint.getdatatype(), 'int')

    def testIntGetInstructions(self):
        self.failUnlessEqual(self.toint.getinstructions(),
                             'int instructions')

    def testIntInSimple(self):
        self.failUnlessEqual(self.toint.insimple(), False)

    def testIntGetSetUC(self):
        self.failUnlessEqual(self.toint.getusercomment(),
                             'int user comment')
        self.toint.setusercomment('New user comment')
        self.failUnlessEqual(self.toint.getusercomment(),
                             'New user comment')

    def testIntGetSetCurVal(self):
        self.failUnlessEqual(self.toint.getcurrvalue(),
                             2)
        self.toint.updatecurrvalue(3)
        self.failUnlessEqual(self.toint.getcurrvalue(),
                             3)

    # Testing Floats
    def testFloatGetKey(self):
        self.failUnlessEqual(self.tofloat.getkey(), 'floatkey')

    def testFloatGetDefValue(self):
        self.failUnlessEqual(self.tofloat.getdefvalue(), 3.5)

    def testFloatGetDataType(self):
        self.failUnlessEqual(self.tofloat.getdatatype(), 'float')

    def testFloatGetInstructions(self):
        self.failUnlessEqual(self.tofloat.getinstructions(),
                             'float instructions')

    def testFloatInSimple(self):
        self.failUnlessEqual(self.tofloat.insimple(), False)

    def testFloatGetSetUC(self):
        self.failUnlessEqual(self.tofloat.getusercomment(),
                             'float user comment')
        self.tofloat.setusercomment('New user comment')
        self.failUnlessEqual(self.tofloat.getusercomment(),
                             'New user comment')

    def testFloatGetSetCurVal(self):
        self.failUnlessEqual(self.tofloat.getcurrvalue(),
                             4.2)
        self.tofloat.updatecurrvalue(42.1)
        self.failUnlessEqual(self.tofloat.getcurrvalue(),
                             42.1)

    # Testing Lists
    def testListGetKey(self):
        self.failUnlessEqual(self.tolist.getkey(), 'listkey')

    def testListGetDefValue(self):
        self.failUnlessEqual(self.tolist.getdefvalue(), self.lista)

    def testListGetDataType(self):
        self.failUnlessEqual(self.tolist.getdatatype(), 'list')

    def testListGetInstructions(self):
        self.failUnlessEqual(self.tolist.getinstructions(),
                             'list instructions')

    def testListInSimple(self):
        self.failUnlessEqual(self.tolist.insimple(), False)

    def testListGetSetUC(self):
        self.failUnlessEqual(self.tolist.getusercomment(),
                             'list user comment')
        self.tolist.setusercomment('New user comment')
        self.failUnlessEqual(self.tolist.getusercomment(),
                             'New user comment')

    def testListGetSetCurVal(self):
        self.failUnlessEqual(self.tolist.getcurrvalue(),
                             self.listb)
        listc = [1, 2, 3, 4]
        self.tolist.updatecurrvalue(listc, False)
        self.failUnlessEqual(self.tolist.getcurrvalue(),
                             listc)

    # Testing Dicts
    def testDictGetKey(self):
        self.failUnlessEqual(self.todict.getkey(), 'dictkey')

    def testDictGetDefValue(self):
        self.failUnlessEqual(self.todict.getdefvalue(), self.dicta)

    def testDictGetDataType(self):
        self.failUnlessEqual(self.todict.getdatatype(), 'dict')

    def testDictGetInstructions(self):
        self.failUnlessEqual(self.todict.getinstructions(),
                             'dict instructions')

    def testDictInSimple(self):
        self.failUnlessEqual(self.todict.insimple(), False)

    def testDictGetSetUC(self):
        self.failUnlessEqual(self.todict.getusercomment(),
                             'dict user comment')
        self.todict.setusercomment('New user comment')
        self.failUnlessEqual(self.todict.getusercomment(),
                             'New user comment')

    def testDictGetSetCurVal(self):
        self.failUnlessEqual(self.todict.getcurrvalue(),
                             self.dictb)
        mydict = self.todict.getcurrvalue()
        mydict['yellow'] = 9
        self.todict.updatecurrvalue(mydict)
        self.failUnlessEqual(self.todict.getcurrvalue(),
                             mydict)

# Tests for new functionality with 4/14 revisions
    def testNewSetKey(self):
        self.tonew1.setkey('foo')
        self.failUnlessEqual(self.tonew1.getkey(), 'foo')

    def testNewSetInstructions(self):
        self.tonew1.setinstructions('test instructions')
        self.failUnlessEqual(self.tonew1.getinstructions(),
                             'test instructions')

    def testNewSetDefault(self):
        self.tonew1.setdefvalue(True)
        self.failUnlessEqual(self.tonew1.getdefvalue(), True)

    def testNewSetSimple(self):
        self.tonew1.setsimple(False)
        self.failUnlessEqual(self.tonew1.insimple(), False)

    def testRegExValidation(self):
        self.tonew2.setkey('foo')
        self.tonew2.setinstructions('test instructions')
        self.tonew2.setdefvalue('bar')
        self.tonew2.setregexpattern('baz')
        self.failUnless(self.tonew2.updatecurrvalue('baz'))
        self.assertFalse(self.tonew2.updatecurrvalue('bongo'))

    def testListValidation(self):
        self.tonew3.setkey('foo')
        self.tonew3.setinstructions('test instructions')
        testlist = ['bar', 'baz', 'flumph', 'frob']
        self.tonew3.setvalidvalueset(testlist)
        self.tonew3.setdefvalue(['bar'])
        self.failUnless(self.tonew3.updatecurrvalue(['flumph', 'frob'], False))
        self.assertFalse(self.tonew3.updatecurrvalue(['bongo'], False))

    def testStringInSetValidation(self):
        self.tonew2.setkey('foo')
        self.tonew2.setinstructions('test instructions')
        faillist = ['bar', 'baz', 'flumph', 2]
        self.failUnlessRaises(TypeError,
                          self.tonew2.setvalidvalueset, faillist)
        testlist = ['bar', 'baz', 'flumph', 'frob']
        self.tonew2.setdefvalue('baz')
        self.tonew2.setvalidvalueset(testlist)
        self.failUnless(self.tonew2.updatecurrvalue('bar'))
        self.assertFalse(self.tonew2.updatecurrvalue('bongo'))

    def testDataCoercionList(self):
        self.tonew3.setkey('foo')
        self.tonew3.setinstructions('test instructions')
        testlist = ['bar', 'baz', 'flumph', 'frob']
        self.tonew3.setvalidvalueset(testlist)
        self.tonew3.setdefvalue(['bar'])
        self.failUnless(self.tonew3.updatecurrvalue('flumph frob'))
        self.assertFalse(self.tonew3.updatecurrvalue('bongo frob'))

    def testDataCoercionInt(self):
        self.tonew4.setkey('foo')
        self.tonew4.setinstructions('test instructions')
        self.tonew4.setdefvalue(15)
        self.failUnlessRaises(TypeError,
                          self.tonew4.setregexpattern, 'fail')
        self.failUnless(self.tonew4.updatecurrvalue('30'))
        self.failUnlessEqual(30, self.tonew4.getcurrvalue())

    def testDataCoercionFloat(self):
        self.tonew5.setkey('foo')
        self.tonew5.setinstructions('test instructions')
        self.tonew5.setdefvalue(1.5)
        self.failUnless(self.tonew5.updatecurrvalue('3.5'))
        self.failUnlessEqual(3.5, self.tonew5.getcurrvalue())

if __name__ == "__main__":
    # import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
