#!/usr/bin/env python3 -d
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
Created on Sep 21, 2011


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
        self.assertEqual(self.tostr.getkey(), 'stringkey')

    def testStrGetDefValue(self):
        self.assertEqual(self.tostr.getdefvalue(), 'stringdefaultval')

    def testStrGetDataType(self):
        self.assertEqual(self.tostr.getdatatype(), 'string')

    def testStrGetInstructions(self):
        self.assertEqual(self.tostr.getinstructions(),
                             'String instructions')

    def testStrInSimple(self):
        self.assertEqual(self.tostr.insimple(), True)

    def testStrGetSetUC(self):
        self.assertEqual(self.tostr.getusercomment(),
                             'String user comment')
        self.tostr.setusercomment('New user comment')
        self.assertEqual(self.tostr.getusercomment(),
                             'New user comment')

    def testStrGetSetCurVal(self):
        self.assertEqual(self.tostr.getcurrvalue(),
                             'strcurval')
        self.tostr.updatecurrvalue('wowza')
        self.assertEqual(self.tostr.getcurrvalue(),
                             'wowza')

    # Testing bools
    def testBoolGetKey(self):
        self.assertEqual(self.tobool.getkey(), 'boolkey')

    def testBoolGetDefValue(self):
        self.assertEqual(self.tobool.getdefvalue(), True)

    def testBoolGetDataType(self):
        self.assertEqual(self.tobool.getdatatype(), 'bool')

    def testBoolGetInstructions(self):
        self.assertEqual(self.tobool.getinstructions(),
                             'bool instructions')

    def testBoolInSimple(self):
        self.assertEqual(self.tobool.insimple(), False)

    def testBoolGetSetUC(self):
        self.assertEqual(self.tobool.getusercomment(),
                             'bool user comment')
        self.tobool.setusercomment('New user comment')
        self.assertEqual(self.tobool.getusercomment(),
                             'New user comment')

    def testBoolGetSetCurVal(self):
        self.assertEqual(self.tobool.getcurrvalue(),
                             True)
        self.tobool.updatecurrvalue(False)
        self.assertEqual(self.tobool.getcurrvalue(),
                             False)

    # Testing ints
    def testIntGetKey(self):
        self.assertEqual(self.toint.getkey(), 'intkey')

    def testIntGetDefValue(self):
        self.assertEqual(self.toint.getdefvalue(), 1)

    def testIntGetDataType(self):
        self.assertEqual(self.toint.getdatatype(), 'int')

    def testIntGetInstructions(self):
        self.assertEqual(self.toint.getinstructions(),
                             'int instructions')

    def testIntInSimple(self):
        self.assertEqual(self.toint.insimple(), False)

    def testIntGetSetUC(self):
        self.assertEqual(self.toint.getusercomment(),
                             'int user comment')
        self.toint.setusercomment('New user comment')
        self.assertEqual(self.toint.getusercomment(),
                             'New user comment')

    def testIntGetSetCurVal(self):
        self.assertEqual(self.toint.getcurrvalue(),
                             2)
        self.toint.updatecurrvalue(3)
        self.assertEqual(self.toint.getcurrvalue(),
                             3)

    # Testing Floats
    def testFloatGetKey(self):
        self.assertEqual(self.tofloat.getkey(), 'floatkey')

    def testFloatGetDefValue(self):
        self.assertEqual(self.tofloat.getdefvalue(), 3.5)

    def testFloatGetDataType(self):
        self.assertEqual(self.tofloat.getdatatype(), 'float')

    def testFloatGetInstructions(self):
        self.assertEqual(self.tofloat.getinstructions(),
                             'float instructions')

    def testFloatInSimple(self):
        self.assertEqual(self.tofloat.insimple(), False)

    def testFloatGetSetUC(self):
        self.assertEqual(self.tofloat.getusercomment(),
                             'float user comment')
        self.tofloat.setusercomment('New user comment')
        self.assertEqual(self.tofloat.getusercomment(),
                             'New user comment')

    def testFloatGetSetCurVal(self):
        self.assertEqual(self.tofloat.getcurrvalue(),
                             4.2)
        self.tofloat.updatecurrvalue(42.1)
        self.assertEqual(self.tofloat.getcurrvalue(),
                             42.1)

    # Testing Lists
    def testListGetKey(self):
        self.assertEqual(self.tolist.getkey(), 'listkey')

    def testListGetDefValue(self):
        self.assertEqual(self.tolist.getdefvalue(), self.lista)

    def testListGetDataType(self):
        self.assertEqual(self.tolist.getdatatype(), 'list')

    def testListGetInstructions(self):
        self.assertEqual(self.tolist.getinstructions(),
                             'list instructions')

    def testListInSimple(self):
        self.assertEqual(self.tolist.insimple(), False)

    def testListGetSetUC(self):
        self.assertEqual(self.tolist.getusercomment(),
                             'list user comment')
        self.tolist.setusercomment('New user comment')
        self.assertEqual(self.tolist.getusercomment(),
                             'New user comment')

    def testListGetSetCurVal(self):
        self.assertEqual(self.tolist.getcurrvalue(),
                             self.listb)
        listc = [1, 2, 3, 4]
        self.tolist.updatecurrvalue(listc, False)
        self.assertEqual(self.tolist.getcurrvalue(),
                             listc)

    # Testing Dicts
    def testDictGetKey(self):
        self.assertEqual(self.todict.getkey(), 'dictkey')

    def testDictGetDefValue(self):
        self.assertEqual(self.todict.getdefvalue(), self.dicta)

    def testDictGetDataType(self):
        self.assertEqual(self.todict.getdatatype(), 'dict')

    def testDictGetInstructions(self):
        self.assertEqual(self.todict.getinstructions(),
                             'dict instructions')

    def testDictInSimple(self):
        self.assertEqual(self.todict.insimple(), False)

    def testDictGetSetUC(self):
        self.assertEqual(self.todict.getusercomment(),
                             'dict user comment')
        self.todict.setusercomment('New user comment')
        self.assertEqual(self.todict.getusercomment(),
                             'New user comment')

    def testDictGetSetCurVal(self):
        self.assertEqual(self.todict.getcurrvalue(),
                             self.dictb)
        mydict = self.todict.getcurrvalue()
        mydict['yellow'] = 9
        self.todict.updatecurrvalue(mydict)
        self.assertEqual(self.todict.getcurrvalue(),
                             mydict)

# Tests for new functionality with 4/14 revisions
    def testNewSetKey(self):
        self.tonew1.setkey('foo')
        self.assertEqual(self.tonew1.getkey(), 'foo')

    def testNewSetInstructions(self):
        self.tonew1.setinstructions('test instructions')
        self.assertEqual(self.tonew1.getinstructions(),
                             'test instructions')

    def testNewSetDefault(self):
        self.tonew1.setdefvalue(True)
        self.assertEqual(self.tonew1.getdefvalue(), True)

    def testNewSetSimple(self):
        self.tonew1.setsimple(False)
        self.assertEqual(self.tonew1.insimple(), False)

    def testRegExValidation(self):
        self.tonew2.setkey('foo')
        self.tonew2.setinstructions('test instructions')
        self.tonew2.setdefvalue('bar')
        self.tonew2.setregexpattern('baz')
        self.assertTrue(self.tonew2.updatecurrvalue('baz'))
        self.assertFalse(self.tonew2.updatecurrvalue('bongo'))

    def testListValidation(self):
        self.tonew3.setkey('foo')
        self.tonew3.setinstructions('test instructions')
        testlist = ['bar', 'baz', 'flumph', 'frob']
        self.tonew3.setvalidvalueset(testlist)
        self.tonew3.setdefvalue(['bar'])
        self.assertTrue(self.tonew3.updatecurrvalue(['flumph', 'frob'], False))
        self.assertFalse(self.tonew3.updatecurrvalue(['bongo'], False))

    def testStringInSetValidation(self):
        self.tonew2.setkey('foo')
        self.tonew2.setinstructions('test instructions')
        faillist = ['bar', 'baz', 'flumph', 2]
        self.assertRaises(TypeError,
                          self.tonew2.setvalidvalueset, faillist)
        testlist = ['bar', 'baz', 'flumph', 'frob']
        self.tonew2.setdefvalue('baz')
        self.tonew2.setvalidvalueset(testlist)
        self.assertTrue(self.tonew2.updatecurrvalue('bar'))
        self.assertFalse(self.tonew2.updatecurrvalue('bongo'))

    def testDataCoercionList(self):
        self.tonew3.setkey('foo')
        self.tonew3.setinstructions('test instructions')
        testlist = ['bar', 'baz', 'flumph', 'frob']
        self.tonew3.setvalidvalueset(testlist)
        self.tonew3.setdefvalue(['bar'])
        self.assertTrue(self.tonew3.updatecurrvalue('flumph frob'))
        self.assertFalse(self.tonew3.updatecurrvalue('bongo frob'))

    def testDataCoercionInt(self):
        self.tonew4.setkey('foo')
        self.tonew4.setinstructions('test instructions')
        self.tonew4.setdefvalue(15)
        self.assertRaises(TypeError,
                          self.tonew4.setregexpattern, 'fail')
        self.assertTrue(self.tonew4.updatecurrvalue('30'))
        self.assertEqual(30, self.tonew4.getcurrvalue())

    def testDataCoercionFloat(self):
        self.tonew5.setkey('foo')
        self.tonew5.setinstructions('test instructions')
        self.tonew5.setdefvalue(1.5)
        self.assertTrue(self.tonew5.updatecurrvalue('3.5'))
        self.assertEqual(3.5, self.tonew5.getcurrvalue())

if __name__ == "__main__":
    # import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
