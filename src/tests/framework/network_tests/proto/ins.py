#!/usr/bin/python
'''
Prototyping the creation of setUpClass and tearDownClass for python < 2.7

'''
import re
import inspect

class MyClass(object):
    def __init__(self):
        self.setUp()
        self.setUp()
        self.setUp()
        self.tearDown()
        self.tearDown()
        self.tearDown()

    def setUp(self):
        try:
            print '... entered setup ...'
            if self.totalTests > 0:
                return
        except:
            self.totalTests = 0
            members = inspect.getmembers(self, inspect.ismethod)
            print members
            for member in members:
                if re.match("^test", member[0]):
                    print member[0]
                    self.totalTests = self.totalTests + 1
        print " ... setUpClass calculated: " + str(self.totalTests) + " tests ..." 

    def tearDown(self):
        if self.totalTests > 1:
            #####
            # tearDown
            ''' ... do work here ... '''
            print ' ... tearDown ... '
            self.totalTests = self.totalTests - 1
            return 
        elif self.totalTests == 1:
            ''' ... do work here ... '''
            print ' ... tearDown ... '
            self.totalTests = self.totalTests - 1
            
        #####
        # tearDownClass
        ''' ... tearDownClass functionality ... '''
        print ' . . . tearDownClass . . . '
        print "done..."

    def test_one(self):
        pass

    def test_two(self):
        pass

    def test_n(self):
        pass

if __name__ == '__main__':
    mycls = MyClass()

