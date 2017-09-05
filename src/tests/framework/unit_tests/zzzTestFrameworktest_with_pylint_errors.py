#!/usr/bin/python -u

from __future__ import absolute_import

import os
import re
import sys
import unittest
from subprocess import Popen, PIPE
from optparse import  OptionParser

sys.path.append("../../..")

from stonix_resources.loggers import CyLogger
from stonix_resources.loggers import LogPriority as lp
#from lib.run_commands import RunWith
from tests.lib.PylintIface import PylintIface, processFile

from pylint import epylint

dirPkgRoot = '../../../..'
logger = CyLogger()
logger.initializeLogs()
#rw = RunWith(logger)

def getRecursiveTree(targetRootDir="."):
    filesList = []
    for root, dirs, files in os.walk(dirPkgRoot):
        for myfile in files:
            if re.search(".+\.py$", myfile): 
                filesList.append(os.path.abspath(os.path.join(root, myfile)))
    return filesList

def getDirList(targetDir="."):
    filesList = []
    for myfile in os.listdir(targetDir):
        if re.search(".+\.py$", myfile): 
            filesList.append(os.path.abspath(os.path.join(targetDir, myfile)))
    return filesList

def genTestData(fileList=[]):
    test_case_data = []
    if not fileList:
        print "Cannot generate data from nothing..."
        sys.exit(1)

    pIface = PylintIface(logger)
    for myfile in fileList:
        #print myfile
        try:
            if not re.search(".+\.py$", myfile):
                continue
            elif not re.match("__init__.py", myfile):
                output = ""
                error = ""
                jsonData = ""
                #print myfile
                jsonData = processFile(myfile)
                jsonData = pIface.processFile(myfile)
                #print jsonData
                for item in jsonData:
                    if re.match("^error$", item['type']) or re.match("^fatal$", item['type']):
                        #print "Found: " + str(item['type']) + " (" + str(item['line']) + ") : " + str(item['message'])
                        test_case_data.append((myfile, item['line'], item['message']))
        except AttributeError:
            pass
    #for data in test_case_data:
    #    print data
    return test_case_data

def pylint_test_template(*args):
    '''
    decorator for monkeypatching
    '''
    def foo(self):
        self.assert_pylint_error(*args)
    return foo


class test_with_pylint_errors(unittest.TestCase):
    def assert_pylint_error(self, myfile, lineNum, text):
        self.assertTrue(False, myfile + ": (" + str(lineNum) + ") " + text)

if __name__=="__main__":
    #####
    # Get options
    parser = OptionParser(usage="\n\n%prog [options]\n\n", version="0.8.6")
    
    parser.add_option("-r", "--recursive-tree", dest="treeRoot",
                      default="",
                      help="The root of a directory to recurse and check all '*.py' files")
    parser.add_option("--dir", dest="dirToCheck",
                      default="",
                      help="Name of the directory to look at for '*.py' files (not recursive)")
    parser.add_option("-f", "--file", dest="fileToCheck",
                      default=".",
                      help="Name of the directory to look at for '*.py' files (not recursive)")
    parser.add_option("-d", "--debug", action="store_true", dest="debug",
                      default=0, help="Print debug messages")
    parser.add_option("-v", "--verbose", action="store_true",
                      dest="verbose", default=0,
                      help="Print status messages")
    
    (opts, args) = parser.parse_args()

    if opts.verbose != 0:
        level = CyLogger(level=lp.INFO)
    elif opts.debug != 0:
        level = CyLogger(level=lp.DEBUG)
    else:
        level=lp.WARNING

    if not opts.treeRoot and not opts.dirToCheck and not opts.fileToCheck:
        output, error = Popen([__file__, "-h"], stdout=PIPE, stderr=PIPE)
        sys.exit(0)

    else:
        #####
        # Run unittest per options
        if opts.treeRoot:
            test_case_data = genTestData(getRecursiveTree(opts.treeRoot))
        elif opts.dirToCheck:
            test_case_data = genTestData(getDirList(opts.dirToCheck))
        elif opts.fileToCheck:
            test_case_data = genTestData([opts.fileToCheck])
    for specificError in test_case_data:
        #print str(specificError)
        myfile, lineNum, text = specificError
        test_name = "test_with_pylint_{0}_{1}_{2}".format("_".join("_".join(myfile.split("/")).split(".")), lineNum, "_".join("_".join(text.split(" ")).split("'")))
        #print test_name
        error_case = pylint_test_template(*specificError)
        setattr(test_with_pylint_errors, test_name, error_case)
    #####
    # Initialize the test suite
    test_suite = unittest.TestSuite()
    
    for specificError in test_case_data:
        #print str(specificError)
        myfile, lineNum, text = specificError
        test_name = "test_with_pylint_{0}_{1}_{2}".format("_".join("_".join(myfile.split("/")).split(".")), lineNum, "_".join("_".join(text.split(" ")).split("'")))
        #print test_name
        error_case = pylint_test_template(*specificError)
        setattr(test_with_pylint_errors, test_name, error_case)

    test_suite.addTest(unittest.makeSuite(test_with_pylint_errors))
    #test_suite.addTest(unittest.makeSuite(ConfigTestCase))
    runner = unittest.TextTestRunner()
    testResults  = runner.run(test_suite)
    
    if testResults.errors:
        raise TestResultsError(str(testResults.error))

else:
    #####
    # Run unittest per current source tree
    test_case_data = genTestData(getRecursiveTree(".."))

    for specificError in test_case_data:
        #print str(specificError)
        myfile, lineNum, text = specificError
        test_name = "test_with_pylint_{0}_{1}_{2}".format("_".join("_".join(myfile.split("/")).split(".")), lineNum, "_".join("_".join(text.split(" ")).split("'")))
        print test_name
        error_case = pylint_test_template(*specificError)
        setattr(test_with_pylint_errors, test_name, error_case)
