#!/usr/bin/python -u

from __future__ import absolute_import

import os
import re
import sys
import json
import unittest
from subprocess import Popen, PIPE
from optparse import OptionParser
from optparse import Option, OptionValueError

mydir = os.path.dirname(os.path.abspath(__file__))
parentdir = "/" + "/".join(mydir.split("/")[:-1])
print parentdir
sys.path.append("../../../..")

from src.stonix_resources.loggers import CyLogger
from src.stonix_resources.loggers import LogPriority as lp
from src.tests.lib.PylintIface import PylintIface, processFile

from pylint import epylint

dirPkgRoot = '..'
logger = CyLogger()
logger.initializeLogs()

def getRecursiveTree(targetRootDir="."):
    filesList = []
    for root, dirs, files in os.walk(targetRootDir):
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

def genTestData(fileList=[], excludeFiles=[], excludeFromLines=[]):
    test_case_data = []

    #print str(excludeFiles)
    #print str(excludeFromLines)


    if not fileList:
        #print "Cannot generate data from nothing..."
        sys.exit(1)

    pIface = PylintIface(logger)
    for myfile in fileList:
        #print myfile
        #####
        # Don't process files that are in the exclude list
        if myfile in excludeFiles:
            continue
        try:
            if not re.search(".+\.py$", myfile):
                continue
            elif not re.match("__init__.py", myfile):
                jsonData = ""
                #print myfile
                jsonData = processFile(myfile)
                jsonData = pIface.processFile(myfile)
                #print jsonData
                for item in jsonData:
                    if re.match("^error$", item['type']) or re.match("^fatal$", item['type']):
                        #print "Found: " + str(item['type']) + " (" + str(item['line']) + ") : " + str(item['message'])
                        item['message'] = re.sub("'", "", item['message'])
                        #####
                        # Don't include json data that has a string from the
                        # excludeLinesWith exclude list.
                        # that contain a search string in excludeFromLines
                        found = False
                        for searchItem in excludeFromLines:
                            #print searchItem
                            if re.search("%s"%searchItem, item['message']):
                                found = True
                        if not found:
                                test_case_data.append((myfile, item['line'], item['message']))
        except AttributeError:
            pass
    #for data in test_case_data:
    #    print data
    return test_case_data

def pylint_test_template(*args):
    '''decorator for monkeypatching

    :param *args: 

    '''
    def foo(self):
        self.assert_pylint_error(*args)
    return foo


class zzzTestFrameworkTestWithPylint(unittest.TestCase):
    def assert_pylint_error(self, myfile, lineNum, text):
        self.assertTrue(False, myfile + ": (" + str(lineNum) + ") " + text)


class MultipleOptions(Option):
    ACTIONS = Option.ACTIONS + ("extend",)
    STORE_ACTIONS = Option.STORE_ACTIONS + ("extend",)
    TYPED_ACTIONS = Option.TYPED_ACTIONS + ("extend",)
    ALWAYS_TYPED_ACTIONS = Option.ALWAYS_TYPED_ACTIONS + ("extend",)

    def take_action(self, action, dest, opt, value, values, parser):
        if action == "extend":
            lvalue = value.split(",")
            values.ensure_value(dest, []).append(value)
        else:
            Option.take_action(self, action, dest, opt, value, values, parser)


if __name__=="__main__":
    #####
    # Get options
    version="0.8.6.1"
    program_name = __file__
    long_commands = ("exclude_files", "exclude_from_line")
    short_commands = {"exfl" : "exclude_files", "exlw" : "exclude_lines_with"}
    description = "Run the chosen files through pylint and throw unittest errors for each of the error and fatal reports\n"

    parser = OptionParser(option_class=MultipleOptions,
                          usage="usage: %prog [OPTIONS] COMMAND",
                          version="%s, %s"%(program_name, version),
                          description=description)

    parser.add_option("-f", "--do_files",
                      action="extend", type="string",
                      dest="doFiles",
                      default=[],
                      metavar="EXCLUDEFILES",
                      help="comma separated list of file names of files you want checked.  Also can have multiple -f, each with it's own file name string.")

    parser.add_option("-x", "--exclude_files",
                      action="extend", type="string",
                      dest="excludeFiles",
                      metavar="EXCLUDEFILES",
                      default=[],
                      help="comma separated list of strings to use to exclude lint errors.  Also can have multiple -f, each with it's own file name string to exclude.")

    parser.add_option("-l", "--exclude_lines_with",
                      action="extend", type="string",
                      dest="excludeLinesWith",
                      default=[],
                      metavar="EXCLUDELINESWITH",
                      help="comma separated list of strings to use to exclude lint errors.  Also can have multiple -l, each with it's own string to exlude.")

    parser.add_option("-c", "--configuration-file", dest="confFile",
                      default="",
                      help="Acquire command line option values from a coniguration file.")

    parser.add_option("-r", "--recursive-tree", dest="treeRoot",
                      default="",
                      help="The root of a directory to recurse and check all '*.py' files")

    parser.add_option("-d", "--dir-to-check", dest="dirToCheck",
                      default="",
                      help="Name of the directory to look at for '*.py' files (not recursive)")

    parser.add_option("--debug", action="store_true", dest="debug",
                      default=0, help="Print debug messages")

    parser.add_option("-v", "--verbose", action="store_true",
                      dest="verbose", default=0,
                      help="Print status messages")

    if len(sys.argv) < 2:
        parser.parse_args(["--help"])

    (opts, args) = parser.parse_args()
    #print "Arguments: " + str(args)
    #print "Options  : " + str(opts)

    if opts.verbose != 0:
        level = CyLogger(level=lp.INFO)
    elif opts.debug != 0:
        level = CyLogger(level=lp.DEBUG)
    else:
        level=lp.WARNING
    '''
    if opts.doFiles and (opts.excludeLinesWith or opts.excludeFiles):
        print "-f cannot be used with either -x or -l\n"
        parser.parse_args(["--help"])
        sys.exit(0)
    '''

    test_case_data = []
    '''
    print "\n\n"
    print str(opts.doFiles)
    print opts.dirToCheck
    print os.path.abspath(opts.treeRoot)
    print "\n\n"
    '''

    if not opts.treeRoot and not opts.dirToCheck and not opts.doFiles and not opts.confFile:
        print "\n\n\nNeed to choose a file acquisition method.\n\n"
        parser.parse_args(["--help"])
        sys.exit(0)

    if opts.confFile:
        with open(os.path.abspath(opts.confFile)) as confDataFile:
            confFileData = json.load(confDataFile)

            try:
                excludeFiles = confFileData['excludeFiles']
            except ValueError:
                excludeFiles = []

            try:
                doFiles = confFileData['doFiles']
            except ValueError:
                doFiles = []

            try:
                excludeLinesWith = confFileData['excludeLinesWith']
            except ValueError:
                excludeLinesWith = []

            try:
                recursiveTree = confFileData['recursiveTree']
            except ValueError:
                recursiveTree = ""

            try:
                dirToCheck = confFileData['dirToCheck']
            except ValueError:
                dirToCheck = ""

            try:
                if re.match("^True$", confFileData['verbose']):
                    verbose = True
                else:
                    verbose = False
            except ValueError:
                verbose = False

            try:
                if re.match("^True$", confFileData['debug']):
                    debug = True
                else:
                    debug = False
            except ValueError:
                debug = False

            if recursiveTree:
                test_case_data = genTestData(getRecursiveTree(os.path.abspath(recursiveTree)), excludeFiles, excludeLinesWith)
            if dirToCheck:
                test_case_data = test_case_data + genTestData(getDirList(dirToCheck), excludeFiles, excludeLinesWith)
            if doFiles:
                test_case_data = test_case_data + genTestData(doFiles, excludeFiles, excludeLinesWith)

    #####
    # Run unittest per options
    if opts.treeRoot:
        test_case_data = test_case_data + genTestData(getRecursiveTree(os.path.abspath(opts.treeRoot)), opts.excludeFiles, opts.excludeLinesWith)
    if opts.dirToCheck:
        test_case_data = test_case_data + genTestData(getDirList(opts.dirToCheck), opts.excludeFiles, opts.excludeLinesWith)
    if opts.doFiles:
        test_case_data = test_case_data + genTestData(opts.doFiles, opts.excludeFiles, opts.excludeLinesWith)

    #for item in test_case_data:
    #    print item

    #####
    # Initialize the test suite
    test_suite = unittest.TestSuite()

    for specificError in test_case_data:
        #print str(specificError)
        myfile, lineNum, text = specificError
        test_name = "test_with_pylint_{0}_{1}_{2}".format("_".join("_".join(myfile.split("/")).split(".")), lineNum, "_".join("_".join(text.split(" ")).split("'")))
        #print test_name
        error_case = pylint_test_template(*specificError)
        setattr(zzzTestFrameworkTestWithPylint, test_name, error_case)

    test_suite.addTest(unittest.makeSuite(zzzTestFrameworkTestWithPylint))
    runner = unittest.TextTestRunner()
    testResults  = runner.run(test_suite)  # output goes to stderr

else:
    #####
    # Run unittest per current source tree
    test_case_data = genTestData(getRecursiveTree("../../.."))

    for specificError in test_case_data:
        #print str(specificError)
        myfile, lineNum, text = specificError
        test_name = "test_with_pylint_{0}_{1}_{2}".format("_".join("_".join(myfile.split("/")).split(".")), lineNum, "_".join("_".join(text.split(" ")).split("'")))
        #print test_name
        error_case = pylint_test_template(*specificError)
        setattr(zzzTestFrameworkTestWithPylint, test_name, error_case)

