#!/usr/bin/env python3
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
This is a Unit Test for Rule InstallCasper

@author: ekkehard j. koch
@change: 2014-11-24 Original Implementation
@change: 2016-02-08 roy Added sys.path.append for being able to unit test this
                        file as well as with the test harness.
@change: 2016-12-1 eball Made necessary fixes to get unit test to run as part
    of the stonixtest suite
'''

import unittest
import sys
import os
import re
sys.path.append("../../../..")
from src.tests.lib.RuleTestTemplate import RuleTest
from src.stonix_resources.CommandHelper import CommandHelper
from src.stonix_resources.macpkgr import MacPkgr
from src.stonix_resources.rules.InstallCasperSuite import InstallCasperSuite
from src.stonix_resources.Connectivity import Connectivity
from src.tests.lib.logdispatcher_lite import LogPriority


class zzzTestRuleInstallCasperSuite(RuleTest):

    def setUp(self):
        """
        Perform this task before running any of the tests in this class

        @author: Roy Nielsen
        """
        RuleTest.setUp(self)
        self.rule = InstallCasperSuite(self.config, self.environ,
                                       self.logdispatch,
                                       self.statechglogger)
        self.rulename = self.rule.rulename
        self.rulenumber = self.rule.rulenumber
        self.ch = CommandHelper(self.logdispatch)
        self.pkgr = MacPkgr(self.environ, self.logdispatch)
        self.pkgUrl = self.rule.reporoot + self.rule.package
        message = "Reporoot: " + str(self.rule.reporoot)
        self.logdispatch.log(LogPriority.DEBUG, message)
        self.connection = Connectivity(self.logdispatch)

    ###########################################################################

    def tearDown(self):
        pass

    ###########################################################################

    def test_defaultOsInstall(self):
        """
        Test as if testing on a default OS install.  May result initial report
        pass, which would not run Fix mode.

        @author: Roy Nielsen
        """
        #####
        # Ensure the system is set as the default install would be set for this
        # OS
        self.removeJamfFramework()

        #####
        # Run simpleRuleTest
        self.simpleRuleTest()

        #####
        # Validate successful final state
        self.checkForBadInstallation()

    ###########################################################################

    def test_wrongSystemSettings(self):
        """
        Initial state for this test is set up to fail initial report run,
        forcing a fix run.

        @author: Roy Nielsen
        """
        #####
        # Put the system in a known bad state, then run the simpleRuleTest
        self.removeJamfFramework()

        #####
        # Run simpleRuleTest
        self.simpleRuleTest()

        #####
        # Validate successful final state
        self.checkForBadInstallation()

    ###########################################################################

    def test_correctSystemSettigns(self):
        """
        Only report should run.

        @author: Roy Nielsen
        """
        #####
        # Put the system in a known good state, then run the simpleRuleTest

        #####
        # If there is a network connection, install, otherwise just log
        hasconnection = self.connection.isPageAvailable(self.pkgUrl)
        if hasconnection:
            msg = "Connected to " + str(self.rule.package)
            self.logdispatch.log(LogPriority.DEBUG, msg)
            #####
            # Install the package
            if self.pkgr.installPackage(self.rule.package):
                self.rulesuccess = True
                self.rule.touch_imaged()

        #####
        # Run simpleRuleTest
        self.simpleRuleTest()

        #####
        # Validate successful final state
        self.checkForSuccessfullInstallation()

    ###########################################################################

    def test_resultAppend(self):
        """
        Test the unique rule method "resultAppend".

        @author: Roy Nielsen
        """
        #####
        # First test:
        # test the string case
        # self.detailedresults = string
        # passing in string
        self.rule.detailedresults = "Snow season looks good this year..."
        string_to_append = "The End"
        self.rule.resultAppend("The End")
        self.logdispatch.log(LogPriority.DEBUG, "results: " +
                             str(self.rule.detailedresults))
        self.assertTrue(re.search("%s" % string_to_append,
                                  self.rule.detailedresults))

        #####
        # second test:
        # test the first list case
        # self.detailedresults = list
        # passing in string
        self.rule.detailedresults = ["Snow season looks good this year..."]
        string_to_append = "The End"

        #####
        #####
        # Note here - we're not testing right, but the code passes test.
        # assertRasis isn't the right assert to be using
        self.assertRaises(TypeError, self.rule.resultAppend, string_to_append)

        #####
        # Third test:
        # test the second list case
        # self.detailedresults = list
        # passing in list
        self.rule.detailedresults = ["Snow season looks good this year..."]
        list_to_append = ["The End"]

        #####
        #####
        # Note here - we're not testing right, but the code passes test.
        # assertRasis isn't the right assert to be using
        self.assertRaises(TypeError, self.rule.resultAppend, list_to_append)

        #####
        # fourth test:
        # test the first "else" case
        # self.detailedresults = string
        # passing in boolean
        self.rule.detailedresults = "Snow season looks good this year..."

        #####
        #####
        # Note - assertRaises is being correctly used here
        self.assertRaises(TypeError, self.rule.resultAppend, False)

        #####
        # fifth test:
        # test the second "else" case
        # self.detailedresults = list
        # passing in False
        self.rule.detailedresults = ["Snow season looks good this year..."]

        #####
        #####
        # Note - assertRaises is being correctly used here
        self.assertRaises(TypeError, self.rule.resultAppend, False)

        #####
        # sixth test:
        # test the first "else" case
        # self.detailedresults = string
        # passing in None
        self.rule.detailedresults = "Snow season looks good this year..."

        #####
        #####
        # Note - assertRaises is being correctly used here
        self.assertRaises(TypeError, self.rule.resultAppend, None)

        #####
        # seventh test:
        # test the second "else" case
        # self.detailedresults = list
        # passing in None
        self.rule.detailedresults = ["Snow season looks good this year..."]

        #####
        #####
        # Note - assertRaises is being correctly used here
        self.assertRaises(TypeError, self.rule.resultAppend, None)

        #####
        #####
        # Note, we are not testing the passing in of every python type...
        # Be careful when choosing a representative selection of tests,
        # as critical tests might be missed.
        #
        # In this case, if another valid case is found, a test can be added
        # that will test that specific case, or class of cases.
        #
        # Testing is an iterative process.
        #

    ###########################################################################

    def test_touch_imaged(self):
        """
        Test the unique rule method "touch_imaged".

        The touched_imaged method is not dependent of any other methods, so it
        can be tested atomically.

        @author: Roy Nielsen
        """
        sig1 = "/etc/dds.txt"
        sig2 = "/var/log/dds.log"

        #####
        # Check for the existence of the first signature file, remove it if it
        # exists
        if os.path.exists(sig1):

            os.unlink(sig1)

            foundSig1 = True
        else:
            foundSig1 = False

        #####
        # Check for the existence of the second signature file, remove it if it
        # exists
        if os.path.exists(sig2):
            os.unlink(sig2)
            foundSig2 = True
        else:
            foundSig2 = False

        #####
        # Call the method
        self.rule.touch_imaged()

        #####
        # Check for the first file system signature
        success_a = os.path.isfile("/etc/dds.txt")
        self.logdispatch.log(LogPriority.DEBUG,
                             "Found first signature file...")
        self.assertTrue(success_a)

        #####
        # Check for the Second file system signature
        success_b = os.path.isfile("/var/log/dds.log")
        self.logdispatch.log(LogPriority.DEBUG,
                             "Found second signature file..")
        self.assertTrue(success_b)

        self.assertTrue(success_a and success_b)

        #####
        # If the files didn't exist at the beginning of the test, remove them.
        if not foundSig1:
            os.unlink(sig1)
        if not foundSig2:
            os.unlink(sig2)

    ###########################################################################

    def checkForSuccessfullInstallation(self):
        """
        Check for successfull test run.  Specifically what needs to have
        happened after a successfull run.  IE: must satisfy ALL conditions.

        @author: Roy Nielsen
        """
        #####
        # Check for existence of jamf binary
        success = os.path.isfile("/usr/local/bin/jamf")
        self.logdispatch.log(LogPriority.DEBUG, "Found the jamf binary..")
        self.assertTrue(success)

        #####
        # Check for the existence of the LANL Self Service.app
        success = os.path.isdir("/Applications/LANL Self Service.app")
        self.logdispatch.log(LogPriority.DEBUG, "Found result: " +
                                                str(success) +
                                                " Lanl Self Service.app")
        self.assertTrue(success)

        #####
        # Check for the first file system signature
        success = os.path.isfile("/etc/dds.txt")
        self.logdispatch.log(LogPriority.DEBUG, "Found first sig file...")
        self.assertTrue(success)

        #####
        # Check for the Second file system signature
        success = os.path.isfile("/var/log/dds.log")
        self.logdispatch.log(LogPriority.DEBUG, "Found second sig file...")
        self.assertTrue(success)

        #####
        # Check to make sure the "jamf recon" command works
        cmd = ["/usr/local/bin/jamf", "recon"]
        self.ch.executeCommand(cmd)
        return_code = self.ch.getReturnCode()
        self.logdispatch.log(LogPriority.DEBUG, "Return code from jamf " +
                                                " recon command: " +
                                                str(return_code))
        self.assertEqual(str(0), str(return_code))

    ###########################################################################

    def checkForBadInstallation(self):
        """
        Check for UNsuccessfull test run.  IE: must fail any of the following
        conditions.  Needs fuzzing applied, or variation on inputs to prove
        the variation works as expected.

        @Note: Running of the "/usr/local/bin/jamf recon" command is not
               executed in this test, as that functionality has already been
               tested.  The other variables need to be "fuzzed". IE, run
               every combination of the variables tested in this test.

        @author: Roy Nielsen
        """

        #####
        # Check if any of the following are false.  At least one must be false.
        success_a = os.path.isfile("/usr/local/bin/jamf")
        success_b = os.path.isdir("/Applications/LANL Self Service.app")
        success_c = os.path.isfile("/etc/dds.txt")
        success_d = os.path.isfile("/var/log/dds.log")

        #####
        # If any of these success parameters are false, the test fails
        self.assertTrue(success_a and success_b and success_c and success_d,
                        "Could not find all files and directories " +
                        "associated with a successful Casper installation")

        #####
        # Future testing needs to perform "fuzzing" - automated or auto
        # generated input testing
        # --
        # for every combination of inputs assert the correct outputs
        #
        # - at least one case is missing in this method - making sure to also
        #   test for the existence of the Jamf plist.
        #

    ###########################################################################

    def setConditionsForRule(self):
        '''Configure system for the unit test

        :param self: essential if you override this definition
        :returns: boolean - If successful True; If failure False
        @author: ekkehard j. koch

        '''
        success = True
        return success

    ###########################################################################

    def checkReportForRule(self, pCompliance, pRuleSuccess):
        '''check on whether report was correct

        :param self: essential if you override this definition
        :param pCompliance: the self.iscompliant value of rule
        :param pRuleSuccess: did report run successfully
        :returns: boolean - If successful True; If failure False
        @author: ekkehard j. koch

        '''
        self.logdispatch.log(LogPriority.DEBUG, "pCompliance = " +
                             str(pCompliance) + ".")
        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " +
                             str(pRuleSuccess) + ".")

        success = True
        return success

    ###########################################################################

    def checkFixForRule(self, pRuleSuccess):
        '''check on whether fix was correct

        :param self: essential if you override this definition
        :param pRuleSuccess: did report run successfully
        :returns: boolean - If successful True; If failure False
        @author: ekkehard j. koch

        '''
        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " +
                             str(pRuleSuccess) + ".")

        if pRuleSuccess:
            success = True
        else:
            success = False

        return success

    ###########################################################################

    def checkUndoForRule(self, pRuleSuccess):
        '''check on whether undo was correct

        :param self: essential if you override this definition
        :param pRuleSuccess: did report run successfully
        :returns: boolean - If successful True; If failure False
        @author: ekkehard j. koch

        '''
        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " +
                             str(pRuleSuccess) + ".")

        if pRuleSuccess:
            success = True
        else:
            success = False

        return success

    ###########################################################################

    def removeJamfFramework(self):
        """
        Remove the jamf framework for setting initial conditions..

        @NOTE: There are many ways that a jamf install can be broken,
               This tests a clean uninstall.  Partial or broken installs
               are not covered in this test, however it may be a good idea
               to test for this in the future.

        @author: Roy Nielsen
        """
        success = False
        jamf_path = "/usr/local/bin/jamf"
        if os.path.exists(jamf_path):
            cmd = [jamf_path, "removeFramework"]

            self.ch.executeCommand(cmd)

            output = self.ch.getOutputString().split("\n")
            self.logdispatch.log(LogPriority.DEBUG, output)

            if self.ch.getReturnCode() == 0:
                success = True
        else:
            success = True
        return success

###############################################################################

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
