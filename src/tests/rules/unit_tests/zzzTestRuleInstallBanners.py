#!/usr/bin/env python
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


"""
This is a Unit Test for Rule InstallBanners

@author: ekkehard j. koch
@change: 02/27/2013 Original Implementation
@change: 2016/02/10 roy Added sys.path.append for being able to unit test this
                        file as well as with the test harness.
"""



import unittest
import sys
import os

sys.path.append("../../../..")
from src.tests.lib.RuleTestTemplate import RuleTest
from src.stonix_resources.localize import GDMWARNINGBANNER
from src.stonix_resources.localize import GDM3WARNINGBANNER
from src.stonix_resources.localize import ALTWARNINGBANNER
from src.stonix_resources.CommandHelper import CommandHelper
from src.tests.lib.logdispatcher_mock import LogPriority
from src.stonix_resources.rules.InstallBanners import InstallBanners


class zzzTestRuleInstallBanners(RuleTest):

    def setUp(self):
        RuleTest.setUp(self)
        self.rule = InstallBanners(self.config,
                                   self.environ,
                                   self.logdispatch,
                                   self.statechglogger)
        self.rulename = self.rule.rulename
        self.rulenumber = self.rule.rulenumber
        self.ch = CommandHelper(self.logdispatch)
        self.dc = "/usr/bin/defaults"
        self.checkUndo = True

    def tearDown(self):
        pass

    def test_initobjs(self):
        ''' '''

        self.rule.initobjs()

        try:
            self.assertIsNotNone(self.rule.ph)
            self.assertIsNotNone(self.rule.ch)
        except AttributeError:
            pass
        except:
            raise

        self.assertFalse(self.rule.linux)
        self.assertFalse(self.rule.mac)
        self.assertFalse(self.rule.gnome2)
        self.assertFalse(self.rule.gnome3)
        self.assertFalse(self.rule.kde)
        self.assertFalse(self.rule.lightdm)
        self.assertFalse(self.rule.badline)

    def test_setgnome3(self):
        ''' '''

        self.rule.setgnome3()

        self.assertTrue(self.rule.gnome3)
        self.assertEqual(self.rule.gnome3bannertext, GDM3WARNINGBANNER)

    def test_setgnome2(self):
        ''' '''

        self.rule.setgnome2()

        self.assertTrue(self.rule.gnome2)
        self.assertEqual(self.rule.gnome2bannertext, GDMWARNINGBANNER)

    def test_setkde(self):
        ''' '''

        self.rule.setkde()

        self.assertTrue(self.rule.kde)
        self.assertEqual(self.rule.kdebannertext, ALTWARNINGBANNER)

        try:
            self.assertIsNotNone(self.rule.kdeditor)
        except AttributeError:
            pass
        except:
            raise

    def test_setlightdm(self):
        ''' '''

        self.rule.setlightdm()

        self.assertTrue(self.rule.lightdm)
        self.assertEqual(self.rule.ldmbannertext, ALTWARNINGBANNER)

    def test_setcommon(self):
        ''' '''

        self.rule.setcommon()

        try:
            self.assertIsNotNone(self.rule.loginbannerfile)
            self.assertNotEqual(self.rule.loginbannerfile, "")
            self.assertIsNotNone(self.rule.sshdfile)
            self.assertNotEqual(self.rule.sshdfile, "")
        except AttributeError:
            pass
        except:
            raise

    def test_getfilecontents(self):
        ''' '''

        self.assertEqual(self.rule.getFileContents(''), [])
        self.assertEqual(self.rule.getFileContents('', 'unknown'), '')

        try:
            self.assertNotEqual(self.rule.getFileContents(os.path.dirname(os.path.abspath(__file__)) + "/" + __file__), [])
            self.assertIsInstance(self.rule.getFileContents(os.path.dirname(os.path.abspath(__file__)) + "/" + __file__), list)
        except AttributeError:
            pass
        except:
            raise

    def runTest(self):
        self.simpleRuleTest()

    def setConditionsForRule(self):
        '''This makes sure the intial report fails by executing the following
        commands:
        defaults -currentHost delete /Library/Preferences/com.apple.AppleFileServer loginGreeting
        defaults -currentHost delete /Library/Preferences/com.apple.loginwindow LoginWindowText

        :param self: essential if you override this definition
        :returns: boolean - If successful True; If failure False
        @author: ekkehard j. koch

        '''
        success = True
        if self.environ.getosfamily() == "darwin":
            if success:
                command = [self.dc, "-currentHost", "delete",
                           "/Library/Preferences/com.apple.AppleFileServer",
                           "loginGreeting"]
                self.logdispatch.log(LogPriority.DEBUG, str(command))
                success = self.ch.executeCommand(command)
            if success:
                command = [self.dc, "-currentHost", "delete",
                           "/Library/Preferences/com.apple.loginwindow",
                           "LoginWindowText"]
                self.logdispatch.log(LogPriority.DEBUG, str(command))
                success = self.ch.executeCommand(command)
        if success:
            success = self.checkReportForRule(False, True)
        return success


    def checkReportForRule(self, pCompliance, pRuleSuccess):
        '''To see what happended run these commans:
        defaults -currentHost read /Library/Preferences/com.apple.AppleFileServer loginGreeting
        defaults -currentHost read /Library/Preferences/com.apple.loginwindow LoginWindowText

        :param self: essential if you override this definition
        :param pCompliance: 
        :param pRuleSuccess: 
        :returns: boolean - If successful True; If failure False
        @author: ekkehard j. koch

        '''
        self.logdispatch.log(LogPriority.DEBUG, "pCompliance = " +
                             str(pCompliance) + ".")
        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " +
                             str(pRuleSuccess) + ".")
        success = True
        if self.environ.getosfamily() == "darwin":
            if success:
                command = [self.dc, "-currentHost", "read",
                           "/Library/Preferences/com.apple.AppleFileServer",
                           "loginGreeting"]
                self.logdispatch.log(LogPriority.DEBUG, str(command))
                success = self.ch.executeCommand(command)
            if success:
                command = [self.dc, "-currentHost", "read",
                           "/Library/Preferences/com.apple.loginwindow",
                           "LoginWindowText"]
                self.logdispatch.log(LogPriority.DEBUG, str(command))
                success = self.ch.executeCommand(command)
        return success

    def checkFixForRule(self, pRuleSuccess):
        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " +
                             str(pRuleSuccess) + ".")
        success = self.checkReportForRule(True, pRuleSuccess)
        return success

    def checkUndoForRule(self, pRuleSuccess):
        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " +
                             str(pRuleSuccess) + ".")
        success = self.checkReportForRule(False, pRuleSuccess)
        return success

if __name__ == "__main__":
    unittest.main()
