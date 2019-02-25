###############################################################################
#                                                                             #
# Copyright 2015-2019.  Los Alamos National Security, LLC. This material was       #
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
from __future__ import absolute_import
from src.stonix_resources.configuration import Configuration
from src.stonix_resources.environment import Environment
from src.stonix_resources.StateChgLogger import StateChgLogger
from src.tests.lib.logdispatcher_lite import LogDispatcher, LogPriority
import os
import unittest


class RuleTest(unittest.TestCase):

    def setUp(self):
        '''
        Setup what we need for the test.
        @author: ekkehard j. koch
        @param self:essential if you override this definition
        '''
        self.environ = Environment()
        self.environ.setverbosemode(True)
        self.environ.setdebugmode(True)
        self.config = Configuration(self.environ)
        self.logdispatch = LogDispatcher(self.environ)
        self.statechglogger = StateChgLogger(self.logdispatch, self.environ)
        self.rule = None
        self.rulename = ""
        self.rulenumber = ""
        self.checkUndo = False
        self.ignoreresults = False

###############################################################################

    def tearDown(self):
        '''
        Release anything we no longer need what we need for the test.
        @author: ekkehard j. koch
        @param self:essential if you override this definition
        '''
        pass

###############################################################################

    def simpleRuleTest(self):
        '''
        Run a simple Report, Fix, Report Cycle
        @author: ekkehard j. koch
        @param self:essential if you override this definition
        '''
        nextstep = True
        prefixHeadline = "################################################### "
        prefixRuleInfo = self.rulename + "(" + str(self.rulenumber) + "): "
        messagestring = ""
# Make Rule Is supposed to run in this environment
        if nextstep:
            messagestring = "Make sure Rule Is supposed to run in this " + \
                "environment"
            self.logdispatch.log(LogPriority.DEBUG, prefixHeadline +
                                 prefixRuleInfo + messagestring)
            isapplicable = self.rule.isapplicable()
            messagestring = "rule.isapplicable() = " + str(isapplicable)
            self.logdispatch.log(LogPriority.DEBUG, prefixRuleInfo +
                                 messagestring)
            valueIsInList = isapplicable in [True, False]
            messagestring = "Invalid isapplicable Type!"
            self.assertTrue(valueIsInList, prefixRuleInfo +
                            messagestring)
            messagestring = "rule.isapplicable() = " + str(isapplicable) + \
                " and should be True."
            self.assertTrue(isapplicable, prefixRuleInfo +
                            messagestring)
            nextstep = isapplicable
# Check to see if we are running in the right context
        if nextstep:
            messagestring = "Check to see if we are running in the " + \
                "right context"
            self.logdispatch.log(LogPriority.DEBUG, prefixHeadline +
                                 prefixRuleInfo + messagestring)
            effectiveUserID = self.environ.geteuid()
            messagestring = "environ.geteuid() = " + str(effectiveUserID)
            self.logdispatch.log(LogPriority.DEBUG, prefixRuleInfo +
                                 messagestring)
            isRootRequired = self.rule.getisrootrequired()
            messagestring = "rule.getisrootrequired() = " + str(isRootRequired)
            self.logdispatch.log(LogPriority.DEBUG, prefixRuleInfo +
                                 messagestring)
            if effectiveUserID == 0 and isRootRequired:
                nextstep = True
            elif not isRootRequired:
                nextstep = True
            else:
                nextstep = False
            messagestring = "Rule requires root and effective uid ='" + \
                str(effectiveUserID) + "'"
            self.assertTrue(nextstep, prefixRuleInfo +
                            messagestring)
# Run setConditionsForRule to configure system for test
        if nextstep:
            messagestring = "Run setConditionsForRule to configure " + \
                "system for test"
            self.logdispatch.log(LogPriority.DEBUG, prefixHeadline +
                                 prefixRuleInfo + messagestring)
            setTestConditions = self.setConditionsForRule()
            self.logdispatch.log(LogPriority.DEBUG,
                                 "setConditionsForRule()" +
                                 " = " + str(setTestConditions))
            if setTestConditions:
                nextstep = True
            else:
                nextstep = False
            messagestring = "setConditionsForRule() = " + \
                str(setTestConditions) + "."
            self.assertTrue(setTestConditions, prefixRuleInfo +
                            messagestring)
# Run rule.report()
        if nextstep:
            messagestring = "Run rule.report()"
            self.logdispatch.log(LogPriority.DEBUG, prefixHeadline +
                                 prefixRuleInfo + messagestring)
            report = self.rule.report()
            self.logdispatch.log(LogPriority.DEBUG, "rule.report() = " +
                                 str(report))
            rulesuccess = self.rule.getrulesuccess()
            originalResults = self.rule.getdetailedresults()
            self.logdispatch.log(LogPriority.DEBUG, "rule.getrulesuccess() = "
                                 + str(rulesuccess))
            valueIsInList = rulesuccess in [True, False]
            messagestring = "Invalid rule.getrulesuccess() Value'" + \
                str(rulesuccess) + "'!"
            self.assertTrue(valueIsInList, prefixRuleInfo + messagestring)
            if not rulesuccess:
                nextstep = False
            messagestring = ": rule.getrulesuccess() is '" + \
                str(rulesuccess) + "'"
            self.assertTrue(rulesuccess, prefixRuleInfo + messagestring)
            rulecompliance = self.rule.iscompliant()
            self.logdispatch.log(LogPriority.DEBUG, "rule.iscompliant() = " +
                                 str(rulecompliance))
            valueIsInList = rulecompliance in [True, False]
            messagestring = "Invalid rule.iscompliant() Value'" + \
                str(rulecompliance) + "'!"
            self.assertTrue(valueIsInList, prefixRuleInfo + messagestring)
# Run checkReportForRule()
            messagestring = "Run checkReportForRule(" + str(rulecompliance) + \
                ", " + str(rulesuccess) + ")"
            self.logdispatch.log(LogPriority.DEBUG, prefixHeadline +
                                 prefixRuleInfo + messagestring)
            checkReportConditions = self.checkReportForRule(rulecompliance,
                                                            rulesuccess)
            self.logdispatch.log(LogPriority.DEBUG,
                                 "checkReportForRule() = " +
                                 str(checkReportConditions))
            if checkReportConditions and not rulecompliance:
                nextstep = True
            else:
                nextstep = False
            messagestring = ": Rule checkReportForRule() = " + \
                str(checkReportConditions) + "."

            self.assertTrue(checkReportConditions,
                            self.rulename + "(" + str(self.rulenumber) +
                            "): Rule checkReportForRule() = " +
                            str(checkReportConditions) + ".")
# Run rule.fix()
        if nextstep:
            messagestring = "Run rule.fix()"
            self.logdispatch.log(LogPriority.DEBUG, prefixHeadline +
                                 prefixRuleInfo + messagestring)
            fix = self.rule.fix()
            self.logdispatch.log(LogPriority.DEBUG, "rule.fix() = " +
                                 str(fix))
            rulesuccess = self.rule.getrulesuccess()
            self.logdispatch.log(LogPriority.DEBUG, "rule.getrulesuccess() = "
                                 + str(rulesuccess))
            valueIsInList = rulesuccess in [True, False]
            messagestring = "Invalid rule.rulesuccess() Value'" + \
                str(rulesuccess) + "'!"
            self.assertTrue(valueIsInList, prefixRuleInfo + messagestring)
            messagestring = "rule.getrulesuccess() = '" + \
                str(rulesuccess) + "'"
            self.assertTrue(rulesuccess, prefixRuleInfo + messagestring)
# Run checkFixForRule()
            messagestring = "Run checkFixForRule(" + str(rulesuccess) + ")"
            self.logdispatch.log(LogPriority.DEBUG, prefixHeadline +
                                 prefixRuleInfo + messagestring)
            checkFixConditions = self.checkFixForRule(rulesuccess)
            self.logdispatch.log(LogPriority.DEBUG,
                                 "checkFixForRule(" + str(rulesuccess) +
                                 ")" + " = " +
                                 str(checkFixConditions))
            if checkFixConditions and rulesuccess:
                nextstep = True
            else:
                nextstep = False
            messagestring = "Rule checkFixForRule() = " + \
                            str(checkFixConditions) + "."
            self.assertTrue(nextstep, prefixRuleInfo + messagestring)
# Run rule.report()
        if nextstep:
            messagestring = "Run rule.report()"
            self.logdispatch.log(LogPriority.DEBUG, prefixHeadline +
                                 prefixRuleInfo + messagestring)
            report = self.rule.report()
            self.logdispatch.log(LogPriority.DEBUG, "rule.report() = " +
                                 str(report))
            rulesuccess = self.rule.getrulesuccess()
            self.logdispatch.log(LogPriority.DEBUG,
                                 "rule.getrulesuccess() = " +
                                 str(rulesuccess))
            valueIsInList = rulesuccess in [True, False]
            messagestring = "Invalid rule.getrulesuccess() Value'" + \
                str(rulesuccess) + "'!"
            self.assertTrue(valueIsInList, prefixRuleInfo + messagestring)
            if not rulesuccess:
                nextstep = False
            self.assertTrue(rulesuccess,
                            self.rulename + "(" + str(self.rulenumber) +
                            "): rule.getrulesuccess() is '" +
                            str(rulesuccess) + "' with reported error '" +
                            str(self.rule.getdetailedresults()) + "'")
            rulecompliance = self.rule.iscompliant()
            self.logdispatch.log(LogPriority.DEBUG, "rule.iscompliant() = " +
                                 str(rulecompliance))
            valueIsInList = rulecompliance in [True, False]
            messagestring = "Invalid rule.iscompliant() Value'" + \
                str(rulecompliance) + "'!"
            self.assertTrue(valueIsInList, prefixRuleInfo + messagestring)

            messagestring = "rule.iscompliant() is '" + \
                str(rulecompliance) + "' after rule.fix() and " + \
                "rule.report() have run."
            if not self.ignoreresults:
                self.assertTrue(rulecompliance, prefixRuleInfo + messagestring)
# Run checkReportFinalForRule()
            messagestring = "Run checkReportFinalForRule(" + \
                str(rulecompliance) + ", " + str(rulesuccess) + ")"
            self.logdispatch.log(LogPriority.DEBUG, prefixHeadline +
                                 prefixRuleInfo + messagestring)
            checkReportFinalConditions = self.checkReportFinalForRule(rulecompliance,
                                                                      rulesuccess)
            self.logdispatch.log(LogPriority.DEBUG,
                                 "checkReportFinalForRule() = " +
                                 str(checkReportFinalConditions))
            if checkReportFinalConditions and rulecompliance:
                nextstep = True
            else:
                nextstep = False

            self.assertTrue(checkReportFinalConditions,
                            self.rulename + "(" + str(self.rulenumber) +
                            "): Rule checkReportFinalForRule() = " +
                            str(checkReportFinalConditions) + ".")
# Run rule.undo()
        if nextstep and self.checkUndo:
            messagestring = "Run rule.undo()"
            self.logdispatch.log(LogPriority.DEBUG, prefixHeadline +
                                 prefixRuleInfo + messagestring)
            undo = self.rule.undo()
            self.logdispatch.log(LogPriority.DEBUG, "rule.undo() = " +
                                 str(undo))
            self.rule.report()
            postUndoResults = self.rule.getdetailedresults()
            # In order to get detailed, well-formatted error information, this
            # has been turned into a short procedure to produce the most
            # helpful information, rather than simply using the assert
            # statement
            if originalResults != postUndoResults:
                orlines = originalResults.splitlines()
                pulines = postUndoResults.splitlines()
                orlinestmp = orlines[:]  # [:] to copy by value r/t reference
                for line in orlinestmp:
                    if line in pulines:
                        orlines.remove(line)
                        pulines.remove(line)
                error = "After undo, the report results were not the same " + \
                    "as the initial pre-fix report."
                if orlines:
                    error += "\nOnly in original:\n" + "\n".join(orlines)
                if pulines:
                    error += "\nOnly in post-undo:\n" + "\n".join(pulines)
                self.assertTrue(False, error)
# Run checkUndoForRule()
            messagestring = "Run checkUndoForRule(" + str(rulesuccess) + ")"
            self.logdispatch.log(LogPriority.DEBUG, prefixHeadline +
                                 prefixRuleInfo + messagestring)
            checkUndoConditions = self.checkUndoForRule(rulesuccess)
            self.logdispatch.log(LogPriority.DEBUG,
                                 "checkUndoForRule()" +
                                 " = " + str(checkUndoConditions))
            if checkUndoConditions and not rulecompliance:
                nextstep = True
            else:
                nextstep = False

            self.assertTrue(checkUndoConditions,
                            self.rulename + "(" + str(self.rulenumber) +
                            "): Rule checkUndoForRule() = " +
                            str(checkUndoConditions) + ".")

        return nextstep

###############################################################################

    def setConditionsForRule(self):
        return True

###############################################################################

    def checkReportForRule(self, pCompliance, pRuleSuccess):
        self.logdispatch.log(LogPriority.DEBUG, "pCompliance = " +
                             str(pCompliance) + ".")
        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " +
                             str(pRuleSuccess) + ".")
        return True

###############################################################################

    def checkFixForRule(self, pRuleSuccess):
        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " +
                             str(pRuleSuccess) + ".")
        return True

###############################################################################

    def checkReportFinalForRule(self, pCompliance, pRuleSuccess):
        self.logdispatch.log(LogPriority.DEBUG, "pCompliance = " +
                             str(pCompliance) + ".")
        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " +
                             str(pRuleSuccess) + ".")
        return True

###############################################################################

    def checkUndoForRule(self, pRuleSuccess):
        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " +
                             str(pRuleSuccess) + ".")
        return True

###############################################################################

    def setCheckUndo(self, checkUndo):
        self.checkUndo = checkUndo

###############################################################################

    def getCheckUndo(self):
        return self.checkUndo

###############################################################################

    def runDestructive(self):
        return os.path.exists("/etc/stonix-destructive")

###############################################################################

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
