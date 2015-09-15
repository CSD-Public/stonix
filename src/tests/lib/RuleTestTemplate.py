from __future__ import absolute_import
from src.stonix_resources.configuration import Configuration
from src.stonix_resources.environment import Environment
from src.stonix_resources.StateChgLogger import StateChgLogger
from src.tests.lib.logdispatcher_lite import LogDispatcher, LogPriority
import unittest


class RuleTest(unittest.TestCase):

###############################################################################

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
            self.logdispatch.log(LogPriority.DEBUG, prefixHeadline + \
                                 prefixRuleInfo + messagestring)
            isapplicable = self.rule.isapplicable()
            messagestring = "rule.isapplicable() = " + str(isapplicable)
            self.logdispatch.log(LogPriority.DEBUG, prefixRuleInfo + \
                                 messagestring)
            valueIsInList = isapplicable in [True, False]
            messagestring = "Invalid isapplicable Type!"
            self.assertTrue(valueIsInList, prefixRuleInfo + \
                          messagestring)
            messagestring = "rule.isapplicable() = " + str(isapplicable) + \
            " and should be True."
            self.assertTrue(isapplicable, prefixRuleInfo + \
                          messagestring)
            nextstep = isapplicable
# Check to see if we are running in the right context
        if nextstep:
            messagestring = "Check to see if we are running in the " + \
            "right context"
            self.logdispatch.log(LogPriority.DEBUG, prefixHeadline + \
                                 prefixRuleInfo + messagestring)
            effectiveUserID = self.environ.geteuid()
            messagestring = "environ.geteuid() = " + str(effectiveUserID)
            self.logdispatch.log(LogPriority.DEBUG, prefixRuleInfo + \
                                 messagestring)
            isRootRequired = self.rule.getisrootrequired()
            messagestring = "rule.getisrootrequired() = " + str(isRootRequired)
            self.logdispatch.log(LogPriority.DEBUG, prefixRuleInfo + \
                                 messagestring)
            if effectiveUserID == 0 and isRootRequired:
                nextstep = True
            elif not isRootRequired:
                nextstep = True
            else:
                nextstep = False
            messagestring = "Rule requires root and effective uid ='" + \
            str(effectiveUserID) + "'"
            self.assertTrue(nextstep, prefixRuleInfo + \
                          messagestring)
# Run setConditionsForRule to configure system for test
        if nextstep:
            messagestring = "Run setConditionsForRule to configure " + \
            "system for test"
            self.logdispatch.log(LogPriority.DEBUG, prefixHeadline + \
                                 prefixRuleInfo + messagestring)
            setTestConditions = self.setConditionsForRule()
            self.logdispatch.log(LogPriority.DEBUG,
                                 "setConditionsForRule()" + \
                                 " = " + \
                                 str(setTestConditions))
            if setTestConditions:
                nextstep = True
            else:
                nextstep = False
            messagestring = "setConditionsForRule() = " + \
            str(setTestConditions) + "."
            self.assertTrue(setTestConditions, prefixRuleInfo + \
                          messagestring)
# Run rule.report()
        if nextstep:
            messagestring = "Run rule.report()"
            self.logdispatch.log(LogPriority.DEBUG, prefixHeadline + \
                                 prefixRuleInfo + messagestring)
            report = self.rule.report()
            self.logdispatch.log(LogPriority.DEBUG, "rule.report() = " + \
                                 str(report))
            rulesuccess = self.rule.getrulesuccess()
            self.logdispatch.log(LogPriority.DEBUG, "rule.getrulesuccess() = " + \
                                 str(rulesuccess))
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
            self.logdispatch.log(LogPriority.DEBUG, "rule.iscompliant() = " + \
                                 str(rulecompliance))
            valueIsInList = rulecompliance in [True, False]
            messagestring = "Invalid rule.iscompliant() Value'" + \
            str(rulecompliance) + "'!"
            self.assertTrue(valueIsInList, prefixRuleInfo + messagestring)
# Run checkReportForRule()
            messagestring = "Run checkReportForRule(" + str(rulecompliance) + \
            ", " + str(rulesuccess) + ")"
            self.logdispatch.log(LogPriority.DEBUG, prefixHeadline + \
                                 prefixRuleInfo + messagestring)
            checkReportConditions = self.checkReportForRule(rulecompliance,
                                                            rulesuccess)
            self.logdispatch.log(LogPriority.DEBUG,
                                 "checkReportForRule()" + \
                                 " = " + \
                                 str(checkReportConditions))
            if checkReportConditions and not rulecompliance:
                nextstep = True
            else:
                nextstep = False
            messagestring = ": Rule checkReportForRule() = " + \
            str(checkReportConditions) + "."
            self.assertTrue(checkReportConditions, prefixRuleInfo + \
                            messagestring)
            self.assertTrue(checkReportConditions,
                            self.rulename + "(" + str(self.rulenumber) + ")" +
                            ": Rule " + \
                            "checkReportForRule() = " + \
                            str(checkReportConditions) + ".")
# Run rule.fix()
        if nextstep:
            messagestring = "Run rule.fix()"
            self.logdispatch.log(LogPriority.DEBUG, prefixHeadline + \
                                 prefixRuleInfo + messagestring)
            fix = self.rule.fix()
            self.logdispatch.log(LogPriority.DEBUG, "rule.fix() = " + \
                                 str(fix))
            rulesuccess = self.rule.getrulesuccess()
            self.logdispatch.log(LogPriority.DEBUG, "rule.getrulesuccess() = " + \
                                 str(rulesuccess))
            valueIsInList = rulesuccess in [True, False]
            messagestring = "Invalid rule.rulesuccess() Value'" + \
            str(rulesuccess) + "'!"
            self.assertTrue(valueIsInList, prefixRuleInfo + messagestring)
            messagestring = "rule.getrulesuccess() = '" + \
            str(rulesuccess) + "'"
            self.assertTrue(rulesuccess, prefixRuleInfo + messagestring)
# Run checkFixForRule()
            messagestring = "Run checkFixForRule(" + str(rulesuccess) + ")"
            self.logdispatch.log(LogPriority.DEBUG, prefixHeadline + \
                                 prefixRuleInfo + messagestring)
            checkFixConditions = self.checkFixForRule(rulesuccess)
            self.logdispatch.log(LogPriority.DEBUG,
                                 "checkFixForRule(" + str(rulesuccess) + \
                                 ")" + " = " + \
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
            self.logdispatch.log(LogPriority.DEBUG, prefixHeadline + \
                                 prefixRuleInfo + messagestring)
            report = self.rule.report()
            self.logdispatch.log(LogPriority.DEBUG, "rule.report() = " + \
                                 str(report))
            rulesuccess = self.rule.getrulesuccess()
            self.logdispatch.log(LogPriority.DEBUG,
                                 "rule.getrulesuccess() = " + \
                                 str(rulesuccess))
            valueIsInList = rulesuccess in [True, False]
            messagestring = "Invalid rule.getrulesuccess() Value'" + \
            str(rulesuccess) + "'!"
            self.assertTrue(valueIsInList, prefixRuleInfo + messagestring)
            if not rulesuccess:
                nextstep = False
            self.assertTrue(rulesuccess,
                            self.rulename + "(" + str(self.rulenumber) + ")" +
                            ": rule.getrulesuccess() is '" + \
                            str(rulesuccess) + "' with reported error '" + \
                            str(self.rule.getdetailedresults()))
            rulecompliance = self.rule.iscompliant()
            self.logdispatch.log(LogPriority.DEBUG, "rule.iscompliant() = " + \
                                 str(rulecompliance))
            valueIsInList = rulecompliance in [True, False]
            messagestring = "Invalid rule.iscompliant() Value'" + \
            str(rulecompliance) + "'!"
            self.assertTrue(valueIsInList, prefixRuleInfo + messagestring)

            messagestring = "rule.iscompliant() is '" + \
            str(rulecompliance) + "' after rule.fix() and rule.report() " + \
            "have run."
            self.assertTrue(rulecompliance, prefixRuleInfo + messagestring)
            if rulecompliance:
                nextstep = False

        return nextstep

###############################################################################

    def setConditionsForRule(self):
        return True

###############################################################################

    def checkReportForRule(self, pCompliance, pRuleSuccess):
        self.logdispatch.log(LogPriority.DEBUG, "pCompliance = " + \
                             str(pCompliance) + ".")
        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " + \
                             str(pRuleSuccess) + ".")
        return True

###############################################################################

    def checkFixForRule(self, pRuleSuccess):
        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " + \
                             str(pRuleSuccess) + ".")
        return True

###############################################################################

    def checkUndoForRule(self, pRuleSuccess):
        self.logdispatch.log(LogPriority.DEBUG, "pRuleSuccess = " + \
                             str(pRuleSuccess) + ".")
        return True

###############################################################################

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
