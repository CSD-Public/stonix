#!/usr/bin/env python

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

# ============================================================================#
#               Filename          $RCSfile: stonix/rule.py,v $
#               Description       Security Configuration Script
#               OS                Linux, Mac OS X, Solaris, BSD
#               Author            Dave Kennel
#               Last updated by   $Author: $
#               Notes             Based on CIS Benchmarks, NSA RHEL
#                                 Guidelines, NIST and DISA STIG/Checklist
#               Release           $Revision: 1.0 $
#               Modified Date     $Date: 2012/06/26 14:00:00 $
# ============================================================================#
'''
Created on Aug 24, 2010

@author: dkennel
@change: eball 2015/07/08 - Added pkghelper and ServiceHelper undos
'''

from observable import Observable
from configurationitem import ConfigurationItem
from logdispatcher import LogPriority
from isapplicable import ApplicableCheck
from types import *
import os
import re
from distutils.version import LooseVersion

from stonixutilityfunctions import isServerVersionHigher
from subprocess import call
from localize import DRINITIAL
from localize import DRREPORTCOMPIANT, DRREPORTNOTCOMPIANT, DRREPORTNOTAVAILABLE
from localize import DRFIXSUCCESSFUL, DRFIXFAILED, DRFIXNOTAVAILABLE
from localize import DRUNDOSUCCESSFUL, DRUNDOFAILED, DRUNDONOTAVAILABLE
from CommandHelper import CommandHelper
from pkghelper import Pkghelper
from ServiceHelper import ServiceHelper
import traceback


class Rule (Observable, ApplicableCheck):

    """
    Abstract class for all Rule objects.
    :version: 1.0
    :author: D. Kennel
    """

    def __init__(self, config, environ, logger, statechglogger):
        Observable.__init__(self)
        ApplicableCheck.__init__(self)
        self.config = config
        self.environ = environ
        self.statechglogger = statechglogger
        self.logdispatch = logger
        self.rulenumber = 0
        self.rulename = 'template class'
        self.mandatory = False
        self.helptext = """This is the default help text for the base rule
class. If you are seeing this text it is because the developer for one of the
rules forgot to assign the appropriate help text. Please file a bug against
LANL-stonix."""
        self.executionpriority = 50
        self.rootrequired = True
        self.configinsimple = False
        self.detailedresults = """This is the default detailed results text
        for the base rule class. If you are seeing this text it is because the
        developer for one of the rules forgot to assign the appropriate text.
        Please file a bug against stonix."""
        self.compliant = False
        self.rulesuccess = True
        self.databaserule = False
        self.applicable = {'default': 'default'}
        self.revertable = False
        self.confitems = []
        self.currstate = "notconfigured"
        self.targetstate = "configured"
        self.guidance = []

    def fix(self):
        """
        The fix method will apply the required settings to the system.
        self.rulesuccess will be updated if the rule does not succeed.

        @author
        """
# This must be implemented later once the parameter option or observable
# pattern for taking control of self.detailedresults refresh is implemented
# see artf30937 : self.detailedresults through application flow for details
        # self.formatDetailedResults("fix", None)
        # self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        pass

    def report(self):
        """
        The report method examines the current configuration and determines
        whether or not it is correct. If the config is correct then the
        self.compliant, self.detailed results and self.currstate properties are
        updated to reflect the system status. self.rulesuccess will be updated
        if the rule does not succeed.

        @author D. Kennel
        """
# This must be implemented later once the parameter option or observable
# pattern for taking control of self.detailedresults refresh is implemented
# see artf30937 : self.detailedresults through application flow for details
        # self.formatDetailedResults("fix", None)
        # self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        pass

    def undo(self):
        """
        Undo changes made by this rule. Some rules may not be undone.
        self.rulesuccess will be updated if the rule does not succeed.

        @author D. Kennel & D. Walker
        """
        # pass
        if not self.environ.geteuid() == 0:
            self.detailedresults = "Root access required to revert changes."
            self.formatDetailedResults("undo", None, self.detailedresults)
        try:
# This must be implemented later once the parameter option or observable
# pattern for taking control of self.detailedresults refresh is implemented
# see artf30937 : self.detailedresults through application flow for details
            self.detailedresults = ""
            undosuccessful = True
            eventlist = self.statechglogger.findrulechanges(self.rulenumber)
            if not eventlist:
                self.formatDetailedResults("undo", None, self.detailedresults)
                self.logdispatch.log(LogPriority.INFO, self.detailedresults)
                return undosuccessful
            #eventlist.reverse()
            for entry in eventlist:
                try:
                    event = self.statechglogger.getchgevent(entry)
                    if event["eventtype"] == "perm":
                        perms = event["startstate"]
                        os.chmod(event["filepath"], perms[2])
                        os.chown(event["filepath"], perms[0], perms[1])

                    elif event["eventtype"] == "conf":
                        self.statechglogger.revertfilechanges(event["filepath"],
                                                              entry)

                    elif event["eventtype"] == "comm" or \
                         event["eventtype"] == "commandstring":
                        ch = CommandHelper(self.logdispatch)
                        command = event["command"]
                        ch.executeCommand(command)
                        if ch.getReturnCode() != 0:
                            self.detailedresults = "Couldn't run the " + \
                                "command to undo\n"
                            self.logdispatch.log(LogPriority.DEBUG,
                                                 self.detailedresults)

                    elif event["eventtype"] == "creation":
                        try:
                            os.remove(event["filepath"])
                        except OSError as oser:
                            if oser.errno == 21:
                                try:
                                    os.rmdir(event["filepath"])
                                except OSError as oserr:
                                    if oserr.errno == 39:
                                        self.logdispatch.log(LogPriority.DEBUG, "Cannot remove file path: " + str(event["filepath"]) + " because it is a non-empty directory.")
                            elif oser.errno == 2:
                                self.logdispatch.log(LogPriority.DEBUG, "Cannot remove file path: " + str(event["filepath"]) + " because it does not exist.")

                    elif event["eventtype"] == "deletion":
                        self.statechglogger.revertfiledelete(event["filepath"])

                    elif event["eventtype"] == "pkghelper":
                        ph = Pkghelper(self.logdispatch, self.environ)
                        if event["startstate"] == "installed":
                            ph.install(event["pkgname"])
                        elif event["startstate"] == "removed":
                            ph.remove(event["pkgname"])
                        else:
                            self.detailedresults = 'Invalid startstate for ' \
                                + 'eventtype "pkghelper". startstate should ' \
                                + 'either be "installed" or "removed"\n'
                            self.logdispatch.log(LogPriority.ERROR,
                                                 self.detailedresults)

                    elif event["eventtype"] == "servicehelper":
                        sh = ServiceHelper(self.environ, self.logdispatch)
                        if event["startstate"] == "enabled":
                            sh.enableservice(event["servicename"])
                        elif event["startstate"] == "disabled":
                            sh.disableservice(event["servicename"])
                        else:
                            self.detailedresults = 'Invalid startstate for ' \
                                + 'eventtype "servicehelper". startstate ' + \
                                'should either be "enabled" or "disabled"\n'
                            self.logdispatch.log(LogPriority.ERROR,
                                                 self.detailedresults)
                except(IndexError, KeyError):
                    self.detailedresults = "EventID " + entry + " not found"
                    self.logdispatch.log(LogPriority.DEBUG,
                                         self.detailedresults)
        except(KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            undosuccessful = False
            self.detailedresults = traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, [self.rulename + ".undo",
                                                     self.detailedresults])
        self.formatDetailedResults("undo", undosuccessful,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return undosuccessful

    def getrulenum(self):
        """
        Return the rule number

        @return int :
        @author D. Kennel
        """
        return self.rulenumber

    def getrulename(self):
        """
        Return the name of the rule

        @return string :
        @author D. Kennel
        """
        return self.rulename

    def getmandatory(self):
        """
        Return true if the rule in question represents a mandatory
        configuration. False indicates that the rule is optional.

        @return bool :
        @author D. Kennel
        """
        return self.mandatory

    def iscompliant(self):
        """
        This returns true if the configuration in question is compliant with
        the rule's required settings. The associated property is set by the
        report method.

        @return bool :
        @author D. Kennel
        """
        return self.compliant

    def getisrootrequired(self):
        """
        Return true if the rule requires root privileges to execute correctly.
        Rules that return true for this will not run when stonix is run without
        privileges.

        @return bool :
        @author D. Kennel
        """
        return self.rootrequired

    def gethelptext(self):
        """
        Return the help text for the rule.

        @return string :
        @author D. Kennel
        """
        return self.helptext

    def processconfig(self):
        """
        This is primarily a private method but may be called if the
        configuration has changed after the rules have been instantiated. This
        method will cause the rule to process it's entries from the
        configuration file object and instantiate it's dependent
        configuration item objects. Instantiated configurationitems will be
        added to the self.confitems property.

        @return void :
        @author D. Kennel
        """
        pass

    def getconfigitems(self):
        """
        This method will return all instantiated configitems for the rule.

        @return list : configurationitem instances
        @author D. Kennel
        """
        return self.confitems

    def getdetailedresults(self):
        """
        Return the detailed results string.

        @return string :
        @author D. Kennel
        """
        return self.detailedresults

    def getrulesuccess(self):
        """
        Return true if the rule executed successfully. 

        @return bool :
        @author D. Kennel
        """
        return self.rulesuccess

    def checkconfigopts(self):
        """
        This method will call the validate routine on all CI objects held by
        the rule. If any CI fails the validation we will return false. Rules
        with complicated CI's may want to override this to do more in-depth
        checks as the default CI checks are rudimentary.

        @return bool : True is all CI objs check out OK
        @author D. Kennel
        """
        allvalid = True
        for ciobj in self.confitems:
            currentval = ciobj.getcurrvalue()
            isvalid = ciobj.validate(currentval)
            if not isvalid:
                allvalid = False
        return allvalid

    def isdatabaserule(self):
        """
        Return true if the rule in question maintains a database on disk. E.g.
        a rule that tracks programs installed with SUID permissions.

        @return bool :
        @author D. Kennel
        """
        return self.databaserule

    def addresses(self):
        """
        This method returns the list of guidance elements addressed by the
        rule.

        @return: list
        @author: D. Kennel
        """
        return self.guidance

    def getcurrstate(self):
        """
        This method returns the current state. This information is only valid
        after the report() method is run.

        @return: string
        @author: D. Kennel
        """
        return self.currstate

    def gettargetstate(self):
        """
        This method returns the target state.

        @return: string
        @author: D. Kennel
        """
        return self.targetstate

    def settargetstate(self, state):
        """
        This method updates the value of the target state. By default the
        target state is 'configured' but when undoing a rule the target state
        will be set to 'notconfigured'.

        @author: D. Kennel
        """

        assert state in ['configured', 'notconfigured'], 'Invalid state: ' + \
        state

        self.targetstate = state

    def initCi(self, datatype, key, instructions, default):
        """
        This method constructs a ConfigurationItem for the rule. This is a
        shorthand method for instantiating a CI that should cover most cases.
        All parameters are required.

        @param datatype: string indicating data type - string, bool, int,
        float, list
        @param key: The Name of the CI as it appears in the GUI and Conf file.
        @param instructions: Text instructions to be shown to the user.
        @param default: default value for the rule.
        @author: dkennel
        """
        myci = ConfigurationItem(datatype)
        myci.setkey(key)
        myci.setinstructions(instructions)
        myci.setdefvalue(default)
        try:
            confcurr = self.config.getconfvalue(self.rulename, key)
        except(KeyError):
            confcurr = default
        myci.updatecurrvalue(confcurr)
        try:
            confuc = self.config.getusercomment(self.rulename, key)
        except(KeyError):
            confuc = ''
        myci.setusercomment(confuc)
        self.confitems.append(myci)
        self.logdispatch.log(LogPriority.DEBUG,
                             key + ' = ' + str(confcurr))
        return myci

    def formatDetailedResults(self, mode, result=True, detailedresults=""):
        """
        Description: This get a yes/no configuration item by name

        @author: ekkehard j. koch
        @note: This must be improve later once the parameter option or
        observable pattern for taking control of self.detailedresults refresh
        is implemented. see artf30937 : self.detailedresults through
        application flow for details
        """
        try:
            formattedDetailedResults = ""
            prefix = "Rule " + str(self.rulename) + "(" + \
            str(self.rulenumber) + ")"
            resultstring = ""
            if str(mode) == "initialize":
                prefix = prefix + ": "
                resultstring = str(DRINITIAL)
            elif str(mode) == "report":
                if result == None:
                    prefix = prefix + ": "
                    resultstring = str(DRREPORTNOTAVAILABLE)
                elif result:
                    prefix = prefix + " report results: "
                    self.currstate = self.targetstate
                    resultstring = str(DRREPORTCOMPIANT)
                else:
                    prefix = prefix + " report results: "
                    self.currstate = "notconfigured"
                    resultstring = str(DRREPORTNOTCOMPIANT)
            elif str(mode) == "fix":
                if result == None:
                    prefix = prefix + ": "
                    resultstring = str(DRFIXNOTAVAILABLE)
                elif result:
                    prefix = prefix + " fix results: "
                    resultstring = str(DRFIXSUCCESSFUL)
                else:
                    prefix = prefix + " fix results: "
                    resultstring = str(DRFIXFAILED)
            elif str(mode) == "undo":
                if result == None:
                    prefix = prefix + ": "
                    resultstring = str(DRUNDONOTAVAILABLE)
                elif result:
                    prefix = prefix + " revert results: "
                    resultstring = str(DRUNDOSUCCESSFUL)
                else:
                    prefix = prefix + " revert results: "
                    resultstring = str(DRUNDOFAILED)
            else:
                prefix = prefix + " "
                resultstring = "has results errors."
                raise ValueError("'" + str(mode) + "' is not a valid mode.")
            if str(detailedresults) == "":
                formattedDetailedResults = prefix + resultstring
            else:
                formattedDetailedResults = prefix + resultstring + "\n" + \
                str(detailedresults)
            self.detailedresults = formattedDetailedResults
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            formattedDetailedResults = ""
            raise
        return formattedDetailedResults
