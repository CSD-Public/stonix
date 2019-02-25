#!/usr/bin/env python

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
@change: 2017/03/07 dkennel - Added FISMA risk level support to isapplicable
@change: 2017/10/23 rsn - change to new service helper interface
'''

from observable import Observable
from configurationitem import ConfigurationItem
from logdispatcher import LogPriority
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
from CheckApplicable import CheckApplicable

class Rule (Observable):

    """
    Abstract class for all Rule objects.

    @version: 1.0
    @author:  D. Kennel
    @change: Breen Malmberg - 7/18/2017 - added method getauditonly();
            added and initialized variable self.auditonly to False (default);
            fixed doc string
    """

    def __init__(self, config, environ, logger, statechglogger):
        Observable.__init__(self)
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
        self.auditonly = False

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
        @change: - modified to new service helper interface - NOTE - 
                   Mac rules will need to set the self.serviceTarget
                   variable in their __init__ method after runing
                   "super" on this parent class.
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
                            debug = "Successfully deleted " + event["filepath"]
                            self.logdispatch.log(LogPriority.DEBUG, debug)
                        except OSError as oser:
                            if oser.errno == 21:
                                try:
                                    os.rmdir(event["filepath"])
                                except OSError as oserr:
                                    if oserr.errno == 39:
                                        self.logdispatch.log(LogPriority.DEBUG,
                                                             "Cannot remove file path: " +
                                                             str(event["filepath"]) +
                                                             " because it is a non-empty directory.")
                            elif oser.errno == 2:
                                self.logdispatch.log(LogPriority.DEBUG,
                                                     "Cannot remove file path: " +
                                                     str(event["filepath"]) +
                                                     " because it does not exist.")

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
                            sh.enableService(event["servicename"], serviceTarget=self.serviceTarget)
                        elif event["startstate"] == "disabled":
                            sh.disableService(event["servicename"], serviceTarget=self.serviceTarget)
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

    def isapplicable(self):
        """
        This method returns true if the rule applies to the platform on which
        stonix is currently running. The method in this template class will
        return true by default. The class property applicable will be
        referenced when this method is called and should be set by classes
        inheriting from the rule class including sub-template rules and
        concrete rule implementations.

        The format for the applicable property is a dictionary. The dictionary
        will be interpreted as follows:
        Key    Values        Meaning
        type    black/white  Whether the rest of the entries will be
                             interpreted as a whitelist (apply to) or a
                             blacklist (do not apply to). Blacklist is the
                             default.
        family  [list, valid environment.getosfamily() return types] The listed
                             os family will be whitelisted or blacklisted
                             according to the value of the type key.
        os    [Dict: key is a valid regex string that will match against return
                            from environment.getostype(), value is a list
                            containing version numbers, the - symbol, the +
                            symbol, or the letter "r" +|- may only be combined
                            with a single version number. "r" indicates a range
                            and expects 2 version numbers.]
                            This key is for matching specific os versions.
                             To match all Mac OS 10.11 and newer:
                             os: {'Mac OS X': ['10.11', '+']}
                             To match all Mac OS 10.8 and older:
                             os: {'Mac OS X': ['10.8', '-']}
                             To match only RHEL 6:
                             os: {'Red Hat Enterprise Linux': ['6.0']}
                             To match only Mac OS X 10.11.6:
                             os: {'Mac OS X': ['10.11.6']
                             To match a series of OS types:
                             os: {'Mac OS X': ['10.11', 'r', '10.13'],
                                  'Red Hat Enterprise Linux': ['6.0', '+'],
                                  'Ubuntu: ['14.04']}
        noroot   True|False This is an option, needed on systems like OS X,
                            which are "rootless". Meaning the root user isn't
                            used like a regular user. On these systems some
                            rules aimed at the user environment may not work or
                            actually cause problems. If this option is set to
                            True (python bool) then this method will return
                            false if EUID == 0. The default is False.
        fisma    low|med|high  This is the FISMA risk categorization that the
                            rule should apply to. Under FIPS 199 systems are
                            categorized for risk into low, medium (moderate),
                            and high categories. Some controls are particularly
                            impactful to operations and are only specified for
                            FISMA medium or high systems. Rules are selected
                            for low, medium or high applicability based on
                            guidance from NIST 800-53 or the applicable STIG.
        default  default    This is the default value in the template class and
                            always causes the method to return true. The
                            default only takes affect if the family and os keys
                            are not defined.

        An Example dictionary might look like this:
        self.applicable = {'type': 'white',
                           'family': Linux,
                           'os': {'Mac OS X': ['10.11', 'r', '10.14.10'],
                           'fisma': 'high',
                           'noroot': True}
        That example whitelists all Linux operating systems and Mac OS X from
        10.11.0 to 10.14.10.

        The family and os keys may be combined. Note that specifying a family
        will mask the behavior of the more specific os key.

        Note that version comparison is done using the distutils.version
        module. If the stonix environment module returns a 3 place version
        string then you need to provide a 3 place version string. I.E. in this
        case 10.11 only matches 10.11.0 and does not match 10.11.3 or 10.11.5.

        This method may be overridden if required.

        @return bool :
        @author D. Kennel
        @change: 2015/04/13 added this method to template class
        @change: 2017/11/13 ekkehard - make eligible for OS X El Capitan 10.11+
        """
        # return True
        # Shortcut if we are defaulting to true
        self.logdispatch.log(LogPriority.DEBUG,
                             'Check applicability for ' + self.rulename)
        self.logdispatch.log(LogPriority.DEBUG,
                             'Dictionary is: ' + str(self.applicable))
        try:
            if 'os' not in self.applicable and 'family' not in self.applicable:
                amidefault = self.applicable['default']
                if amidefault == 'default':
                    self.logdispatch.log(LogPriority.DEBUG,
                                         'Defaulting to True')
                    return True
        except KeyError:
            pass

        # Determine whether we are a blacklist or a whitelist, default to a
        # blacklist
        if 'type' in self.applicable:
            listtype = self.applicable['type']
        else:
            listtype = 'black'
        # Set the default return as appropriate to the list type
        # FIXME check for valid input
        assert listtype in ['white', 'black'], 'Invalid list type specified: %r' % listtype
        if listtype == 'black':
            applies = True
        else:
            applies = False

        # get our data in local vars
        myosfamily = self.environ.getosfamily()
        myosversion = self.environ.getosver()
        myostype = self.environ.getostype()

        # Process the os family list
        if 'family' in self.applicable:
            if myosfamily in self.applicable['family']:
                if listtype == 'black':
                    applies = False
                else:
                    applies = True
                self.logdispatch.log(LogPriority.DEBUG,
                                     'Family match, applies: ' + str(applies))

        # Process the OS list
        if 'os' in self.applicable:
            for ostype, osverlist in self.applicable['os'].iteritems():
                if re.search(ostype, myostype):
                    # Process version and up
                    if '+' in osverlist:
                        assert len(osverlist) is 2, "Wrong number of entries for a +"
                        if osverlist[1] == '+':
                            baseversion = osverlist[0]
                        else:
                            baseversion = osverlist[1]
                        if LooseVersion(myosversion) >= LooseVersion(baseversion):
                            if listtype == 'black':
                                applies = False
                            else:
                                applies = True
                            self.logdispatch.log(LogPriority.DEBUG,
                                                 'Plus match, applies: ' + str(applies))
                    # Process version and lower
                    elif '-' in osverlist:
                        assert len(osverlist) is 2, "Wrong number of entries for a -"
                        if osverlist[1] == '-':
                            baseversion = osverlist[0]
                        else:
                            baseversion = osverlist[1]
                        if LooseVersion(myosversion) <= LooseVersion(baseversion):
                            if listtype == 'black':
                                applies = False
                            else:
                                applies = True
                            self.logdispatch.log(LogPriority.DEBUG,
                                                 'Minus match, applies: ' + str(applies))
                    # Process inclusive range
                    elif 'r' in osverlist:
                        assert len(osverlist) is 3, "Wrong number of entries for a range"
                        vertmp = osverlist
                        vertmp.remove('r')
                        if LooseVersion(vertmp[0]) > LooseVersion(vertmp[1]):
                            highver = vertmp[0]
                            lowver = vertmp[1]
                        elif LooseVersion(vertmp[0]) < LooseVersion(vertmp[1]):
                            highver = vertmp[1]
                            lowver = vertmp[0]
                        else:
                            raise ValueError('Range versions are the same')
                        if LooseVersion(myosversion) <= LooseVersion(highver) \
                        and LooseVersion(myosversion) >= LooseVersion(lowver):
                            if listtype == 'black':
                                applies = False
                            else:
                                applies = True
                            self.logdispatch.log(LogPriority.DEBUG,
                                                 'Range match, applies: ' + str(applies))
                    # Process explicit match
                    else:
                        if myosversion in osverlist:
                            if listtype == 'black':
                                applies = False
                            else:
                                applies = True
                            self.logdispatch.log(LogPriority.DEBUG,
                                                 'Version match, applies: ' + str(applies))

        # Perform the rootless check
        if applies and self.environ.geteuid() == 0:
            if 'noroot' in self.applicable:
                if self.applicable['noroot'] == True:
                    applies = False

        # Perform the FISMA categorization check
        if applies:
            rulefisma = ''
            systemfismacat = ''
            systemfismacat = self.environ.getsystemfismacat()
            if systemfismacat not in ['high', 'med', 'low']:
                raise ValueError('SystemFismaCat invalid: valid values are low, med, high')
            if 'fisma' in self.applicable:
                if self.applicable['fisma'] not in ['high', 'med', 'low']:
                    raise ValueError('fisma value invalid: valid values are low, med, high')
                else:
                    rulefisma = self.applicable['fisma']
            if systemfismacat == 'high' and rulefisma == 'high':
                pass
            elif systemfismacat == 'med' and rulefisma == 'high':
                applies = False
            elif systemfismacat == 'low' and \
                 (rulefisma == 'med' or rulefisma == "high"):
                applies = False

        return applies

    def checkConsts(self, constlist=[]):
        """
        This method returns True or False depending
        on whether the list of constants passed to it
        are defined or not (if they are == None)
        This method was implemented to handle the
        default undefined state of constants in localize.py
        when operating in the public environment

        @return: retval
        @rtype: bool
        @author: Breen Malmberg
        """

        retval = True

        # if there is nothing to check, return False
        if not constlist:
            retval = False
            return retval

        if not isinstance(constlist, list):
            retval = False
            return retval

        try:

            # If there is a None type variable, return False
            for v in constlist:
                if v == None:
                    retval = False

            self.logdispatch.log(LogPriority.DEBUG, "One or more constants defined in localize.py, which are required for " + self.rulename + " to run, are missing or undefined")

        except Exception:
            raise
        return retval

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

    def getauditonly(self):
        '''
        Return the audit only status boolean.
        This class variable (self.auditonly) is
        meant to indicate whether a particular
        rule is intended to be audit-only or not.
        Default = False.

        @return: self.auditonly
        @rtype: bool
        @author: Breen Malmberg
        '''

        return self.auditonly

    def sethelptext(self):
        '''
        Set the help text for the current rule.
        Help text is retrieved from help/stonix_helptext.

        The help text blocks within stonix_helptext must
        always follow 4 basic rules in formatting:

        1) Each new help text block must begin with the
        rule's rulenumber in diamond brackets - e.g. <123>
        followed by an opening double quote
        2) Each help text block must end with ." (period
        followed by double quote)
        3) Each help text block must not contain any "
        (double quotes) other than starting and ending

        @return: void
        @author: Breen Malmberg
        '''

        # change helpdir variable if you change where the help text is stored!
        helpdir = self.environ.resources_path + '/help/stonix_helptext'
        contents = ''
        bstring = ''
        rulenum = self.getrulenum()

        try:

            if os.path.exists(helpdir):
                f = open(helpdir, 'r')
                contents = f.read()
                f.close()
            else:
                self.logdispatch.log(LogPriority.DEBUG, "Could not find help text file at: " + helpdir)
            
            b=re.findall(r'(?<=\<' + str(rulenum) + '\>).+?(?=\.\")', contents, re.DOTALL)
            if b:
                if isinstance(b, list):
                    if len(b) > 0:
                        bstring = b[0]
                bstring = bstring.strip()
                if re.search('^\"', bstring, re.IGNORECASE):
                    bstring = bstring[1:]
            if not bstring:
                self.logdispatch.log(LogPriority.DEBUG, "Failed to get help text for rulenumber = " + str(self.rulenumber))
                self.helptext = "Could not locate help text for this rule."
            else:
                self.helptext = bstring

        except Exception:
            raise
