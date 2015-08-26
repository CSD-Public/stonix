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
'''
Created on Nov 4, 2013

Set an alias for root mail on the system so that it is read by an actual human.

@author: bemalmbe
@change: 02/16/2014 ekkehard Implemented self.detailedresults flow
@change: 02/16/2014 ekkehard Implemented isapplicable
@change: 04/21/2014 dkennel Updated CI invocation, fixed bug where boolean CI
was not checked before exectuing fix()
@change: 05/08/2014 dwalker fixing non compliant after fix issues, will be
    refactoring entire rule
@change: 05/28/2014 dwalker refactored rule so that would show compliant after
    fix on mac os x
@change: 2014/10/17 ekkehard OS X Yosemite 10.10 Update
@change: 2015/04/17 dkennel updated for new isApplicable
@change: 2015/04/28 dkennel changed default2 for ci2 to "root@localhost".
    Original had local domain name appended which provides no value.
@change: 2015/08/26 ekkehard [artf37780] : RootMailAlias(251) - NCAF & Lack of detail in Results - OS X El Capitan 10.11
'''

from __future__ import absolute_import

from ..rule import Rule
from ..logdispatcher import LogPriority
from ..stonixutilityfunctions import checkPerms, setPerms
from ..stonixutilityfunctions import writeFile, readFile, iterate, resetsecon
from ..pkghelper import Pkghelper
import os
from re import search
import traceback
# from Carbon.Aliases import false


class RootMailAlias(Rule):
    '''
    Set an alias for root mail on the system so that it is read by an actual
    human.

    @author: bemalmbe
    '''

    def __init__(self, config, environ, logger, statechglogger):
        '''
        Constructor
        '''

        Rule.__init__(self, config, environ, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 251
        self.rulename = 'RootMailAlias'
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.helptext = '''Set an alias for root mail on the system so that \
it is read by an actual human.'''
        self.guidance = ['none']

        datatype = 'bool'
        key = 'RootMailAlias'
        instructions = '''To prevent the setting of an alias for root mail, \
set the value of RootMailAlias to False.'''
        default = True
        self.ci1 = self.initCi(datatype, key, instructions, default)

        datatype2 = 'string'
        key2 = 'AliasString'
        instructions2 = '''Please specify the email address which should \
receive root mail for this system.'''
        default2 = ''
        self.ci2 = self.initCi(datatype2, key2, instructions2, default2)

        self.iditerator = 0
        self.applicable = {'type': 'white',
                           'family': ['linux', 'solaris', 'freebsd'],
                           'os': {'Mac OS X': ['10.9', 'r', '10.10.10']}}
        self.emailfound = True
###############################################################################

    def report(self):
        '''
        Check the /etc/aliases file for the existence of an alias mail address
        to send root's mail to

        @return: bool
        @author: bemalmbe
        @change: dwalker
        '''
        try:
            self.detailedresults = ""
            compliant = True
            self.ph = Pkghelper(self.logger, self.environ)
            fp = "/etc/aliases"
            email = self.ci2.getcurrvalue()
            if email:
                if not search("[^@]+@[^@]+\.[^@]+", email):
                    self.detailedresults += "Your email address is invalid\n"
                    self.logger.log(LogPriority.WARNING, self.detailedresults)
                    return
            if self.ph.manager == "apt-get":
                if not self.ph.check("mailman"):
                    compliant = False
                else:
                    if os.path.exists(fp):
                        if not checkPerms(fp, [0, 0, 420], self.logger):
                            compliant = False
                        contents = readFile(fp, self.logger)
                        email = self.ci2.getcurrvalue()
                        if contents:
                            for line in contents:
                                if search("^root:\s+", line.strip()):
                                    line = line.split()
                                    if email:
                                        try:
                                            if line[1].strip() != email:
                                                compliant = False
                                                break
                                        except IndexError:
                                            debug = traceback.format_exc() + \
                                                "\n"
                                            debug += "Index out of range " + \
                                                "on line: " + line + "\n"
                                            self.logger.log(LogPriority.DEBUG,
                                                            debug)
                                    else:
                                        if not search("[^@]+@[^@]+\.[^@]+",
                                                      line[1].strip()):
                                            compliant = False
                        else:
                            compliant = False
                    else:
                        compliant = False
            elif os.path.exists(fp):
                if not checkPerms(fp, [0, 0, 420], self.logger):
                    compliant = False
                contents = readFile(fp, self.logger)
                email = self.ci2.getcurrvalue()
                if contents:
                    rootfound = False
                    for line in contents:
                        if search("^root", line.strip()):
                            rootfound = True
                            line = line.split()
                            if email:
                                try:
                                    if line[1].strip() != email:
                                        self.detailedresults += "email " + \
                                            "address doesn't match\n"
                                        compliant = False
                                        break
                                except IndexError:
                                    debug = traceback.format_exc() + "\n"
                                    debug += "Index out of range on line: " + \
                                        line + "\n"
                                    self.logger.log(LogPriority.DEBUG,
                                                    debug)
                            else:
                                if not search("[^@]+@[^@]+\.[^@]+",
                                              line[1].strip()):
                                    compliant = False
                    if not rootfound:
                        self.detailedresults += "root line not found\n"
                        compliant = False
            else:
                compliant = False
            if compliant:
                self.compliant = True
                self.detailedresults += "RootMailAlias report has been run \
and is compliant \n"
            else:
                self.compliant = False
                self.detailedresults += "RootMailAlias report has been run \
and is not compliant\n"
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

###############################################################################

    def fix(self):
        '''
        Add an alias for the root mail on the system to the /etc/aliases file

        @author: bemalmbe
        @change: dwalker
        '''
        try:
            if not self.ci1.getcurrvalue():
                return
            elif self.ci2.getcurrvalue():
                if not search("[^@]+@[^@]+\.[^@]+", self.ci2.getcurrvalue()):
                    return
            success = True
            self.detailedresults = ""

            self.iditerator = 0
            eventlist = self.statechglogger.findrulechanges(self.rulenumber)
            for event in eventlist:
                self.statechglogger.deleteentry(event)

            tempstring = ""
            fp = "/etc/aliases"
            tfp = fp + ".tmp"
            badfile = False
            if self.ph.manager == "apt-get":
                print "IT's and apt-get system"
                if not self.ph.check("mailman"):
                    if self.ph.checkAvailable("mailman"):
                        if not self.ph.install("mailman"):
                            success = False
                if os.path.exists(fp):
                    if not checkPerms(fp, [0, 0, 420],
                                      self.logger):
                        self.iditerator += 1
                        myid = iterate(self.iditerator,
                                       self.rulenumber)
                        if not setPerms(fp, [0, 0, 420],
                                        self.logger,
                                        self.statechglogger,
                                        myid):
                            success = False
                    contents = readFile(fp, self.logger)
                    email = self.ci2.getcurrvalue()
                    if contents:
                        found = False
                        for line in contents:
                            if search("^root:\s+", line.strip()):
                                if found:
                                    continue
                                temp = line.split()
                                if email:
                                    try:
                                        if temp[1].strip() == email:
                                            found = True
                                            tempstring += line
                                        else:
                                            badfile = True
                                    except IndexError:
                                        debug = \
                                            traceback.format_exc() + \
                                            "\n"
                                        debug += "Index out of " + \
                                            "range on line: " + \
                                            line + "\n"
                                        self.logger.log(LogPriority.DEBUG, debug)
                                else:
                                    if not search("[^@]+@[^@]+\.[^@]+", temp[1].strip()):
                                        continue
                            else:
                                tempstring += line
                        if not found:
                            if not email:
                                fail = "No email was entered " + \
                                "and no other email for root " + \
                                "was found.  Nothing can be done\n"
                                self.detailedresults += fail
                                self.logger.log(LogPriority.WARNING, fail)
                                success = False
                            else:
                                badfile = True
                                tempstring += "root:     " + email + "\n"
            else:
                if os.path.exists(fp):
                    if not checkPerms(fp, [0, 0, 420], self.logger):
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        if not setPerms(fp, [0, 0, 420], self.logger,
                                        self.statechglogger, myid):
                            success = False
                    contents = readFile(fp, self.logger)
                    email = self.ci2.getcurrvalue()
                    if contents and email:
                        found = False
                        for line in contents:
                            if search("^root:\s+", line.strip()):
                                if found:
                                    continue
                                temp = line.split()
                                if email:
                                    try:
                                        if temp[1].strip() == email:
                                            found = True
                                            tempstring += line
                                        else:
                                            badfile = True
                                    except IndexError:
                                        debug = traceback.format_exc() + "\n"
                                        debug += "Index out of range on line: " + line + "\n"
                                        self.logger.log(LogPriority.DEBUG, debug)
                                else:
                                    if not search("[^@]+@[^@]+\.[^@]+", temp[1].strip()):
                                        continue
                            else:
                                tempstring += line
                        if not found:
                            if not email:
                                fail = "No email was entered " + \
                                    "and no other email for root " + \
                                    "was found.  Nothing can be done\n"
                                self.detailedresults += fail
                                self.logger.log(LogPriority.WARNING, fail)
                                success = False
                            else:
                                badfile = True
                                tempstring += "root:     " + email + "\n"
            if badfile:
                if writeFile(tfp, tempstring, self.logger):
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    event = {"eventtype": "conf",
                             "filepath": fp}
                    self.statechglogger.recordchgevent(myid, event)
                    self.statechglogger.recordfilechange(fp, tfp, myid)
                    self.detailedresults += "corrected contents and wrote to \
file: " + fp + "\n"
                    os.rename(tfp, fp)
                    os.chown(fp, 0, 0)
                    os.chmod(fp, 420)
                    resetsecon(fp)
                else:
                    self.detailedresults += "Unable to successfully write \
to the file: " + fp + "\n"
                    success = False
            self.rulesuccess = success
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.rulesuccess
