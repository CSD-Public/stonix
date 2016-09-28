'''
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

Created on Feb 19, 2013

@author: bemalmbe,dwalker
@change: 02/16/2014 ekkehard Implemented self.detailedresults flow
@change: 02/16/2014 ekkehard Implemented isapplicable
@change: 04/21/2014 ekkehard ci updates and ci fix method implementation
@change: 06/02/2014 dkennel multiple bug fixes for undefined variable issues.
@change: 2015/04/17 dkennel updated for new isApplicable
@change: 2015/09/23 eball Removed Banner setting to resolve InstallBanners conflict
@change: 2015/10/08 eball Help text cleanup
@change: 2015/11/09 ekkehard - make eligible of OS X El Capitan
'''
from __future__ import absolute_import
import os
import traceback
import re
from ..rule import Rule
from ..stonixutilityfunctions import iterate, checkPerms, setPerms, resetsecon
from ..stonixutilityfunctions import createFile
from ..KVEditorStonix import KVEditorStonix
from ..logdispatcher import LogPriority


class SecureSSH(Rule):
    '''
    The SecureSSH class makes a number of configuration changes to SSH in \
    order to ensure secure use of the functionality.

    @author bemalmbe
    '''

    def __init__(self, config, environ, logger, statechglogger):
        '''
        Constructor
        '''
        Rule.__init__(self, config, environ, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 8
        self.rulename = 'SecureSSH'
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.helptext = '''This rule makes a number of configuration \
changes to SSH in order to ensure its security.  This rule \
will not attempt to install the SSH server or client if it is not installed. \
However, it will create the appropriate files if not present and put the \
appropriate contents in them whether installed or not.'''
        self.applicable = {'type': 'white',
                           'family': ['linux', 'solaris', 'freebsd'],
                           'os': {'Mac OS X': ['10.9', 'r', '10.12.10']}}
        datatype = 'bool'
        key = 'SECURESSH'
        instructions = "To disable this rule set the value " + \
                       "of SECURESSH to False"
        default = True
        self.ci = self.initCi(datatype, key, instructions, default)
        self.guidance = ['CIS, NSA(3.5.2.1)', 'CCE 4325-7', 'CCE 4726-6',
                         'CCE 4475-0', 'CCE 4370-3', 'CCE 4387-7',
                         'CCE 3660-8', 'CCE 4431-3', 'CCE 14716-5',
                         'CCE 14491-5']
        self.ed1, self.ed2 = "", ""

###############################################################################

    def report(self):
        try:
            self.client = {"Host": "*",
                           "Protocol": "2",
                           "GSSAPIAuthentication": "yes",
                           "GSSAPIDelegateCredentials": "yes"}
            self.server = {"Protocol": "2",
                           "SyslogFacility": "AUTHPRIV",
                           "PermitRootLogin": "no",
                           "MaxAuthTries": "5",
                           "RhostsRSAAuthentication": "no",
                           "HostbasedAuthentication": "no",
                           "IgnoreRhosts": "yes",
                           "PermitEmptyPasswords": "no",
                           "PasswordAuthentication": "yes",
                           "ChallengeResponseAuthentication": "no",
                           "KerberosAuthentication": "yes",
                           "GSSAPIAuthentication": "yes",
                           "GSSAPICleanupCredentials": "yes",
                           "UsePAM": "yes",
                           "Ciphers": "aes128-ctr,aes192-ctr,aes256-ctr",
                           "PermitUserEnvironment": "no"}
            self.detailedresults = ""
            compliant = True
            debug = ""
            if self.environ.getostype() == "Mac OS X":
                if re.search("10\.11\.*|10\.12\.*", self.environ.getosver()):
                    self.path1 = '/private/etc/ssh/sshd_config'
                    self.path2 = '/private/etc/ssh/ssh_config'
                else:
                    self.path1 = "/private/etc/sshd_config"  # server file
                    self.path2 = "/private/etc/ssh_config"  # client file
            else:
                self.path1 = "/etc/ssh/sshd_config"  # server file
                self.path2 = "/etc/ssh/ssh_config"  # client file

            if os.path.exists(self.path1):
                tpath1 = self.path1 + ".tmp"
                if re.search("Ubuntu", self.environ.getostype()):
                    del(self.server["GSSAPIAuthentication"])
                    del(self.server["KerberosAuthentication"])
                self.ed1 = KVEditorStonix(self.statechglogger,
                                          self.logger, "conf",
                                          self.path1, tpath1,
                                          self.server, "present",
                                          "space")
                if not self.ed1.report():
                    self.detailedresults += "Did not find the correct " + \
                        "contents in sshd_config\n"
                    compliant = False
                if re.search("Ubuntu", self.environ.getostype()):
                    self.server = {"GSSAPIAuthentication": "",
                                   "KerberosAuthentication": ""}
                    self.ed1.setIntent("notpresent")
                    self.ed1.setData(self.server)
                    if not self.ed1.report():
                        debug = "didn't find the correct" + \
                            " contents in sshd_config\n"
                        self.logger.log(LogPriority.DEBUG, debug)
                        compliant = False
                if not checkPerms(self.path1, [0, 0, 420],
                                  self.logger):
                    self.detailedresults += "Incorrect permissions for " + \
                        "file " + self.path1 + "\n"
                    compliant = False
            else:
                self.detailedresults += self.path1 + " does not exist\n"
                compliant = False
            if os.path.exists(self.path2):
                tpath2 = self.path2 + ".tmp"
                if re.search("Ubuntu", self.environ.getostype()):
                    del(self.client["GSSAPIAuthentication"])
                self.ed2 = KVEditorStonix(self.statechglogger,
                                          self.logger, "conf",
                                          self.path2, tpath2,
                                          self.client, "present",
                                          "space")
                if not self.ed2.report():
                    self.detailedresults += "Did not find the correct " + \
                        "contents in ssh_config\n"
                    compliant = False
                if re.search("Ubuntu", self.environ.getostype()):
                    self.client = {"GSSAPIAuthentication": ""}
                    self.ed2.setIntent("notpresent")
                    self.ed2.setData(self.client)
                    if not self.ed2.report():
                        self.detailedresults += "Did not find the correct " + \
                            "contents in ssh_config\n"
                if not checkPerms(self.path2, [0, 0, 420],
                                  self.logger):
                    self.detailedresults += "Incorrect permissions for " + \
                        "file " + self.path2 + "\n"
                    compliant = False
            else:
                self.detailedresults += self.path2 + " does not exist\n"
                compliant = False
            self.compliant = compliant
        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
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
        try:
            if not self.ci.getcurrvalue():
                return
            self.detailedresults = ""
            created1, created2 = False, False
            debug = ""

            self.iditerator = 0
            eventlist = self.statechglogger.findrulechanges(self.rulenumber)
            for event in eventlist:
                self.statechglogger.deleteentry(event)
            tpath1 = self.path1 + ".tmp"

            if not os.path.exists(self.path1):
                createFile(self.path1, self.logger)
                created1 = True
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                event = {"eventtype": "creation",
                         "filepath": self.path1}
                self.statechglogger.recordchgevent(myid, event)
            if os.path.exists(self.path1):
                if not self.ed1:
                    tpath1 = self.path1 + ".tmp"
                    if re.search("Ubuntu", self.environ.getostype()):
                        del(self.server["GSSAPIAuthentication"])
                        del(self.server["KerberosAuthentication"])
                    self.ed1 = KVEditorStonix(self.statechglogger,
                                              self.logger, "conf", self.path1,
                                              tpath1, self.server, "present",
                                              "space")
                    self.ed1.report()
                    if re.search("Ubuntu", self.environ.getostype()):
                        self.server = {"GSSAPIAuthentication": "",
                                       "KerberosAuthentication": ""}
                        self.ed1.setIntent("notpresent")
                        self.ed1.setData(self.server)
                        self.ed1.report()
                if not checkPerms(self.path1, [0, 0, 420], self.logger):
                    if not created1:
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        if not setPerms(self.path1, [0, 0, 420], self.logger,
                                        self.statechglogger, myid):
                            self.rulesuccess = False
                    else:
                        if not setPerms(self.path1, [0, 0, 420], self.logger):
                            self.rulesuccess = False
                if self.ed1.fixables or self.ed1.removeables:
                    if not created1:
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        self.ed1.setEventID(myid)
                    if self.ed1.fix():
                        self.detailedresults += "kveditor1 fix ran successfully\n"
                        if self.ed1.commit():
                            self.detailedresults += "kveditor1 commit ran \
successfully\n"
                        else:
                            self.detailedresults += "kveditor1 commit did not run \
successfully\n"
                            self.rulesuccess = False
                    else:
                        self.detailedresults += "kveditor1 fix did not run \
successfully\n"
                        self.rulesuccess = False
                    os.chown(self.path1, 0, 0)
                    os.chmod(self.path1, 420)
                    resetsecon(self.path1)

            tpath2 = self.path2 + ".tmp"
            if not os.path.exists(self.path2):
                createFile(self.path2, self.logger)
                created2 = True
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                event = {"eventtype": "creation",
                         "filepath": self.path2}
                self.statechglogger.recordchgevent(myid, event)

            if os.path.exists(self.path2):
                if not self.ed2:
                    tpath2 = self.path2 + ".tmp"
                    if re.search("Ubuntu", self.environ.getostype()):
                        del(self.client["GSSAPIAuthentication"])
                    self.ed2 = KVEditorStonix(self.statechglogger,
                                              self.logger, "conf", self.path2,
                                              tpath2, self.client, "present",
                                              "space")
                    self.ed2.report()
                    if re.search("Ubuntu", self.environ.getostype()):
                        self.server = {"GSSAPIAuthentication": "",
                                       "KerberosAuthentication": ""}
                        self.ed2.setIntent("notpresent")
                        self.ed2.setData(self.client)
                        self.ed2.report()
                if not checkPerms(self.path2, [0, 0, 420], self.logger):
                    if not created2:
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        if not setPerms(self.path2, [0, 0, 420], self.logger,
                                        self.statechglogger, myid):
                            self.rulesuccess = False
                    else:
                        if not setPerms(self.path2, [0, 0, 420], self.logger):
                            self.rulesuccess = False
                if self.ed2.fixables or self.ed2.removeables:
                    if not created2:
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        self.ed2.setEventID(myid)
                    if self.ed2.fix():
                        self.detailedresults += "kveditor2 fix ran successfully\n"
                        if self.ed2.commit():
                            self.detailedresults += "kveditor2 commit ran \
successfully\n"
                        else:
                            self.detailedresults += "kveditor2 commit did not \
run successfully\n"
                            self.rulesuccess = False
                    else:
                        self.detailedresults += "kveditor2 fix did not run \
successfully\n"
                        self.rulesuccess = False
                    os.chown(self.path2, 0, 0)
                    os.chmod(self.path2, 420)
                    resetsecon(self.path2)
            if debug:
                self.logger.log(LogPriority.DEBUG, debug)
        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.rulesuccess
