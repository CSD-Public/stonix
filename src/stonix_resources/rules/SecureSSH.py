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
Created on Feb 19, 2013

@author: Breen Malmberg, dwalker
@change: 02/16/2014 ekkehard Implemented self.detailedresults flow
@change: 02/16/2014 ekkehard Implemented isapplicable
@change: 04/21/2014 ekkehard ci updates and ci fix method implementation
@change: 06/02/2014 dkennel multiple bug fixes for undefined variable issues.
@change: 2015/04/17 dkennel updated for new isApplicable
@change: 2015/09/23 eball Removed Banner setting to resolve InstallBanners conflict
@change: 2015/10/08 eball Help text cleanup
@change: 2015/11/09 ekkehard - make eligible of OS X El Capitan
@change: 2017/01/04 Breen Malmberg - added more detail to the help text to make
        it more clear to the end user, what the rule actually does.
@change: 2017/04/17 Breen Malmberg - added doc strings to fix and report methods;
        refactored fix and report methods; added setvars method; added a check
        for PrintMotd option; added checkPaths method
'''

from __future__ import absolute_import
import os
import traceback
import re
from ..rule import Rule
from ..stonixutilityfunctions import iterate, checkPerms, setPerms
from ..stonixutilityfunctions import createFile
from ..KVEditorStonix import KVEditorStonix
from ..logdispatcher import LogPriority
from ..pkghelper import Pkghelper


class SecureSSH(Rule):
    '''
    The SecureSSH class makes a number of configuration changes to SSH in \
    order to ensure secure use of the functionality.

    @author Breen Malmberg
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
        self.helptext = '''
This rule will not do anything if SSH is not installed.

This rule touches a number of configuration 
options in the ssh_config and sshd_config files. 
These options are checked and then changed, if necessary, 
to be more secure than the default configuration.

The CLIENT options touched are:
Host
Protocol
GSSAPIAuthentication
GSSAPIDelegateCredentials

The SERVER options touched are:
Protocol
SyslogFacility
PermitRootLogin
MaxAuthTries
RhostsRSAAuthentication
HostbasedAuthentication
IgnoreRhosts
PermitEmptyPasswords
PasswordAuthentication
ChallengeResponseAuthentication
KerberosAuthentication
GSSAPIAuthentication
GSSAPICleanupCredentials
UsePAM
Ciphers
PermitUserEnvironment
'''

        self.applicable = {'type': 'white',
                           'family': ['linux', 'solaris', 'freebsd'],
                           'os': {'Mac OS X': ['10.9', 'r', '10.12.10']}}
        datatype = 'bool'
        key = 'SECURESSH'
        instructions = "To disable this rule, set the value of SECURESSH to False"
        default = True
        self.ci = self.initCi(datatype, key, instructions, default)
        self.guidance = ['CIS, NSA(3.5.2.1)', 'CCE 4325-7', 'CCE 4726-6',
                         'CCE 4475-0', 'CCE 4370-3', 'CCE 4387-7',
                         'CCE 3660-8', 'CCE 4431-3', 'CCE 14716-5',
                         'CCE 14491-5']

        self.setvars()

###############################################################################

    def setvars(self):
        '''
        init and set all the variables to be used by
        this class/rule

        @return: void
        @author: Breen Malmberg
        '''

        try:

            self.sshdpath = ""   # server file
            self.sshpath = ""    # client file
            self.SSHDkvo = None
            self.SSHkvo = None
            self.sshdconfig = {}
            self.sshconfig = {}
            self.sshdconftype = "conf"
            self.sshdintent = "present"
            self.sshdseparator = "space"
            self.sshconftype = "conf"
            self.sshintent = "present"
            self.sshseparator = "space"
            self.sshdfileperms = [0, 0, 420]
            self.sshfileperms = [0, 0, 420]
            self.packagenames = ["openssh", "ssh"]
    
            if self.environ.getostype() == "Mac OS X":
                if re.search("10\.11\.*|10\.12\.*", self.environ.getosver()):
                    self.sshdpath = "/private/etc/ssh/sshd_config"
                    self.sshpath = "/private/etc/ssh/ssh_config"
                else:
                    self.sshdpath = "/private/etc/sshd_config"
                    self.sshpath = "/private/etc/ssh_config"
            else:
                self.sshdpath = "/etc/ssh/sshd_config"
                self.sshpath = "/etc/ssh/ssh_config"
    
            self.sshdtemppath = self.sshdpath + ".stonixtmp"
            self.sshtemppath = self.sshpath + ".stonixtmp"
    
            self.sshconfig = {"Host": "*",
                               "Protocol": "2",
                               "GSSAPIAuthentication": "yes",
                               "GSSAPIDelegateCredentials": "yes"}
            self.sshdconfig = {"Protocol": "2",
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

        except Exception:
            raise

    def checkPaths(self, paths, r=True):
        '''
        check for existence of given paths on the system
        report whether each exists or not

        @param paths: list; list of strings representing full paths to files
        @param r: bool; whether the method should check for the existence of
                a given file path or just whether it is not blank
        @return: pathexists
        @rtype: bool
        @author: Breen Malmberg
        '''

        pathexists = True

        try:

            # argument validation
            if not paths:
                self.logger.log(LogPriority.DEBUG, "Parameter: paths was empty!")
                pathexists = False
                return pathexists

            if not isinstance(paths, list):
                self.logger.log(LogPriority.DEBUG, "Parameter: paths has to be type: list. Got: " + str(type(paths)))
                pathexists = False
                return pathexists

            for p in paths:
                if not isinstance(p, basestring):
                    self.logger.log(LogPriority.DEBUG, "Parameter: paths has to be a list of types: string. Got: " + str(type(p)))
                    pathexists = False
                    return pathexists

            # check paths
            for p in paths:
                if not p:
                    pathexists = False
            if not pathexists:
                self.detailedresults += "\nUnable to determine name of one or more required config files."
                return pathexists
    
            if r:
                for p in paths:
                    if not os.path.exists(p):
                        pathexists = False
                if not pathexists:
                    self.detailedresults += "\nUnable to locate one or more required configuration files."
                    return pathexists

        except Exception:
            raise
        return pathexists

    def report(self):
        '''
        report on the status of both client and server
        configuration values

        @return: self.compliant
        @rtype: bool
        @author: Breen Malmberg, dwalker
        @change: Breen Malmberg - 4/14/2017 - added doc string; refactor of method
        '''

        # defaults
        self.compliant = True
        self.detailedresults = ""
        self.rulesuccess = True
        self.ph = Pkghelper(self.logger, self.environ)
        installed = False

        try:

            if self.environ.getostype() != "Mac OS X":

                # if ssh is not installed, do nothing.
                for p in self.packagenames:
                    if self.ph.check(p):
                        installed = True
                if not installed:
                    self.detailedresults += "\nSSH is not installed on this system. Will not continue."
                    self.formatDetailedResults("report", self.compliant, self.detailedresults)
                    self.logdispatch.log(LogPriority.INFO, self.detailedresults)
                    return self.compliant

            # check required config paths
            if not self.checkPaths([self.sshdpath, self.sshpath]):
                self.compliant = False
                self.formatDetailedResults("report", self.compliant, self.detailedresults)
                self.logdispatch.log(LogPriority.INFO, self.detailedresults)
                return self.compliant

            # if this is Ubuntu, set Ubuntu-specific settings
            if re.search("Ubuntu", self.environ.getostype()):
                self.sshdconfig = {"GSSAPIAuthentication": "",
                                   "KerberosAuthentication": "",
                                   "PrintMotd": "no"}
                self.sshdintent = "notpresent"
                self.sshconfig = {"GSSAPIAuthentication": ""}
                self.sshintent = "notpresent"

            # init the ssh server kveditor object
            self.SSHDkvo = KVEditorStonix(self.statechglogger, self.logger, self.sshdconftype, self.sshdpath, self.sshdtemppath,
                                          self.sshdconfig, self.sshdintent, self.sshdseparator)

            # report on the ssh server kveditor object
            if not self.SSHDkvo.report():
                self.detailedresults += "\nThe following configuration options do not have the correct values, in " + str(self.sshdpath) + " :\n"
                if self.SSHDkvo.fixables:
                    self.detailedresults += "\n".join(self.SSHDkvo.fixables)
                if self.SSHDKvo.removeables:
                    self.detailedresults += "\n".join(self.SSHDkvo.removeables)
                self.compliant = False

            # check perms and owner on server conf file
            if not checkPerms(self.sshdpath, self.sshdfileperms, self.logger):
                self.detailedresults += "\nFile: " + str(self.sshdpath) + " needs ownership = root:root"
                self.detailedresults += "\nFile: " + str(self.sshdpath) + " needs permissions = rw,r,r"
                self.compliant = False

            # init ssh client kveditor object
            self.SSHkvo = KVEditorStonix(self.statechglogger, self.logger, self.sshconftype, self.sshpath, self.sshtemppath,
                                         self.sshconfig, self.sshintent, self.sshseparator)

            # report on the ssh client kveditor object
            if not self.SSHkvo.report():
                self.detailedresults += "\nThe following configuration options do not have the correct values, in " + str(self.sshpath) + " :\n"
                if self.SSHkvo.fixables:
                    self.detailedresults += "\n".join(self.SSHkvo.fixables)
                if self.SSHKvo.removeables:
                    self.detailedresults += "\n".join(self.SSHkvo.removeables)
                self.compliant = False

            # check permissions and ownership on ssh client config file
            if not checkPerms(self.sshpath, self.sshfileperms, self.logger):
                self.detailedresults += "\nFile: " + str(self.sshpath) + " needs ownership = root:root"
                self.detailedresults += "\nFile: " + str(self.sshpath) + " needs permissions = rw,r,r"
                self.compliant = False

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults = traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

###############################################################################

    def fix(self):
        '''
        run fix actions to set all of the required configuration options
        for ssh server and client config

        @return: fixsuccess
        @rtype: bool
        @author: Breen Malmberg, dwalker
        @change: Breen Malmberg - 4/14/2017 - added doc string; refactor of method
        '''

        self.detailedresults = ""
        fixsuccess = True
        self.iditerator = 0
        createdsshdcfg, createdsshcfg = False, False
        installed = False

        try:

            # if the CI is not enabled, do nothing.
            if not self.ci.getcurrvalue():
                self.detailedresults += "\nThe CI for this rule was not enabled. Nothing was done."
                self.formatDetailedResults("fix", fixsuccess, self.detailedresults)
                self.logdispatch.log(LogPriority.INFO, self.detailedresults)
                return fixsuccess

            if self.environ.getostype() != "Mac OS X":

                # if ssh is not installed, do nothing.
                for p in self.packagenames:
                    if self.ph.check(p):
                        installed = True
                if not installed:
                    self.detailedresults += "\nNothing was done."
                    self.formatDetailedResults("fix", fixsuccess, self.detailedresults)
                    self.logdispatch.log(LogPriority.INFO, self.detailedresults)
                    return fixsuccess

            # check required config paths
            if not self.checkPaths([self.sshdpath, self.sshpath], False):
                fixsuccess = False
                self.formatDetailedResults("fix", fixsuccess, self.detailedresults)
                self.logdispatch.log(LogPriority.INFO, self.detailedresults)
                return fixsuccess

            eventlist = self.statechglogger.findrulechanges(self.rulenumber)
            for event in eventlist:
                self.statechglogger.deleteentry(event)

            if not os.path.exists(self.sshdpath):
                createFile(self.sshdpath, self.logger)
                createdsshdcfg = True
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                event = {"eventtype": "creation",
                         "filepath": self.sshdpath}
                self.statechglogger.recordchgevent(myid, event)

            if os.path.exists(self.sshdpath):
                if not self.SSHDkvo:

                    # if, for whatever reason, the server kv object is not yet created, create it
                    # and run a report on it, to generate fixables/removeables
                    self.SSHDkvo = KVEditorStonix(self.statechglogger, self.logger, self.sshdconftype, self.sshdpath, self.sshdtemppath,
                                                  self.sshdconfig, self.sshdintent, self.sshdseparator)

                    if re.search("Ubuntu", self.environ.getostype()):
                        self.sshdconfig = {"GSSAPIAuthentication": "",
                                       "KerberosAuthentication": "",
                                       "PrintMotd": "no"}
                        self.SSHDkvo.setIntent("notpresent")
                        self.SSHDkvo.setData(self.sshdconfig)

                    self.SSHDkvo.report()

                # make the config changes to server config file
                if self.SSHDkvo.fixables or self.SSHDkvo.removeables:
                    if not createdsshdcfg:
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        self.SSHDkvo.setEventID(myid)

                    if self.SSHDkvo.fix():
                        self.detailedresults += "kveditor1 fix ran successfully\n"
                        if self.SSHDkvo.commit():
                            self.detailedresults += "kveditor1 commit ran successfully\n"
                        else:
                            self.detailedresults += "kveditor1 commit did not run successfully\n"
                            fixsuccess = False
                    else:
                        self.detailedresults += "kveditor1 fix did not run successfully\n"
                        fixsuccess = False

                # set the permissions and ownership back to correct values
                if not checkPerms(self.sshdpath, self.sshdfileperms, self.logger):
                    if not createdsshdcfg:
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        if not setPerms(self.sshdpath, self.sshdfileperms, self.logger,
                                        self.statechglogger, myid):
                            fixsuccess = False
                    else:
                        if not setPerms(self.sshdpath, self.sshdfileperms, self.logger):
                            fixsuccess = False

            # if the client config file doesn't exist, then create it
            if not os.path.exists(self.sshpath):
                createFile(self.sshpath, self.logger)
                createdsshcfg = True
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                event = {"eventtype": "creation",
                         "filepath": self.sshpath}
                self.statechglogger.recordchgevent(myid, event)

            if os.path.exists(self.sshpath):
                if not self.SSHkvo:

                    # if, for whatever reason, the client kv object is not yet created, create it
                    # and run a report on it, to generate fixables/removeables
                    self.SSHkvo = KVEditorStonix(self.statechglogger, self.logger, self.sshconftype, self.sshpath, self.sshtemppath,
                                                 self.sshconfig, self.sshintent, self.sshseparator)

                    if re.search("Ubuntu", self.environ.getostype()):
                        self.sshconfig = {"GSSAPIAuthentication": "",
                                       "KerberosAuthentication": ""}
                        self.SSHkvo.setIntent("notpresent")
                        self.SSHkvo.setData(self.sshconfig)

                    self.SSHkvo.report()

                # make the config changes to ssh client file
                if self.SSHkvo.fixables or self.SSHkvo.removeables:
                    if not createdsshcfg:
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        self.SSHkvo.setEventID(myid)
                    if self.SSHkvo.fix():
                        self.detailedresults += "kveditor2 fix ran successfully\n"
                        if self.SSHkvo.commit():
                            self.detailedresults += "kveditor2 commit ran successfully\n"
                        else:
                            self.detailedresults += "kveditor2 commit did not run successfully\n"
                            fixsuccess = False
                    else:
                        self.detailedresults += "kveditor2 fix did not run successfully\n"
                        fixsuccess = False

                # set the permissions and ownership back to correct values
                if not checkPerms(self.sshpath, self.sshfileperms, self.logger):
                    if not createdsshcfg:
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        if not setPerms(self.sshpath, self.sshfileperms, self.logger, self.statechglogger, myid):
                            fixsuccess = False
                    else:
                        if not setPerms(self.sshpath, self.sshfileperms, self.logger):
                            fixsuccess = False

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults = traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", fixsuccess, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return fixsuccess
