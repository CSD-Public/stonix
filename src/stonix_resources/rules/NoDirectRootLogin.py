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
Created on Mar 27, 2018

The NoDirectRootLogin rule prevents users from logging into root directly
through virtual console or tty connections. Users can still access root
through non-tty connections or by escalating privileges using sudo.

@author: bgonz12
'''


import os
import traceback

from rule import Rule
from logdispatcher import LogPriority
from CommandHelper import CommandHelper
from stonixutilityfunctions import createFile, writeFile, readFileString,\
    iterate, checkPerms, setPerms, resetsecon

class NoDirectRootLogin(Rule):
    '''@author bgonz12'''

    def __init__(self, config, environ, logger, statechglogger):
        '''
        Constructor
        '''

        Rule.__init__(self, config, environ, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 85
        self.rulename = 'NoDirectRootLogin'
        self.formatDetailedResults("initialize")
        self.compliant = False
        self.mandatory = True
        self.sethelptext()
        self.rootrequired = True
        self.guidance = ["CCE-RHEL7-CCE-TBD 2.4.1.1.7"]
        self.applicable = {'type': 'white',
                           'family': ['linux', 'solaris', 'freebsd']}

        # Configuration item instantiation
        datatype = "bool"
        key = "NODIRECTROOTLOGIN"
        instructions = "To disable this rule, set the value of " + \
                       "NODIRECTROOTLOGIN to false."
        default = True
        self.ci = self.initCi(datatype, key, instructions, default)
        
        self.ch = CommandHelper(self.logger)
        self.securettypath = "/etc/securetty"
        self.iditerator = 0
        self.isblank = False

    def report(self):
        '''The report method examines the current configuration and determines
        whether or not it is correct. If the config is correct then the
        self.compliant, self.detailedresults and self.currstate properties are
        updated to reflect the system status. self.rulesuccess will be updated
        if the rule does not succeed.


        :returns: self.compliant

        :rtype: bool
@author bgonz12

        '''
        try:
            compliant = True
            self.detailedresults = ""
            
            if not os.path.exists(self.securettypath):
                compliant = False
                self.detailedresults += self.securettypath + " is missing\n"
            else:
                if not checkPerms(self.securettypath, [0, 0, 0o600], self.logger):
                    compliant = False
                    self.detailedresults += "Permissions incorrect on " + self.securettypath + "\n"
                contents = readFileString(self.securettypath, self.logger)
                if contents != "":
                    compliant = False
                    self.detailedresults += self.securettypath + " should be empty\n"
                else:
                    self.isblank = True
            self.compliant = compliant
            
        except (OSError):
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.DEBUG, self.detailedresults)
        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception as err:
            self.rulesuccess = False
            self.detailedresults = self.detailedresults + "\n" + str(err) + \
                " - " + str(traceback.format_exc())
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

    def fix(self):
        '''The report method examines the current configuration and determines
        whether or not it is correct. If the config is correct then the
        self.compliant, self.detailedresults and self.currstate properties are
        updated to reflect the system status. self.rulesuccess will be updated
        if the rule does not succeed.


        :returns: self.rulesuccess

        :rtype: bool
@author bgonz12

        '''
        try:
            self.iditerator = 0
            self.detailedresults = ""
            if not self.ci.getcurrvalue():
                return
            success = True
            if not os.path.exists(self.securettypath):
                if not createFile(self.securettypath, self.logger):
                    success = False
                    self.detailedresults += "Unable to create " + \
                                            self.securettypath + "\n"
                else:
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    event = {"eventtype": "creation",
                             "filepath": self.securettypath}
                    self.statechglogger.recordchgevent(myid, event)
                    if not setPerms(self.securettypath, [0, 0, 0o600], self.logger):
                        success = False
                        self.detailedresults += "Unable to correct permissions on " + \
                                                self.securettypath + "\n"
            elif not self.isblank:
                tempfile = self.securettypath + ".tmp"
                if not checkPerms(self.securettypath, [0, 0, 0o600], self.logger):
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    if not setPerms(self.securettypath, [0, 0, 0o600], self.logger,
                                    self.statechglogger, myid):
                        success = False
                        self.detailedresults += "Unable to correct permissions on " + \
                            self.securettypath + "\n"
                if not writeFile(tempfile, "", self.logger):
                    success = False
                    self.detailedresults += "Unable to write blank contents " + \
                        "to " + self.securettypath + "\n"
                else:
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    event = {"eventtype": "conf",
                             "filepath": self.securettypath}
                    self.statechglogger.recordchgevent(myid, event)
                    self.statechglogger.recordfilechange(self.securettypath, tempfile, myid)
                    os.rename(tempfile, self.securettypath)
                    os.chmod(self.securettypath, 0o600)
                    os.chown(self.securettypath, 0, 0)
                    resetsecon(self.securettypath)
            else:
                if not checkPerms(self.securettypath, [0, 0, 0o600], self.logger):
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    if not setPerms(self.securettypath, [0, 0, 0o600], self.logger,
                                    self.statechglogger, myid):
                        success = False
                        self.detailedresults += "Unable to correct permissions on " + \
                                                self.securettypath + "\n"
            self.rulesuccess = success
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
