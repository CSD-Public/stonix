###############################################################################
#                                                                             #
# Copyright 2015-2019.  Los Alamos National Security, LLC. This material was  #
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
Created on Aug 8, 2013

@author: dwalker
@change: 04/18/2014 dkennel Replaced old style CI with new
@change: 2014/10/17 ekkehard OS X Yosemite 10.10 Update
@change: 2015/04/15 dkennel updated for new isApplicable
@change 2017/08/28 rsn Fixing to use new help text methods
'''
from __future__ import absolute_import
from ..stonixutilityfunctions import resetsecon, checkPerms
from ..stonixutilityfunctions import setPerms, iterate
from ..rule import Rule
from ..logdispatcher import LogPriority
from subprocess import call
import os
from ..KVEditorStonix import KVEditorStonix
import traceback


class DisableNobodyAccess(Rule):

    def __init__(self, config, environ, logger, statechglogger):
        Rule.__init__(self, config, environ, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 71
        self.rulename = "DisableNobodyAccess"
        self.mandatory = True
        self.helptext = "The keyserv process stores user keys that are " + \
        "utilized with Sun's secure RPC mechanism. This rule prevents " + \
        "keyserv from using default keys for the \"nobody\" user, " + \
        "effectively stopping this user from accessing information " + \
        "via secure RPC."
        self.guidance = ['NSA 6.2']
        self.detailedresults = "DisableNobodyAccess has not yet been run."
        self.applicable = {'type': 'white',
                           'family': ['solaris']}

        #configuration item instantiation
        datatype = 'bool'
        key = 'DISABLENOBODYACCESS'
        instructions = "To disable this rule set the value of " + \
        "DISABLENOBODYACCESS to False."
        default = True
        self.ci = self.initCi(datatype, key, instructions, default)

        self.iditerator = 0
        self.path = "/etc/default/keyserv"
        self.editor = ""
        self.sethelptext()

    def report(self):
        '''
        DisableNobodyAccess.report() method to report on whether system is
        compliant or not. If the key-value pair ENABLE_NOBODY_KEYS=NO
        is present, the system is compliant, if not, system is not compliant
        @author: dwalker
        @return: bool - False if the method died during execution
        @param self:essential if you override this definition
        '''
        try:
            compliant = True
            keys = {"ENABLE_NOBODY_KEYS": "NO"}
            if os.path.exists(self.path):
                tmpPath = self.path + ".tmp"
                self.editor = KVEditorStonix(self.statechglogger, self.logger,
                       "conf", self.path, tmpPath, keys, "present", "closedeq")
                if not self.editor.report():
                    compliant = False
                if not checkPerms(self.path, [0, 0, 292], self.logger):
                    compliant = False
            else:
                self.createFile(self.path)
                self.created = True
                self.editor = KVEditorStonix(self.statechglogger, self.logger,
                       "conf", self.path, tmpPath, keys, "present", "closedeq")
                self.editor.fixables = keys
                compliant = False
            self.compliant = compliant
            return compliant
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
        '''
        DisableNobodyAccess.fix() method to insert the key value pair of
        ENABLE_NOBODY_KEYS=NO if not present in the necessary file.
        @author: dwalker
        @param self - essential if you override this definition
        @return: bool - True if fix is successful, False if it isn't
        '''
        try:
            if not self.ci.getcurrvalue():
                return

            #clear out event history so only the latest fix is recorded
            self.iditerator = 0
            eventlist = self.statechglogger.findrulechanges(self.rulenumber)
            for event in eventlist:
                self.statechglogger.deleteentry(event)

            if self.created:
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                event = {"eventtype": "creation",
                         "filepath": self.path}
                self.statechglogger.recordchgevent(myid, event)
                if self.editor.fix():
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    self.editor.setEventID(myid)
                    if self.editor.commit():
                        os.chown(self.path, 0, 0)
                        os.chmod(self.path, 292)
                        resetsecon(self.path)
                    else:
                        self.rulesuccess = False
                else:
                    self.rulesuccess = False
            else:
                if not checkPerms(self.path, [0, 0, 292], self.logger):
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    if not setPerms(self.path, [0, 0, 292], self.logger,
                                                    self.statechglogger, myid):
                        self.rulesuccess = False
                if self.editor.fixables:
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    self.editor.setEventID(myid)
                    if not self.editor.fix():
                        self.rulesuccess = False
                    elif not self.editor.commit():
                        self.rulesuccess = False
                    os.chown(self.path, 0, 0)
                    os.chmod(self.path, 292)
                    resetsecon(self.path)
                    retval = call(["/usr/sbin/pkgchk", "-f", "-n", "-p",
                                   "/etc/default/keyserv"], stdout=None,
                                  shell=False)
                    if retval != 0:
                        self.rulesuccess = False
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
