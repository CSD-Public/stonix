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

Created on Nov 12, 2013

This class will secure samba file sharing

@author: bemalmbe
@change: 04/21/2014 dkennel Updated CI invocation
@change: 2015/10/08 eball Help text cleanup
'''

from __future__ import absolute_import

from ..rule import Rule
from ..logdispatcher import LogPriority
from ..KVEditorStonix import KVEditorStonix
from ..stonixutilityfunctions import iterate, checkPerms, setPerms, resetsecon

import os
import traceback


class SecureWinFileSharing(Rule):
    '''
    This class will secure samba file sharing

    @author: bemalmbe
    '''

    def __init__(self, config, environ, logger, statechglogger):
        '''
        Constructor
        '''

        Rule.__init__(self, config, environ, logger, statechglogger)
        self.config = config
        self.environ = environ
        self.logger = logger
        self.statechglogger = statechglogger
        self.rulenumber = 142
        self.rulename = 'SecureWinFileSharing'
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.helptext = '''This rule will secure SAMBA file sharing settings'''
        self.rootrequired = True
        self.guidance = ['']

        # init CIs
        datatype = 'bool'
        key = 'SecureWinFileSharing'
        instructions = '''To disable the configuration of samba file sharing on this system, set the
value of SecureWinFileSharing to False.'''
        default = True
        self.securewinfileShare = self.initCi(datatype, key, instructions,
                                                default)
        
        datatype = 'bool'
        key = 'DisablePrinterSharing'
        instructions = "To prevent the disabling of printer sharing " + \
            "set the value of DISBLEPRINTSHARE to False. If there are no " + \
            "printers on the local machine or if printer sharing with " + \
            "Microsoft Windows is not required this should be enabled to " + \
            "disable the printer sharing capability."
        default = True
        self.disableprintshare = self.initCi(datatype, key, instructions, default)
        # #possible smb.conf locations
        # debian = /etc/samba/smb.conf
        # slackware = /etc/samba/smb.conf
        # rhlinux = /etc/samba/smb.conf
        # solaris = /usr/local/samba/lib/smb.conf, /etc/sfw/samba/smb.conf
        # freebsd = /usr/local/etc/smb.conf
        # suse = /etc/samba/smb.conf
        # ubuntu = /etc/samba/smb.conf

        # init the kveditor object
        self.iditerator = 0

    def report(self):
        '''
        Report whether the current smb.conf file has the necessary/specified configuration directives
        Update self.compliant, self.currstate and self.detailedresults

        @return: bool
        @author: bemalmbe
        '''
        try:
            self.detailedresults = ""
            compliant = True
            self.smbconflocations = ['/etc/samba/smb.conf',
                                 '/usr/local/samba/lib/smb.conf',
                                 '/etc/sfw/samba/smb.conf',
                                 '/usr/local/etc/smb.conf']
''
            self.smbconflocation = ""
            # find and specify actual location (if different from default location)
            for location in self.smbconflocations:
                if os.path.exists(location):
                    self.smbconflocation = location
            if not self.smbconflocation:
                # establish default location
                self.smbconflocation = '/etc/samba/smb.conf'
            if not os.path.exists(self.smbconflocation):
                '''If file doesn't exist the system is compliant'''
                self.compliant = compliant
            else:
                kvpath = self.smbconflocation
                kvtype = "tagconf"
                kvtmppath = kvpath + '.stonixtmp'
                kvconftype = 'openeq'
                smbDirectives = {'global': {'restrict anonymous': '2',
                            'guest ok': 'no',
                            'client ntlmv2 auth': 'yes',
                            'client lanman auth': 'no',
                            'client plaintext auth': 'no',
                            'ntlm auth': 'no',
                            'lanman auth': 'no',
                            'invalid users': 'root @wheel',
                            'server signing': 'mandatory',
                            'client signing': 'mandatory'}}
                
                kvintent = 'present'
                self.kvosmb1 = KVEditorStonix(self.statechglogger, self.logger,
                                              kvtype, kvpath, kvtmppath,
                                              smbDirectives, kvintent,
                                              kvconftype)
                if not self.kvosmb1.report():
                    compliant = False
                kvintent = "notpresent"
                smbDirectives = {"global": {"load printers": "",
                                            "cups options": ""},
                                 "printers":{"comment": "",
                                             "path": "",
                                             "browseable": "",
                                             "guest ok": "",
                                             "writable": "",
                                             "printable": ""}}
                
                self.kvosmb2 = KVEditorStonix(self.statechglogger, self.logger,
                                              kvtype, kvpath, kvtmppath,
                                              smbDirectives, kvintent,
                                              kvconftype)
                if not self.kvosmb2.report():
                    compliant = False
            self.compliant = compliant
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

    def fix(self):
        '''
        Make secure configuration changes to smb.conf

        @author: bemalmbe
        '''

        try:
            self.detailedresults = ""
            if not self.securewinfileShare.getcurrvalue() and not \
                self.disableprintshare.getcurrvalue():
                return
            # Clear out event history so only the latest fix is recorded
            eventlist = self.statechglogger.findrulechanges(self.rulenumber)
            for event in eventlist:
                self.statechglogger.deleteentry(event)
            success = True
            debug = ""
            if self.securewinfileShare.getcurrvalue():
                if self.kvosmb1.fixables:
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    self.kvosmb1.setEventID(myid)
                    if self.kvosmb1.fix():
                        debug += "kvosmb1 fix ran successfully\n"
                        if self.kvosmb1.commit():
                            debug += "kvosmb1 commit ran successfully\n"
                            os.chown(self.kvosmb1.getPath(), 0, 0)
                            os.chmod(self.kvosmb1.getPath(), 420)
                            resetsecon(self.kvosmb1.getPath())
                        else:
                            debug += "Unable to complete kvosmb1 commit\n"
                            success = False
                    else:
                        debug += "Unable to complete kvosmb1 fix\n"
                        success = False
            if self.disableprintshare.getcurrvalue():
                if self.kvosmb2.removeables:
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    self.kvosmb2.setEventID(myid)
                    if self.kvosmb2.fix():
                        debug += "kvosmb2 fix ran successfully\n"
                        if self.kvosmb2.commit():
                            debug += "kvosmb2 commit ran successfully\n"
                            os.chown(self.kvosmb2.getPath(), 0, 0)
                            os.chmod(self.kvosmb2.getPath(), 420)
                            resetsecon(self.kvosmb2.getPath())
                        else:
                            debug += "Unable to complete kvosmb2 commit\n"
                            success = False
                    else:
                        debug += "Unable to complete kvosmb2 fix\n"
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