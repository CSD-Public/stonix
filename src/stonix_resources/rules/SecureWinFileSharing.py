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
Created on Nov 12, 2013

This class will secure samba file sharing

@author: bemalmbe
@change: 04/21/2014 dkennel Updated CI invocation
@change: 2015/10/08 eball Help text cleanup
@change: 2016/04/26 ekkeahrd Results Formatting
@change: 2016/07/26 Breen Malmberg - added smb signing functionality for mac os x;
fixed several doc blocks; fixed typo with license block; added
check for CI enabled/disabled in fix() method; changed the return value
in report() method to self.compliant
@change: 2019/07/17 Brandon R. Gonzales - Make applicable to MacOS 10.13-10.14
    and all Linux
@change: 2019/08/07 ekkehard - enable for macOS Catalina 10.15 only
'''



from ..ruleKVEditor import RuleKVEditor
from ..logdispatcher import LogPriority
from ..KVEditorStonix import KVEditorStonix

import os
import traceback


class SecureWinFileSharing(RuleKVEditor):
    '''This class will secure samba file sharing
    
    @author: Breen Malmberg


    '''

    def __init__(self, config, environ, logger, statechglogger):
        '''
        Constructor
        '''

        RuleKVEditor.__init__(self, config, environ, logger, statechglogger)
        self.config = config
        self.environ = environ
        self.logger = logger
        self.statechglogger = statechglogger
        self.rulenumber = 142
        self.rulename = 'SecureWinFileSharing'
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.sethelptext()
        self.rootrequired = True
        self.guidance = ['']
        self.applicable = {'type': 'white',
                           'os': {'Mac OS X': ['10.15.0', 'r', '10.15.10']},
                           'family': ['linux']}

        # init CIs
        datatype = 'bool'
        key = 'SECUREWINFILESHARING'
        instructions = '''To disable the configuration of samba file sharing on this system, set the
value of SecureWinFileSharing to False.'''
        default = True
        self.SecureWinFileSharing = self.initCi(datatype, key, instructions,
                                                default)

        # smb signing for mac os x
        if self.environ.getostype() == "Mac OS X":
            self.addKVEditor("EnableSigning",
                             "defaults",
                             "/Library/Preferences/SystemConfiguration/com.apple.smb.server",
                             "",
                             {"SigningEnabled": ["1", "-bool yes"]},
                             "present",
                             "",
                             "To prevent the this rule from enabling and requiring signing, set the value of \
                             SecureWinFileSharing to False.",
                             self.SecureWinFileSharing)
            self.addKVEditor("RequireSigning",
                             "defaults",
                             "/Library/Preferences/SystemConfiguration/com.apple.smb.server",
                             "",
                             {"SigningRequired": ["1", "-bool yes"]},
                             "present",
                             "",
                             "To prevent the this rule from enabling and requiring signing, set the value of \
                             SecureWinFileSharing to False.",
                             self.SecureWinFileSharing)

        # #possible smb.conf locations
        # debian = /etc/samba/smb.conf
        # slackware = /etc/samba/smb.conf
        # rhlinux = /etc/samba/smb.conf
        # solaris = /usr/local/samba/lib/smb.conf, /etc/sfw/samba/smb.conf
        # freebsd = /usr/local/etc/smb.conf
        # suse = /etc/samba/smb.conf
        # ubuntu = /etc/samba/smb.conf

        self.smbconflocations = ['/etc/samba/smb.conf',
                                 '/usr/local/samba/lib/smb.conf',
                                 '/etc/sfw/samba/smb.conf',
                                 '/usr/local/etc/smb.conf']

        # establish default location
        self.smbconflocation = '/etc/samba/smb.conf'

        # find and specify actual location (if different from default location)
        for location in self.smbconflocations:
            if os.path.exists(location):
                self.smbconflocation = location

        # init the kveditor object
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
        kvpath = self.smbconflocation
        kvtype = 'tagconf'
        kvtmppath = kvpath + '.stonixtmp'
        kvintent = 'present'
        kvconftype = 'openeq'

        # create the kveditor object to be used in report() and fix() methods
        self.kvosmb = KVEditorStonix(self.statechglogger, self.logger, kvtype,
                                     kvpath, kvtmppath, smbDirectives,
                                     kvintent, kvconftype)

    def isapplicable(self):
        '''determine applicability


        :returns: applicability

        :rtype: bool
@author: Breen Malmberg

        '''

        applicability = False

        if os.path.exists(self.smbconflocation):
            applicability = True
        if self.environ.getostype() == "Mac OS X":
            applicability = True

        return applicability

    def report(self):
        '''Report whether the current smb.conf file has the necessary/specified configuration directives
        Update self.compliant, self.currstate and self.detailedresults


        :returns: self.compliant

        :rtype: bool
@author: Breen Malmberg

        '''

        self.detailedresults = ""
        self.compliant = True

        try:

            if os.path.exists(self.smbconflocation):
                if not self.kvosmb.report():
                    self.compliant = False
                    self.detailedresults += "The following configuration options were missing from : " + str(self.smbconflocation) + "\n" + "\n".join(self.kvosmb.fixables)
            if self.environ.getostype() == "Mac OS X":
                if not RuleKVEditor.report(self, True):
                    self.compliant = False

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

    def fix(self):
        '''Make secure configuration changes to smb.conf


        :returns: self.rulesuccess

        :rtype: bool
@author: Breen Malmberg

        '''

        # defaults
        self.detailedresults = ""
        self.rulesuccess = True

        try:

            if self.SecureWinFileSharing.getcurrvalue():

                if os.path.exists(self.smbconflocation):

                    myid = '0142001'
        
                    self.kvosmb.setEventID(myid)
                    if not self.kvosmb.fix():
                        self.rulesuccess = False
                        self.detailedresults += "KVEditor.fix() failed"
                    if not self.kvosmb.commit():
                        self.rulesuccess = False
                        self.detailedresults += "KVEditor.commit() failed"

                if self.environ.getostype() == "Mac OS X":
                    if not RuleKVEditor.fix(self, True):
                        self.rulesuccess = False
                        self.detailedresults += "RuleKVEditor.fix() failed"

            else:
                self.logger.log(LogPriority.DEBUG, "The SecureWinFileSharing CI was disabled when fix() ran, so nothing was done.")
                self.detailedresults += "\nThe CI for this rule was already set to disabled when the rule ran, so nothing was fixed."

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.rulesuccess
