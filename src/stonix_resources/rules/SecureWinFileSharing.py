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
'''

from __future__ import absolute_import

from ..rule import Rule
from ..logdispatcher import LogPriority
from ..KVEditorStonix import KVEditorStonix

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
        self.currstate = 'notconfigured'
        self.targetstate = 'configured'
        self.rulename = 'SecureWinFileSharing'
        self.compliant = False
        self.mandatory = True
        self.helptext = '''This class will secure samba file sharing'''
        self.rootrequired = True
        self.detailedresults = '''The SecureWinFileSharing rule has not yet been run.'''
        self.guidance = ['']

        # init CIs
        datatype = 'bool'
        key = 'SecureWinFileSharing'
        instructions = '''To disable the configuration of samba file sharing on this system, set the
value of SecureWinFileSharing to False.'''
        default = True
        self.SecureWinFileSharing = self.initCi(datatype, key, instructions,
                                                default)

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

        self.kvosmb = KVEditorStonix(self.statechglogger, self.logger, kvtype,
                                     kvpath, kvtmppath, smbDirectives,
                                     kvintent, kvconftype)

    def isapplicable(self):
        '''

        @return: bool
        @author: bemalmbe
        '''

        if os.path.exists(self.smbconflocation):
            return True
        else:
            return False

    def report(self):
        '''
        Report whether the current smb.conf file has the necessary/specified configuration directives
        Update self.compliant, self.currstate and self.detailedresults

        @return: bool
        @author: bemalmbe
        '''

        # defaults
        secure = True

        try:

            if not self.kvosmb.report():
                secure = False

            if secure:
                self.compliant = True
                self.currstate = 'configured'
                self.detailedresults = 'This system is compliant with the SecureWinFileSharing rule.'
            else:
                self.compliant = False
                self.currstate = 'notconfigured'
                self.detailedresults = 'This system is not compliant with the SecureWinFileSharing rule.'

            return secure

        except (KeyError, TypeError):
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.DEBUG, self.detailedresults)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
            return self.rulesuccess

    def fix(self):
        '''
        Make secure configuration changes to smb.conf

        @author: bemalmbe
        '''

        try:

            myid = '0142001'

            self.kvosmb.setEventID(myid)
            self.kvosmb.fix()
            self.kvosmb.commit()

        except KeyError:
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.DEBUG, self.detailedresults)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
