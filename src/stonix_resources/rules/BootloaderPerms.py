###############################################################################
#                                                                             #
# Copyright 2015-2017.  Los Alamos National Security, LLC. This material was  #
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

This rule will verify the permissions on the boot loader config file to be 
root:root and 600

@author: Breen Malmberg
@change: 02/12/2014 ekkehard Implemented self.detailedresults flow
@change: 02/12/2014 ekkehard Implemented isapplicable
@change: 04/18/2014 dkennel - Moved to new style CI. Fixed bug in fix
    method where CI was not referenced before executing fix actions.
@change: 2014/10/17 ekkehard OS X Yosemite 10.10 Update
@change: 2015/10/07 eball Help text cleanup
@change: 2017/05/04 Breen Malmberg added logging and detailedresults output
'''

from __future__ import absolute_import

from ..rule import Rule
from ..logdispatcher import LogPriority
from ..stonixutilityfunctions import getOctalPerms, resetsecon, iterate
import os
import traceback
import stat


class BootloaderPerms(Rule):
    '''
    This rule will verify the permissions on the boot loader config file to be
    root:root and 600

    @author: Breen Malmberg
    @change: 04/18/2014 dkennel - Moved to new style CI. Fixed bug in fix
    method where CI was not referenced before executing fix actions.
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
        self.rulenumber = 146
        self.rulename = 'BootloaderPerms'
        self.formatDetailedResults("initialize")
        self.compliant = False
        self.mandatory = True
        self.sethelptext()
        self.rootrequired = True
        self.guidance = ['NSA(2.3.5.2)', 'cce-4144-2', '3923-0, 4197-0']

        # init CIs
        datatype = 'bool'
        key = 'BOOTLOADERPERMS'
        instructions = 'To prevent setting of permissions on the grub ' + \
            'bootloader file, set the value of BootLoaderPerms to False'
        default = True
        self.BootloaderPerms = self.initCi(datatype, key, instructions, default)

        self.bootloaderpathlist = ['/etc/grub.conf', '/boot/grub/grub.cfg',
                                   '/boot/grub/grub.conf',
                                   '/boot/grub/menu.lst',
                                   '/boot/efi/EFI/redhat/grub.cfg',
                                   '/boot/grub2/grub.cfg']

    def isapplicable(self):
        '''
        Determine if this rule is applicable to the current system

        @return: applicable
        @rtype: bool
        @author: Breen Malmberg
        @change: 02/12/2014 ekkehard update to exclude old OS X version
        '''

        # defaults
        applicable = False

        for path in self.bootloaderpathlist:
            if os.path.exists(path):
                applicable = True

        return applicable

    def report(self):
        '''
        Verify the ownership and permissions of the boot loader config file to
        be root:root and 600 - respectively
        Return True if they are both set to these respective values
        Return False if one or more are not set to the respective owner and permissions values

        @return: self.compliant
        @rtype: bool
        @author: Breen Malmberg
        '''

        # defaults
        self.compliant = True
        self.detailedresults = ""

        try:

            for path in self.bootloaderpathlist:
                if os.path.exists(path):

                    perms = getOctalPerms(path)
                    stat_info = os.stat(path)
                    uid = stat_info.st_uid
                    gid = stat_info.st_gid

                    if uid != 0:
                        self.compliant = False
                        self.detailedresults += "\nOwner on file " + str(path) + " is incorrect"
                        self.logger.log(LogPriority.DEBUG, "Owner on file " + str(path) + " is incorrect")

                    if gid != 0:
                        self.compliant = False
                        self.detailedresults += "\nGroup on file " + str(path) + " is incorrect"
                        self.logger.log(LogPriority.DEBUG, "Group on file " + str(path) + " is incorrect")

                    if perms != 600:
                        self.compliant = False
                        self.detailedresults += "\nPermissions on file " + str(path) + " are incorrect"
                        self.logger.log(LogPriority.DEBUG, "Permissions on file " + str(path) + " are incorrect")

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.compliant = False
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

    def fix(self):
        '''
        Set the owner and group of the boot loader config file to root:root
        Set the permissions on the boot loader config file to 600
        Return True if no problems were encountered while setting these values
        Return False if any errors or problems were encountered while setting these values

        @return: self.rulesuccess
        @rtype: bool
        @author: Breen Malmberg
        '''

        # defaults
        self.detailedresults = ""
        self.iditerator = 0
        self.rulesuccess = False

        try:

            if self.BootloaderPerms.getcurrvalue():

                for path in self.bootloaderpathlist:
                    if os.path.exists(path):

                        self.logger.log(LogPriority.DEBUG, "Your boot loader config file detected as: " + str(path))
                        self.logger.log(LogPriority.DEBUG, "Setting ownership and permissions...")

                        stat_info = os.stat(path)
                        perms = stat.S_IMODE(stat_info.st_mode)
                        uid = stat_info.st_uid
                        gid = stat_info.st_gid

                        event = {'eventtype': 'perm',
                                 'startstate': [uid, gid, perms],
                                 'filepath': path}

                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)

                        os.chown(path, 0, 0)
                        os.chmod(path, 0600)
                        resetsecon(path)

                        self.statechglogger.recordchgevent(myid, event)
                        self.rulesuccess = True

                        self.logger.log(LogPriority.DEBUG, "Finished setting ownership and permissions on file " + str(path))

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.rulesuccess
