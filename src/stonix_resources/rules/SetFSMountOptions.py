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

Created on Apr 10, 2013

SetFSMountOptions sets the file system mount options for non-Root local
partitions, file systems mounted on removable media, removable storage
partitions, and temporary storage partitions such as /tmp and /dev/shm in
order to help protect against malicious code being run on the system.

@author: bemalmbe
@change: 02/13/2014 ekkehard Implemented self.detailedresults flow
@change: 02/13/2014 ekkehard Implemented isapplicable
@change: 04/18/2014 ekkehard ci updates and ci fix method implementation
@change: 09/09/2014 bemalmbe fix and report methods rewritten to use new methods;
                            added dictSearch() and dictFix() methods; added
                            in-line comments
@change: 2015/04/17 dkennel updated for new isApplicable
'''
from __future__ import absolute_import
from ..rule import Rule
from ..stonixutilityfunctions import iterate
from ..logdispatcher import LogPriority

import os
import re
import traceback


class SetFSMountOptions(Rule):
    '''
    SetFSMountOptions sets the file system mount options for non-Root local
    partitions, file systems mounted on removable media, removable storage
    partitions, and temporary storage partitions such as /tmp and /dev/shm in
    order to help protect against malicious code being run on the system.

    @author bemalmbe
    '''

    def __init__(self, config, environ, logger, statechglogger):
        '''
        Constructor
        '''
        Rule.__init__(self, config, environ, logger, statechglogger)
        self.config = config
        self.environ = environ
        self.statechglogger = statechglogger
        self.logger = logger
        self.rulenumber = 21
        self.rulename = 'SetFSMountOptions'
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.helptext = "SetFSMountOptions sets the file system mount " + \
        "options for non-Root local partitions, file systems mounted on " + \
        "removable media, removable storage partitions, and temporary " + \
        "storage partitions such as /tmp and /dev/shm in order to help " + \
        "protect against malicious code being run on the system."
        self.rootrequired = True

        # set up CI's
        datatype = "bool"
        key = "SetFSMountOptions"
        instructions = "To prevent the configuration of mount options, set the value of SetFSMountOptions to False."
        default = True
        self.ci = self.initCi(datatype, key, instructions, default)
        datatype2 = 'bool'
        key2 = 'NFSRoot'
        instructions2 = 'If this system uses an NFS mounted root, set the value of NFSRoot to True.'
        default2 = False
        self.NFSRootci = self.initCi(datatype2, key2, instructions2, default2)

        self.guidance = ['CIS NSA(2.2.1.1)', 'cce4249-9', 'cce4368-7',
                         'cce4024-6', 'cce4526-0', 'CIS NSA(2.2.1.2)',
                         'cce3522-0', 'cce4042-8', 'cce4315-8']

        self.applicable = {'type': 'black',
                           'family': ['darwin', 'solaris', 'freebsd']}

        # list of local fs types
        self.localfstypes = ['ext2', 'ext3', 'ext4', 'xfs', 'jfs', 'reiser',
                             'reiserfs']
        self.localfstypesoptions = ['nodev']

        # temp mount points options dict
        self.temporarytypes = ['/dev/shm', '/tmp']
        self.temporarytypeslist = ['nodev', 'nosuid', 'noexec']

        # removeable fs types options dict
        self.removeables = ['floppy', 'cdrom']
        self.removeablelist = ['nodev', 'nosuid', 'noexec']

        # config line to check for
        self.bindmnttmp = '/tmp /var/tmp none rw,noexec,nosuid,nodev,bind 0 0'

        # possible locations of fstab file
        fstablocations = ['/etc/fstab', '/etc/vfstab']

        self.filepath = ''
        for location in fstablocations:
            if os.path.exists(location):
                self.filepath = location

    def report(self):
        """
        The report method examines the current configuration and determines
        whether or not it is correct. If the config is correct then the
        self.compliant, self.detailed results and self.currstate properties are
        updated to reflect the system status. self.rulesuccess will be updated
        if the rule does not succeed.

        @return bool
        @author bemalmbe
        @change: bemalmbe 09/05/2014 rewritten rule to be more atomic, less
                complex and more human-readable
        """

        # defaults
        self.detailedresults = ""
        foundcfgline = False
        self.compliant = True

        try:

            if not self.checknfs():
                self.compliant = False
                self.logger.log(LogPriority.DEBUG, "checknfs() returned non compliant")

            # search for the various config options
            f = open(self.filepath, 'r')
            contentlines = f.readlines()
            f.close()

            for line in contentlines:
                sline = line.split()

                try:

                    if sline[0] != '#' and sline[0] != '\n' and sline[1] != '/':
                        if sline[2] in self.localfstypes:
                            if 'nodev' not in sline[3]:
                                self.compliant = False
                                self.detailedresults += "\nLine:\n" + str(line) + "\nis missing the required option: nodev"
                        elif sline[2] in self.removeables:
                            for item in self.removeablelist:
                                if item not in sline[3]:
                                    self.compliant = False
                                    self.detailedresults += "\nLine:\n" + str(line) + "\nis missing one or more of the following required options: " + "".join(self.removeablelist)
                        elif sline[1] in self.temporarytypes:
                            for item in self.temporarytypeslist:
                                if item not in sline[3]:
                                    self.compliant = False
                                    self.detailedresults += "\nLine:\n" + str(line) + "\nis missing one or more of the following required options: " + "".join(self.temporarytypeslist)

                except IndexError:
                    continue

                if re.search('^' + self.bindmnttmp, line):
                        foundcfgline = True

            if not foundcfgline:
                self.compliant = False
                self.detailedresults += "\nA required configuration line:\n" + str(self.bindmnttmp) + "\n was not found"

        except (KeyboardInterrupt, SystemExit):
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

    def checknfs(self):
        '''
        check if all nfs mounts use packet signing
        this is an audit-only action

        @return: retval
        @rtype: bool
        @author: Breen Malmberg
        '''

        self.logger.log(LogPriority.DEBUG, "Running checknfs() method...")

        retval = True
        options = ['sec=krb5i', 'sec=ntlmv2i']
        fstabfile = '/etc/fstab'
        nodev = 'nodev'
        nosuid = 'nosuid'
        sambasharedetected = False
        nfsmountdetected = False
        smboptdict = {'sec=krb5i': False,
                      'sec=ntlmv2i': False}
        nfsmountdict = {nodev: True,
                        nosuid: True}

        try:

            if not os.path.exists(fstabfile):
                self.logger.log(LogPriority.DEBUG, "Could not locate the fstab file on this system")
                retval = False
                return retval

            self.logger.log(LogPriority.DEBUG, "Attempting to open file: " + str(fstabfile) + " ...")
            f = open(fstabfile, 'r')
            contentlines = f.readlines()
            f.close()
            self.logger.log(LogPriority.DEBUG, "Successfully retrieved contents of file: " + str(fstabfile))

            self.logger.log(LogPriority.DEBUG, "Beginning check for required samba share mount options...")
            for line in contentlines:
                sline = line.split()
                if len(sline) < 3:
                    continue
                else:
                    if not re.search('^cifs$', str(sline[2]).strip().lower()):
                        continue
                    else:
                        self.logger.log(LogPriority.DEBUG, "Samba share detected. Checking for required options...")
                        sambasharedetected = True
                        for option in options:
                            if re.search(option, str(line).lower()):
                                smboptdict[option] = True
                        for option in smboptdict:
                            if not smboptdict[option]:
                                retval = False
                                self.detailedresults += '\nNo packet signing option specified for samba share on line:\n' + line
            if sambasharedetected:
                if retval:
                    self.detailedresults += "\nAll detected samba shares have packet signing enabled."
                if not retval:
                    self.detaildresults += "\nOne or more detected samba shares do not have packet signing enabled!"
            else:
                self.logger.log(LogPriority.DEBUG, "No samba shares detected on this system.")

            for line in contentlines:
                sline = line.split()
                if len(sline) < 4:
                    continue
                else:
                    if re.search('^nfs$', str(sline[2]).strip().lower()):
                        nfsmountdetected = True
                        self.logger.log(LogPriority.DEBUG, "NFS mount detected. Checking for required options...")
                        if not re.search(nodev, str(sline[3]).strip().lower()):
                            retval = False
                            nfsmountdict[nodev] = False
                            self.detailedresults += '\nnfs mount line missing option: ' + nodev
                        if not self.NFSRootci:
                            self.logger.log(LogPriority.DEBUG, "NFSRoot ci is disabled; performing check for nosuid option...")
                            if not re.search(nosuid, str(sline[3]).strip().lower()):
                                retval = False
                                nfsmountdict[nosuid] = False
                                self.detailedresults += '\nnfs mount line missing option: ' + nosuid
                        else:
                            self.logger.log(LogPriority.DEBUG, "NFSRoot ci is enabled; skipping nosuid check...")
            if not nfsmountdetected:
                self.logger.log(LogPriority.DEBUG, "No nfs mounts detected on this system.")
            else:
                if retval:
                    self.detailedresults += "\nAll nfs mount entries contain the required options."
                else:
                    for opt in nfsmountdict:
                        if not nfsmountdict[opt]:
                            self.detailedresults += "\nOne or more nfs mount entries is missing the required: " + str(opt) + " option."

        except Exception:
            raise
        return retval

    def fix(self):
        """
        The fix method will apply the required settings to the system.
        self.rulesuccess will be updated if the rule does not succeed.

        @author bemalmbe
        @change: 2014/06/02 dkennel - line 180 changed
        if os.path.exists():
        to
        if os.path.exists(filename):
        @change: 2014/09/09 bemalmbe - method rewritten to use new method
                dictFix()
        """

        # defaults
        self.iditerator = 0
        self.detailedresults = ""
        tmpfile = self.filepath + '.stonixtmp'
        bindtmplinefound = False

        try:

            if self.ci.getcurrvalue():

                f = open(self.filepath, 'r')
                contentlines = f.readlines()
                f.close()

                for line in contentlines:
                    sline = line.split()

                    try:

                        if sline[0] != '#' and sline[0] != '\n' and sline[1] != '/':
                            if sline[2] in self.localfstypes:
                                if 'nodev' not in sline[3]:
                                    sline[3] += ',nodev'
                            elif sline[2] in self.removeables:
                                for item in self.removeablelist:
                                    if item not in sline[3]:
                                        sline[3] += ',' + item
                            elif sline[1] in self.temporarytypes:
                                for item in self.temporarytypeslist:
                                    if item not in sline[3]:
                                        sline[3] += ',' + item

                    except IndexError:
                        continue

                    newLine = ''
                    for item in sline:
                        if sline[0] == '#':
                            newLine += item + ' '
                        else:
                            newLine += item + '    '
                    newLine += '\n'

                    contentlines = [c.replace(line, newLine) for c in contentlines]

                    if re.search('^' + self.bindmnttmp, line):
                        bindtmplinefound = True

                if not bindtmplinefound:
                    contentlines.append('\n' + self.bindmnttmp + '\n')

                tf = open(tmpfile, 'w')
                tf.writelines(contentlines)
                tf.close()

                # undo stuff
                event = {'eventtype': 'conf',
                         'filepath': self.filepath}
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)

                self.statechglogger.recordchgevent(myid, event)
                self.statechglogger.recordfilechange(self.filepath, tmpfile, myid)

                os.rename(tmpfile, self.filepath)
                os.chmod(self.filepath, 0644)
                os.chown(self.filepath, 0, 0)

            else:

                self.detailedresults += '\n' + str(self.ci.getkey()) + \
                ' was disabled. No action was taken.'

        except (OSError, KeyError, IndexError):
            self.rulesuccess = False
            self.detailedresults += ' - ' + str(traceback.format_exc())
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as err:
            self.rulesuccess = False
            self.detailedresults += '\n' + str(err) + ' - ' + \
            str(traceback.format_exc())
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults('fix', self.rulesuccess,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.rulesuccess
