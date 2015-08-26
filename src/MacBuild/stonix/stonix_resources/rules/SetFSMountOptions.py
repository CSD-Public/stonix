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
        self.compliant = False
        self.ci = self.initCi("bool",
                              "SetFSMountOptions",
                              "To prevent the configuration of " + \
                              "mount options, set the value of " + \
                              "SetFSMountOptions to False.",
                              True)
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
        retval = True
        self.detailedresults = ''
        foundcfgline = False

        try:

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
                                retval = False
                        elif sline[2] in self.removeables:
                            for item in self.removeablelist:
                                if item not in sline[3]:
                                    retval = False
                        elif sline[1] in self.temporarytypes:
                            for item in self.temporarytypeslist:
                                if item not in sline[3]:
                                    retval = False

                except IndexError:
                    continue

                if re.search('^' + self.bindmnttmp, line):
                        foundcfgline = True

            if retval and foundcfgline:
                self.compliant = True
            else:
                self.compliant = False

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
        self.detailedresults = ''
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
