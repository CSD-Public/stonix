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
Created on Oct 18, 2011
The DisableUnusedFs object is responsible for auditing and removing unused
file system support from the kernel.
@operating system: Linux
@author: dkennel
@change: dkennel 04/18/2014 Replaced old style CI with new
@change: 2015/04/15 dkennel updated for new style isApplicable
@change: 2015/10/07 eball Help text/PEP8 cleanup
@change: 2016/05/26 ekkehard Results Formatting
@change: 2016/10/20 eball Results Formatting
@change: 2017/08/28 rsn Fixing to use new help text methods
'''

import os
import re
import traceback
import stat

from ..rule import Rule
from ..logdispatcher import LogPriority
from ..stonixutilityfunctions import resetsecon


class DisableUnusedFs(Rule):
    '''This class checks kernel configuration files to ensure that support for
    file system types not in regular use is disabled.


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
        self.rulenumber = 256
        self.rulename = 'DisableUnusedFs'
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.rootrequired = True
        self.blacklistfile = '/etc/modprobe.d/usgcb-blacklist.conf'

        datatype = 'bool'
        key = 'DISABLEFS'
        instructions = '''To disable this rule set the value of DISABLEFS to \
False.'''
        default = True
        self.disablefs = self.initCi(datatype, key, instructions, default)

        datatype2 = 'list'
        key2 = 'FSLIST'
        instructions2 = '''This list contains file system types that will be \
disabled. If you need to use a file system currently listed, remove it and \
the support for that file system type will not be disabled. This list should \
be space separated.'''
        default2 = ['cramfs', 'freevxfs', 'jffs2', 'hfs', 'hfsplus',
                    'squashfs']
        self.fslist = self.initCi(datatype2, key2, instructions2, default2)
        self.guidance = ['NSA 2.2.2.5']
        self.applicable = {'type': 'white',
                           'family': ['linux']}
        self.sethelptext()

    def report(self):
        '''Fssupport.report() Public method to report on the status of the
        uncommon filesystem support.


        '''
        compliant = True
        try:
            self.detailedresults = ""
            if not os.path.exists(self.blacklistfile):
                compliant = False
                self.logger.log(LogPriority.DEBUG,
                                ['DisableUnusedFs.report',
                                 "blacklist not found"])
            else:
                fhandle = open(self.blacklistfile, 'r')
                fdata = fhandle.readlines()
                fhandle.close()
                for fstype in self.fslist.getcurrvalue():
                    found = False
                    for line in fdata:
                        pattern = '^install ' + fstype + ' /bin/true'
                        if re.search(pattern, line):
                            found = True
                    if not found:
                        compliant = False
                        self.logger.log(LogPriority.DEBUG,
                                        ['DisableUnusedFs.report',
                                         "Directive not found " + pattern])

        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise

        except Exception:
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.ERROR,
                            ['DisableUnusedFs.report',
                             self.detailedresults])
            self.rulesuccess = False

        if compliant:
            self.detailedresults = """DisableUnusedFs: All unused filesystem \
support appears to be disabled."""
            self.currstate = 'configured'
            self.compliant = True
        else:
            self.detailedresults = """DisableUnusedFs: One or more unused \
filesystem support modules are not disabled."""
            self.currstate = 'notconfigured'
            self.compliant = False
        self.formatDetailedResults("report", self.compliant,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

    def fix(self):
        '''Fssupport.fix() Public method to set the uncommon fs support.'''
        self.detailedresults = ""
        if not self.disablefs.getcurrvalue():
            return True
        if not self.compliant:
            self.logger.log(LogPriority.DEBUG,
                            ['DisableUnusedFs.fix',
                             "Report is False starting fix"])
            try:
                tempfile = self.blacklistfile + '.stonixtmp'
                if os.path.exists(self.blacklistfile):
                    fhandle = open(self.blacklistfile, 'r')
                    fdata = fhandle.readlines()
                    fhandle.close()
                else:
                    fdata = []
                for fstype in self.fslist.getcurrvalue():
                    entry = 'install ' + fstype + ' /bin/true\n'
                    if entry not in fdata:
                        fdata.append(entry)
                whandle = open(tempfile, 'w')
                for line in fdata:
                    whandle.write(line)
                whandle.close()
                self.logger.log(LogPriority.DEBUG,
                                ['DisableUnusedFs.fix', "Recording changes"])
                if os.path.exists(self.blacklistfile):
                    mytype = 'conf'
                    mystart = self.currstate
                    myend = self.targetstate
                    myid = '0256001'
                    self.statechglogger.recordfilechange(self.blacklistfile,
                                                         tempfile, myid)
                else:
                    mytype = 'conf'
                    mystart = 'notpresent'
                    myend = 'present'
                    myid = '0256003'
                event = {'eventtype': mytype,
                         'startstate': mystart,
                         'endstate': myend}
                try:
                    statdata = os.stat(self.blacklistfile)
                    owner = statdata.st_uid
                    group = statdata.st_gid
                    mode = stat.S_IMODE(statdata.st_mode)
                except OSError:
                    owner = 0
                    group = 0
                    mode = 420

                if owner != 0 or group != 0 or mode != 420:
                    mytype2 = 'perm'
                    mystart2 = [owner, group, mode]
                    myend2 = [0, 0, 420]
                    myid2 = '0256002'
                    event2 = {'eventtype': mytype2,
                              'startstate': mystart2,
                              'endstate': myend2}
                    self.statechglogger.recordchgevent(myid2, event2)
                os.rename(tempfile, self.blacklistfile)
                os.chown(self.blacklistfile, 0, 0)
                os.chmod(self.blacklistfile, 420)
                resetsecon(self.blacklistfile)
                self.report()
                if self.currstate == self.targetstate:
                    self.statechglogger.recordchgevent(myid, event)
                else:
                    myfslist = self.fslist.getcurrvalue()
                    fsstring = ', '.join(myfslist)

                    self.detailedresults = '''DisableUnusedFs: Change not \
successful. Please verify configuration manually. \
/etc/modprobe.d/usgcb-blacklist.conf should contain the following entries \
followed by /bin/true: ''' + fsstring
                    return False
            except (KeyboardInterrupt, SystemExit):
                # User initiated exit
                raise

            except Exception:
                self.detailedresults = traceback.format_exc()
                self.rulesuccess = False
                self.logger.log(LogPriority.ERROR,
                                ['DisableUnusedFs.fix',
                                 self.detailedresults])
                return False
        self.formatDetailedResults("fix", self.rulesuccess,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)

        return self.report()

    def undo(self):
        '''


        :returns: @author: D. Kennel

        '''
        self.targetstate = 'notconfigured'
        try:
            event3 = self.statechglogger.getchgevent('0256003')
            if event3['startstate'] == 'notpresent' and \
               event3['endstate'] == 'present':
                try:
                    os.remove(self.blacklistfile)
                except(OSError):
                    pass
        except(IndexError, KeyError):
            self.logger.log(LogPriority.DEBUG,
                            ['DisableUnusedFs.undo',
                             "EventID 0256003 not found"])
        try:
            event1 = self.statechglogger.getchgevent('0256001')
            if event1['startstate'] != event1['endstate']:
                self.statechglogger.revertfilechanges(self.blacklistfile,
                                                      '0256001')
        except(IndexError, KeyError):
            self.logger.log(LogPriority.DEBUG,
                            ['DisableUnusedFs.undo',
                             "EventID 0256001 not found"])
        try:
            event2 = self.statechglogger.getchgevent('0256002')
            if event2['startstate'] != event2['endstate']:
                uid = event2['startstate'][0]
                gid = event2['startstate'][1]
                mode = event2['startstate'][2]
                if os.path.exists(self.blacklistfile):
                    os.chown(self.blacklistfile, uid, gid)
                    os.chmod(self.blacklistfile, mode)
                    resetsecon(self.blacklistfile)
        except(IndexError, KeyError):
            self.logger.log(LogPriority.DEBUG,
                            ['DisableUnusedFs.undo',
                             "EventID 0256002 not found"])
        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception:
            self.detailedresults = traceback.format_exc()
            self.rulesuccess = False
            self.logger.log(LogPriority.ERROR,
                            ['DisableUnusedFs.undo',
                             self.detailedresults])
        self.report()
        if self.currstate == self.targetstate:
            self.detailedresults = "DisableUnusedFs: Changes successfully " + \
                "reverted"

    def isapplicable(self):
        '''Return a bool indicating whether or not to run on the current os. This
        rule only works on Linux systems at present.


        :returns: Bool
        @author: D. Kennel

        '''
        if self.environ.getosfamily() == 'linux':
            return True
        else:
            return False
