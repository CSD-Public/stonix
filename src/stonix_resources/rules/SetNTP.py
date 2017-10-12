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
Created on Jan 14, 2013

The SetNTP class configures ntp for each client.

@author: Breen Malmberg
@change: 2014/04/18 ekkehard ci updates and ci fix method implementation
@change: 2014/08/27 - ekkehard - added self.ss = "/usr/sbin/systemsetup" to make sure we use the full path
@change: 08/27/2014 Breen Malmberg added colons after each docblock parameter
@change: 2015/04/17 dkennel updated for new isApplicable
@change: 2015/10/08 eball Help text cleanup
@change: 2017/07/17 ekkehard - make eligible for macOS High Sierra 10.13
'''

from __future__ import absolute_import
import os
import re
import traceback

from ..rule import Rule
from ..logdispatcher import LogPriority
from ..pkghelper import Pkghelper
from ..stonixutilityfunctions import iterate
from ..localize import NTPSERVERSINTERNAL
from ..localize import NTPSERVERSEXTERNAL
from ..CommandHelper import CommandHelper


class SetNTP(Rule):
    '''
    The SetNTP class sets the ntpd and ntp config for each client.
    '''

    def __init__(self, config, environ, logger, statechglogger):
        '''
        Constructor
        '''
        Rule.__init__(self, config, environ, logger, statechglogger)
        self.rulenumber = 96
        self.rulename = 'SetNTP'
        self.formatDetailedResults("initialize")
        self.logger = logger
        self.sethelptext()
        self.compliant = False
        self.mandatory = True
        self.rootrequired = True
        self.guidance = ['CIS', 'NSA(3.10.2)', 'CCE-4134-3', 'CCE-4385-1',
                         'CCE-4032-9', 'CCE-4424-8', 'CCE-3487-6']

        # init CI
        self.ci = self.initCi("bool",
                              "SetNTP",
                              "To prevent STONIX from setting a time " +
                              "server, set the value of SetNTP to False",
                              True)

        self.applicable = {'type': 'white',
                           'family': ['linux', 'solaris', 'freebsd'],
                           'os': {'Mac OS X': ['10.9', 'r', '10.13.10']}}

        self.ismobile = self.environ.ismobile()
        self.oncorporatenetwork = self.environ.oncorporatenetwork()

        self.ch = CommandHelper(self.logger)
        self.ss = "/usr/sbin/systemsetup"

        # set conf file path
        self.ntpfile = '/etc/ntp.conf'

        # init conf item dictionary
        self.confitemdict = {'restrict default ignore': False}

        # dynamically build conf item dictionary
        if self.ismobile:
            for server in NTPSERVERSINTERNAL:
                self.confitemdict['server ' + server] = False
                self.confitemdict['restrict ' + server + \
                                  ' mask 255.255.255.255 nomodify notrap noquery'] = False
            for server in NTPSERVERSEXTERNAL:
                self.confitemdict['server ' + server] = False

        else:
            if self.oncorporatenetwork:
                for server in NTPSERVERSINTERNAL:
                    self.confitemdict['server ' + server] = False
                    self.confitemdict['restrict ' + server + \
                                      ' mask 255.255.255.255 nomodify notrap noquery'] = False
            else:
                for server in NTPSERVERSEXTERNAL:
                    self.confitemdict['server ' + server] = False

        # get the correct set of host names, based on whether the
        # machine is currently on the internal network or external
        self.ntpservers = []
        if self.ismobile:
            self.ntpservers = NTPSERVERSINTERNAL
            for item in NTPSERVERSEXTERNAL:
                self.ntpservers.append(item)
        else:
            if self.oncorporatenetwork:
                self.ntpservers = NTPSERVERSINTERNAL
            else:
                self.ntpservers = NTPSERVERSEXTERNAL

        self.ntppkg = 'ntp'
        self.chronypkg = 'chrony'

###############################################################################

    def report(self):
        '''
        determine whether the fix() method of this rule has run successfully
        yet or not

        @return: bool
        @author: Breen Malmberg
        '''

        # defaults
        self.detailedresults = ""

        try:

            if self.environ.getosfamily() == "darwin":
                self.compliant = self.report_darwin()
            else:
                self.compliant = self.report_non_darwin()

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as err:
            self.rulesuccess = False
            self.detailedresults = self.detailedresults + "\n" + str(err) + \
            " - " + str(traceback.format_exc())
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
            return self.rulesuccess
        self.formatDetailedResults("report", self.compliant,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

###############################################################################

    def report_darwin(self):
        '''
        determine rule compliance status for darwin based systems

        @return: bool
        @author: ekkehard j. koch
        @change: 08/26/2014 Breen Malmberg added detailedresults message updates to
                indicate which config items are missing/incorrect
        '''

        # defaults
        configured = False
        usingnetworktime = False
        timeserverfound = False
        disablemonitorfound = False

        try:

            cmd = [self.ss, "-getnetworktimeserver"]
            self.ch.executeCommand(cmd)
            self.output = self.ch.getOutput()

            for line in self.output:
                for item in self.ntpservers:
                    if re.search(item, line):
                        timeserverfound = True

            cmd2 = [self.ss, "-getusingnetworktime"]
            self.ch.executeCommand(cmd2)
            self.output2 = self.ch.getOutput()

            for line in self.output2:
                if re.search('On', line):
                    usingnetworktime = True

            if os.path.exists(self.ntpfile):
                f = open(self.ntpfile, 'r')
                contentlines = f.readlines()
                f.close()

                for line in contentlines:
                    if re.search('^disable\s*monitor', line):
                        disablemonitorfound = True

            if not usingnetworktime:
                self.detailedresults += '\nusingnetworktime not set to on'
            if not timeserverfound:
                self.detailedresults += '\ncorrect time server not configured'
            if not disablemonitorfound:
                self.detailedresults += '\ndisable monitor config line not found'

            if usingnetworktime and timeserverfound and disablemonitorfound:
                configured = True

        except Exception:
            raise
        return configured

###############################################################################
    def report_non_darwin(self):
        '''
        determine rule compliance status for linux based systems

        @return: bool
        @author: Breen Malmberg
        '''

        # defaults
        retval = False
        self.ph = Pkghelper(self.logger, self.environ)
        self.useschrony = self.parseVersion()

        try:

            # determine whether ntp is already installed
            if self.useschrony:
                retval = self.report_chrony()
            else:
                retval = self.report_ntp()

        except Exception:
            raise
        return retval

###############################################################################
    def report_chrony(self):
        '''
        '''

        # defaults
        conffile = '/etc/chrony/chrony.conf'
        conffiles = ['/etc/chrony.conf', '/etc/chrony/chrony.conf']
        for f in conffiles:
            if os.path.exists(f):
                conffile = f
        confitemsdict = {'^cmddeny\s*all': False}
        confitems = True
        retval = False

        try:

            if not self.ph.check(self.chronypkg):
                retval = False
                self.detailedresults += "\nchrony is not installed"

            if os.path.exists('/etc/chrony.conf')|os.path.exists('/etc/chrony/chrony.conf'):

                timeserversdict = {}
                for server in self.ntpservers:
                    timeserversdict[server] = False
                timeservers = True

                f = open(conffile, 'r')
                contentlines = f.readlines()
                f.close()

                # check for configuration options
                for item in confitemsdict:
                    for line in contentlines:
                        if re.search(item, line):
                            confitemsdict[item] = True
                for item in confitemsdict:
                    if not confitemsdict[item]:
                        confitems = False

                # check for time servers
                for line in contentlines:
                    for server in timeserversdict:
                        if re.search('^server\s*' + server, line):
                            timeserversdict[server] = True
                for server in timeserversdict:
                    if not timeserversdict[server]:
                        timeservers = False

                if not confitems:
                    self.detailedresults += '\none or more configuration options is missing from the configuration file'
                if not timeservers:
                    self.detailedresults += '\none or more required time servers is missing from the configuration file'

                if confitems and timeservers:
                    retval = True

            else:
                self.detailedresults += '\nNo chrony.conf file found'
                retval = False

        except Exception:
            raise
        return retval

###############################################################################
    def report_ntp(self):
        '''
        '''

        # defaults
        retval = False
        timeservers = True
        confitems = True
        confitemdict = {'restrict\s*default\s*ignore': False,
                        'disable\s*monitor': False}

        try:

            if not self.ph.check(self.ntppkg):
                retval = False
                self.detailedresults += "\nntp is not installed"

            if os.path.exists('/etc/ntp.conf'):

                conffile = '/etc/ntp.conf'

                f = open(conffile, 'r')
                contentlines = f.readlines()
                f.close()

                for line in contentlines:
                    for item in confitemdict:
                        if re.search('^' + item, line):
                            confitemdict[item] = True

                # check for configuration options
                for item in confitemdict:
                    if not confitemdict[item]:
                        confitems = False
                if not confitems:
                    self.detailedresults += '\none or more configuration options missing from conf file'

                if not self.find_servers(conffile):
                    timeservers = False
                    self.detailedresults += '\ntime servers not set correctly in conf file'

                if confitems and timeservers:
                    retval = True
            else:
                self.detailedresults += '\nNo ntp.conf file found'
                retval = False

        except Exception:
            raise
        return retval

###############################################################################
    def find_servers(self, conffile):

        retval = True

        try:

            f = open(conffile, 'r')
            contentlines = f.readlines()
            f.close()

            # check if any non-approved time servers are in file
            serverstocheck = []
            for line in contentlines:
                if re.search('^server', line):
                    line = line.split()
                    if len(line) > 1:
                        serverstocheck.append(line[1])
            for server in serverstocheck:
                if server not in NTPSERVERSINTERNAL and server not in NTPSERVERSEXTERNAL:
                    self.detailedresults += '\n' + str(server) + ' was found and should not be there'
                    retval = False

        except Exception:
            raise
        return retval

###############################################################################
    def fix(self):
        '''
        Decide which fix sub method to run, and run it to configure ntp

        @author: Breen Malmberg
        '''

        # defaults
        self.detailedresults = ""
        self.iditerator = 0
        self.rulesuccess = True

        try:

            if self.ci.getcurrvalue():

                if self.environ.getosfamily() == "darwin":
                    if not self.fix_darwin():
                        self.rulesuccess = False
                else:
                    if not self.fix_non_darwin():
                        self.rulesuccess = False

            else:
                self.detailedresults = str(self.ci.getkey()) + \
                " was disabled. No action was taken."

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as err:
            self.rulesuccess = False
            self.detailedresults = self.detailedresults + "\n" + str(err) + \
            " - " + str(traceback.format_exc())
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.rulesuccess

###############################################################################

    def fix_darwin(self):
        '''
        private method to perform fix operations for mac os x machines

        @author: Breen Malmberg
        '''

        # defaults
        tmpntpfile = self.ntpfile + '.stonixtmp'
        parseoutput1 = []
        parseoutput2 = []
        fixresult = True
        disablemonitorfound = False

        try:

            # set network time on
            cmd1 = [self.ss, "-setusingnetworktime", "on"]
            try:
                self.ch.executeCommand(cmd1)
            except OSError:
                self.logger.log(LogPriority.DEBUG, '\nSetNTP.fix_darwin() - command ' + str(self.ss) + ' not found\n' + str(OSError.message))

            try:

                # set undo cmd to restore original network time state
                for line in self.output2:
                    if re.search('Network Time', line):
                        parseoutput1 = line.split(':')
                originaltimestate = parseoutput1[1].strip()

            except KeyError:
                originaltimestate = "off"

            undocmd1 = self.ss + " -setusingnetworktime " + originaltimestate
            event = {"eventtype": "commandstring",
                     "command": undocmd1}
            self.iditerator += 1
            myid = iterate(self.iditerator, self.rulenumber)
            self.statechglogger.recordchgevent(myid, event)

            # set network time server
            cmd2 = [self.ss, "-setnetworktimeserver",
                    str(self.ntpservers[0])]
            try:
                self.ch.executeCommand(cmd2)
            except OSError:
                self.logger.log(LogPriority.DEBUG, '\nSetNTP.fix_darwin() - command ' + str(self.ss) + ' not found\n' + str(OSError.message))

            try:

                # set undo cmd to reinstate original ntp server
                for line in self.output:
                    if re.search('Network Time Server', line):
                        parseoutput2 = line.split(':')
                originalnetworktimeserver = parseoutput2[1].strip()

            except (IndexError, KeyError):
                originalnetworktimeserver = NTPSERVERSINTERNAL[0]

            undocmd2 = self.ss + " -setusingnetworktime " + \
            originalnetworktimeserver
            event = {"eventtype": "commandstring",
                     "command": undocmd2}
            self.iditerator += 1
            myid = iterate(self.iditerator, self.rulenumber)
            self.statechglogger.recordchgevent(myid, event)

            # build the list of values to write to the file
            contentlines = []
            for host in self.ntpservers:
                contentlines.append('server ' + host + '\n')

            for line in contentlines:
                if re.search('^disable\s*monitor', line):
                    disablemonitorfound = True

            if not disablemonitorfound:
                contentlines.append('\ndisable monitor')

            # if the ntp file exists, write the new values
            if os.path.exists(self.ntpfile):

                tf = open(tmpntpfile, 'w')
                tf.writelines(contentlines)
                tf.close()

                if not os.path.exists(tmpntpfile):
                    self.logger.log(LogPriority.DEBUG, "temporary ntp file was not found or created; unable to apply changes to " + str(self.ntpfile))
                    self.logger.log(LogPriority.DEBUG, "fix_darwin was not run to completion")
                    fixresult = False
                    return fixresult

                event = {'eventtype': 'conf',
                         'filepath': self.ntpfile}
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                self.statechglogger.recordchgevent(myid, event)
                self.statechglogger.recordfilechange(tmpntpfile, self.ntpfile,
                                                     myid)

                os.rename(tmpntpfile, self.ntpfile)
                os.chmod(self.ntpfile, 0644)
                os.chown(self.ntpfile, 0, 0)

            # if the ntp file does not exist, create it and write the new
            # values
            else:
                f = open(self.ntpfile, 'w')
                f.writelines(contentlines)
                f.close()

                if not os.path.exists(self.ntpfile):
                    self.logger.log(LogPriority.DEBUG, "unable to create ntp file; fix_darwin was not run to completion")
                    fixresult = False
                    return fixresult

                event = {'eventtype': 'creation',
                         'filepath': self.ntpfile}
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                self.statechglogger.recordchgevent(myid, event)

                os.chmod(self.ntpfile, 0644)
                os.chown(self.ntpfile, 0, 0)

            cmd3 = ["ntpd"]
            try:
                self.ch.executeCommand(cmd3)
            except OSError:
                self.logger.log(LogPriority.DEBUG, '\nSetNTP.fix_darwin() - ntpd not installed or not found\n' + str(OSError.message))

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            fixresult = False
            raise
        return fixresult

###############################################################################
    def fix_non_darwin(self):
        '''
        check to see if ntp is installed and if it is not, then install it.
        check to see if ntp is properly configured and if it is not, then
        configure it.

        @return: bool
        @author: Breen Malmberg
        @change: 08/27/2014 Breen Malmberg added blank line to bottom in accordance
                with pep8
        '''

        try:

            # defaults
            fixresult = True
            conffiles = ['/etc/chrony.conf', '/etc/chrony/chrony.conf', '/etc/ntp.conf']

            if self.useschrony:

                confoptions = {'cmddeny all': False}
                conffiles = ['/etc/chrony.conf', '/etc/chrony/chrony.conf']
                package = self.chronypkg
            else:

                confoptions = {'restrict default ignore': False,
                               'disable monitor': False}
                conffile = '/etc/ntp.conf'
                package = self.ntppkg

            # check for installation of package
            if not self.ph.check(package):
                self.ph.install(package)

            for f in conffiles:
                if os.path.exists(f):
                    conffile = f

            # check for existence and correct configuration of conf file
            if os.path.exists(conffile):

                tmpfile = conffile + '.stonixtmp'

                f = open(conffile, 'r')
                contentlines = f.readlines()
                f.close()

                # add all server config lines
                for line in contentlines:
                    for option in confoptions:
                        if re.search(option, line):
                            confoptions[option] = True
                for option in confoptions:
                    if not confoptions[option]:
                        contentlines.append('\n' + option)

                # remove non-approved ntp server entries
                for line in contentlines:
                    if re.search('^server', line):
                        sline = line.split()
                        if sline[1] not in NTPSERVERSINTERNAL and sline[1] not in NTPSERVERSEXTERNAL:
                            contentlines = [c.replace(line, '\n') for c in contentlines]

                # add missing server entries to the conf file
                checklist = []
                for line in contentlines:
                    if re.search('^server', line):
                        checklist.append(line.rstrip('\n'))
                for server in self.ntpservers:
                    if not 'server ' + server in checklist:
                        contentlines.append('\nserver ' + server)

                # create temporary file; write new contents
                tf = open(tmpfile, 'w')
                tf.writelines(contentlines)
                tf.close()

                if not os.path.exists(tmpfile):
                    self.logger.log(LogPriority.DEBUG, "temporary ntp file was not found or created; unable to apply changes to " + str(self.ntpfile))
                    self.logger.log(LogPriority.DEBUG, "fix_non_darwin was not run to completion")
                    fixresult = False
                    return fixresult

                event = {'eventtype': 'conf',
                         'filepath': conffile}
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                self.statechglogger.recordchgevent(myid, event)
                self.statechglogger.recordfilechange(tmpfile, conffile, myid)

                os.rename(tmpfile, conffile)
                os.chmod(conffile, 0644)
                os.chown(conffile, 0, 0)

            else:

                fixresult = False
                self.detailedresults += '\nNetwork time package installation failed'

        except Exception:
            raise
        return fixresult

###############################################################################
    def parseVersion(self):
        '''
        This method checks the version of the OS to determine whether or not it
        is using chrony or openNTPD by default.
        
        @return: Bool True if the system uses chrony
        @author: Breen Malmberg
        @change: Modified to correct for bugs in Environment object by D. Kennel
        @change: Breen Malmberg - 2/1/2017 - fixed bug with variable osname being
                referenced before assignment if the osname was not found in the osversion
                dictionary
        '''

        # defaults
        useschrony = False
        osname = ''

        try:

            # the minimum version number of each distro which uses chrony instead of ntp
            # suse still uses ntp
            osversion = {'red': 7,
                         'fedora': 20,
                         'centos': 7,
                         'debian': 8,
                         'ubuntu': 16}

            # get the os distro name to use in comparison with the dictionary version values above
            filedict = ['/etc/redhat-release', '/etc/SuSE-release', '/etc/os-release']
            relfile = ''
            for path in filedict:
                if os.path.exists(path):
                    relfile = path
            if not os.path.exists(relfile):
                self.detailedresults += '\nparseVersion(): could not locate an os version release file to parse'
                return False

            f = open(relfile, 'r')
            contentline = f.readline()
            f.close()

            for key in osversion:
                if re.search(key, contentline, re.IGNORECASE):
                    osname = key

            # compare the os version to the minimum chrony version number of each os in osversion dict above
            osver = self.environ.getosver()
            element = osver.split('.')
            majorver = element[0]

            # if this is an os that uses chrony (in any version)
            if osname:
                if int(majorver) >= osversion[osname]:
                    useschrony = True

        except Exception:
            raise
        return useschrony
