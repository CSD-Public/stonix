###############################################################################
#                                                                             #
# Copyright 2015-2018.  Los Alamos National Security, LLC. This material was  #
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
Created on Dec 12, 2013

Schedule Stonix to run randomly throughout the week and once in a user context
per day

@author: Breen Malmberg
@change: 2014/02/16 ekkehard Implemented self.detailedresults flow
@change: 2014/02/16 ekkehard Implemented isapplicable
@change: 2014/04/30 dkennel Corrected bug where crons were created without -c
@change: 2014/04/30 dkennel Added newline to crontab entries to prevent damage
@change: 2014/04/30 dkennel Corrected overly greedy regexes
@change: 2014/09/02 ekkehard self.rootrequired = True & OS X 10.10 compliant
@change: 2015/04/17 dkennel updated for new isApplicable
@change: 2015/10/08 eball Help text cleanup

@change 2017/01/31 Breen Malmberg removed superfluous logging entries (now contained
        within ServiceHelper and SHlaunchd)
@change: 2017/10/23 rsn - change to new service helper interface
@change: 2017/11/27 Breen Malmberg removed print statements
'''

from __future__ import absolute_import

from ..rule import Rule
from ..logdispatcher import LogPriority
from ..stonixutilityfunctions import readFile
from ..ServiceHelper import ServiceHelper
from ..pkghelper import Pkghelper
from ..CommandHelper import CommandHelper

import random
import os
import re
import pwd
import traceback


class ScheduleStonix(Rule):
    '''
    Schedule Stonix to run randomly throughout the week and once in a user
    context

    @author: Breen Malmberg

    @change: 09/25/2017 - Breen Malmberg - Eliminated redundant code; separated out
            some code into its own methods; Improved method comment blocks; Improved
            in-line code comments; Added logic to ensure that no two STONIX jobs can
            end up being scheduled to run at the same time
    @change: 04/17/2018 - Breen Malmberg - Fixed the key being specified in the mac os
            dict for the jobs from "Day" to "Weekday"
    @change: 05/02/2018 - Breen Malmberg - Fixed a missed logic path for setting a flag
            to False indicating that the config file(s) needed to be created on mac os
            (they were never getting created the paths didn't exist to begin with; this
            appears to have been a recent regression); added debug logging to the fixmac()
            method; removed an unused import "FindUserLoggedIn"
    '''

    def __init__(self, config, environ, logger, statechglogger):
        '''
        Constructor
        '''

        Rule.__init__(self, config, environ, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 268
        self.rulename = 'ScheduleStonix'
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.rootrequired = True
        self.sethelptext()
        self.rulesuccess = True
        self.guidance = ['']
        self.applicable = {'type': 'white',
                           'family': ['linux', 'solaris', 'freebsd'],
                           'os': {'Mac OS X': ['10.9', '+']}}

        self.svchelper = ServiceHelper(self.environ, self.logger)

        self.initVars()
        self.genJobTimes()

        # define the Mac OS X weekly STONIX report launchd job
        self.stonixplistreport = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>gov.lanl.stonix.report</string>
    <key>ProgramArguments</key>
    <array>
        <string>/Applications/stonix4mac.app/Contents/Resources/stonix.app/Contents/MacOS/stonix</string>
        <string>-c</string>
        <string>-r</string>
    </array>
    <key>StartCalendarInterval</key>
    <array>
        <dict>
            <key>Weekday</key>
            <integer>''' + str(self.adminreportday) + '''</integer>
            <key>Hour</key>
            <integer>''' + str(self.adminreporthour) + '''</integer>
            <key>Minute</key>
            <integer>''' + str(self.adminreportminute) + '''</integer>
        </dict>
    </array>
</dict>
</plist>'''

        # define the Mac OS X weekly STONIX fix launchd job
        self.stonixplistfix = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>gov.lanl.stonix.fix</string>
    <key>ProgramArguments</key>
    <array>
        <string>/Applications/stonix4mac.app/Contents/Resources/stonix.app/Contents/MacOS/stonix</string>
        <string>-c</string>
        <string>-f</string>
    </array>
    <key>StartCalendarInterval</key>
    <array>
        <dict>
            <key>Weekday</key>
            <integer>''' + str(self.adminfixday) + '''</integer>
            <key>Hour</key>
            <integer>''' + str(self.adminfixhour) + '''</integer>
            <key>Minute</key>
            <integer>''' + str(self.adminfixminute) + '''</integer>
        </dict>
    </array>
</dict>
</plist>'''

        # define the once-daily STONIX user-context launch agent job
        self.stonixplistuser = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>gov.lanl.stonix.user</string>
    <key>ProgramArguments</key>
    <array>
        <string>/Applications/stonix4mac.app/Contents/Resources/stonix.app/Contents/MacOS/stonix</string>
        <string>-c</string>
        <string>-f</string>
    </array>
    <key>StartCalendarInterval</key>
    <array>
        <dict>
            <key>Hour</key>
            <integer>''' + str(self.userfixhour) + '''</integer>
            <key>Minute</key>
            <integer>''' + str(self.userfixminute) + '''</integer>
        </dict>
    </array>
</dict>
</plist>'''

        # note that if either this string or the user-stonix.py script are altered
        # #they both need to be altered so they match each other identically
        self.userstonixscript = '''#! /usr/bin/env python

#Created on Jan 13, 2014
#
#This script is used by ScheduleStonix.py
#This script will run stonix.py, in user context mode, once daily
#
#@author: Breen Malmberg


import os,time,getpass,pwd,re

#defaults
username = getpass.getuser()
userhome = ''
scriptsuccess = True

#get current user's home directory
for p in pwd.getpwall():
    if p[0] in username:
        if re.search('^/home/',p[5]) or re.search('^/Users/',p[5]):
            userhome = p[5]

todaysdate = time.strftime("%d%m%Y")
stonixscriptpath = '/usr/sbin/stonix.py'
stonixtempfolder = userhome + '/.stonix/'
alreadyran = False

#if the script has not already run today

if os.path.exists(stonixtempfolder + 'userstonix.log'):

    f = open(stonixtempfolder + 'userstonix.log','r')
    contentlines = f.readlines()
    f.close()

    for line in contentlines:
        line = line.split()
        #script log file entries should follow the format: usernameDDMMYYYY
        if re.search('^' + username,line[0]) and re.search(todaysdate,line[1]):
            alreadyran = True

    #if the script has not yet run today, then run it        
    if not alreadyran:

        try:

            #run stonix -f in user context
            os.system(stonixscriptpath + ' -cf')

        except IOError:
            exitcode = IOError.errno
            print IOError.message
            scriptsuccess = False
        except OSError:
            exitcode = OSError.errno
            print OSError.message
            scriptsuccess = False

        if scriptsuccess:

            i = 0

            for line in contentlines:
                if re.search('^' + username,line) and not re.search(todaysdate,line):
                    line = username + ' ' + todaysdate
                    contentlines[i] = line
                    i += 1

            #create/update log entry
            f = open(stonixtempfolder + 'userstonix.log','w')
            f.writelines(contentlines)
            f.close()

        else:

            print "user-stonix.py script failed to run properly"
            exit(exitcode)'''

    def initVars(self):
        '''
        initialize all of the time variables
        to be used by the class

        @author: Breen Malmberg
        '''

        # possible locations where the root cron tab may be located
        # (system-dependent)
        self.cronfilelocations = ['/etc/crontab',
                                  '/var/spool/cron/root',
                                  '/usr/lib/cron/tabs/root',
                                  '/var/cron/tabs/root',
                                  '/var/spool/cron/crontabs/root']

        # init cronfilelocation to blank
        self.cronfilelocation = ''

        # find correct location out of possible locations
        for location in self.cronfilelocations:
            if os.path.exists(location):
                self.cronfilelocation = location

        # get the STONIX executable path
        self.stonixpath = self.environ.get_script_path()

        self.userlist = []

        for p in pwd.getpwall():
            if re.search('^/home/', p[5]) or re.search('^/Users/', p[5]):
                self.userlist.append(p[0].strip())

        self.adminfixday = 0
        self.adminfixhour = 0
        self.adminfixminute = 0

        self.adminreportday = 0
        self.adminreporthour = 0
        self.adminreportminute = 0

        self.userfixhour = 0
        self.userfixminute = 0

    def checkJobTimes(self):
        '''
        check to make sure none of the generated
        job times overlap
        return true if they overlap
        return false if they do NOT overlap

        @return: try_again
        @rtype: bool

        @author: Breen Malmberg
        '''

        try_again = False

        if self.adminfixday == self.adminreportday:
            try_again = True
        if self.userfixhour == self.adminfixhour:
            try_again = True
        if self.userfixhour == self.adminreporthour:
            try_again = True
        return try_again

    def genJobTimes(self):
        '''
        Generate random times to run the launchd
        STONIX jobs on Mac OS X

        @author: Breen Malmberg
        '''

        self.adminfixday = random.randrange(1, 7)
        self.adminfixhour = random.randrange(17, 23)
        self.adminfixminute = random.randrange(1, 59)

        self.adminreportday = random.randrange(1, 7)
        self.adminreporthour = random.randrange(17, 23)
        self.adminreportmin = random.randrange(1, 59)

        self.userfixhour = random.randrange(17, 23)
        self.userfixminute = random.randrange(1, 59)

        if self.checkJobTimes():
            self.genJobTimes()

    def getFileContents(self, filepath):
        '''
        Read file contents from given filepath, into a list
        Return the list (of strings)
        Return empty list if given filepath does not exist

        @param filepath: string; full path to file, from which to read

        @return: contents
        @rtype: list

        @author: Breen Malmberg
        '''

        contents = []

        if os.path.exists(filepath):
            f = open(filepath, 'r')
            contents = f.readlines()
            f.close()

        return contents

    def reportLinux(self):
        '''
        Check for STONIX Cron job entries in the Linux crontab

        @return: retval
        @rtype: bool

        @author: Breen Malmberg
        '''

        retval = True

        self.cronfileexists = True
        self.reportjob = False
        self.fixjob = False
        self.userjob = True
        self.userscriptexists = True
        stonixreportjob = 'root nice -n 19 ' + str(self.stonixpath) + '/stonix.py -cr'
        stonixfixjob = 'root nice -n 19 ' + str(self.stonixpath) + '/stonix.py -cdf'
        stonixuserjobpath = '/etc/profile.d/user-stonix.py'

        # check for existence of Cron file
        if not os.path.exists(self.cronfilelocation):
            self.cronfileexists = False
            self.detailedresults += '\nCron file not found'

        # check for STONIX job entries
        contents = self.getFileContents(self.cronfilelocation)
        if not contents:
            self.detailedresults += '\nSTONIX report job not found'
            self.detailedresults += '\nSTONIX fix job not found'
        else:
            # report entry
            for line in contents:
                if re.search(stonixreportjob, line, re.IGNORECASE):
                    self.reportjob = True
            if not self.reportjob:
                self.detailedresults += '\nSTONIX report job not found'
            else:
                self.detailedresults += '\nSTONIX report job found'

            # fix entry
            for line in contents:
                if re.search(stonixfixjob, line, re.IGNORECASE):
                    self.fixjob = True
            if not self.fixjob:
                self.detailedresults += '\nSTONIX fix job not found'
            else:
                self.detailedresults += '\nSTONIX fix job found'

        # user script
        if not os.path.exists(stonixuserjobpath):
            self.userscriptexists = False
            self.detailedresults += '\nSTONIX user script not found'
        else:
            self.detailedresults += '\nSTONIX user script found'
            contents = self.getFileContents(stonixuserjobpath)
            userstonixscriptlist = self.userstonixscript.splitlines(True)
    
            if cmp(contents, userstonixscriptlist) != 0:
                self.userjob = False
                self.detailedresults += '\nSTONIX user script has incorrect contents'
            else:
                self.detailedresults += '\nSTONIX user script has correct contents'

        if not self.cronfileexists:
            retval = False
        if not self.reportjob:
            retval = False
        if not self.fixjob:
            retval = False
        if not self.userjob:
            retval = False
        if not self.userscriptexists:
            retval = False

        return retval

    def report(self):
        '''
        Linux:
        Check that Cron file(s) exist and that they contain the correct job entries
        Check that the STONIX user script exists and contains the correct contents

        Mac:
        Check that the launchd files exist
        Check that each launchd file contains the correct contents

        @return: self.compliant
        @rtype: bool

        @author: Breen Malmberg
        '''

        self.compliant = True
        self.detailedresults = ""
        self.ch = CommandHelper(self.logger)

        try:

            # if Mac OS, check Mac launchd jobs
            if self.environ.getostype() == "Mac OS X":
                if not self.reportMac():
                    self.compliant = False
            else:
                self.pkghelper = Pkghelper(self.logger, self.environ)
                if not self.reportLinux():
                    self.compliant = False

        except(KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.detailedresults += "\n" + traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

    def reportMac(self):
        '''
        Check for the existence of the necessary STONIX launchd jobs
        Check that each STONIX launchd job contains the correct contents

        @return retval
        @rtype: bool

        @author Breen Malmberg
        '''

        # defaults
        retval = True
        pathsneeded = ['/Library/LaunchDaemons/gov.lanl.stonix.report.plist',
                       '/Library/LaunchDaemons/gov.lanl.stonix.fix.plist',
                       '/Library/LaunchAgents/gov.lanl.stonix.user.plist']

        plistdict = {'/Library/LaunchDaemons/gov.lanl.stonix.report.plist':
                     self.stonixplistreport,
                     '/Library/LaunchDaemons/gov.lanl.stonix.fix.plist':
                     self.stonixplistfix,
                     '/Library/LaunchAgents/gov.lanl.stonix.user.plist':
                     self.stonixplistuser}
        systemservicetargets = ["gov.lanl.stonix.fix", "gov.lanl.stonix.report"]
        #userservicetargets = ["gov.lanl.stonix.user"]
        self.macadminfixjob = True
        self.macadminreportjob = True
        self.macuserjob = True

        try:

            # if a required path is missing, return False
            for path in pathsneeded:
                if not os.path.exists(path):
                    retval = False
                    self.detailedresults += "Path doesn't exist: " + path + "\n"
                    if path == '/Library/LaunchDaemons/gov.lanl.stonix.report.plist':
                        self.macadminreportjob = False
                    elif path == '/Library/LaunchDaemons/gov.lanl.stonix.fix.plist':
                        self.macadminfixjob = False
                    elif path == '/Library/LaunchAgents/gov.lanl.stonix.user.plist':
                        self.macuserjob = False

                # if path exists, check for required plist content
                else:
                    contents = readFile(path, self.logger)

                    # get contents of appropriate plist script in a list
                    scrptcontents = plistdict[path].splitlines(True)

                    # compare contents of plist script
                    i = 0
                    for i in range(len(contents)):
                        if not re.search('<integer>', contents[i]):
                            if contents[i].strip() != scrptcontents[i].strip():
                                retval = False
                                self.detailedresults += "line not correct: " + str(contents[i]) + " in file: " + str(path) + "\n"
                                if re.search('report', path, re.IGNORECASE):
                                    self.macadminreportjob = False
                                if re.search('fix', path, re.IGNORECASE):
                                    self.macadminfixjob = False
                                if re.search('user', path, re.IGNORECASE):
                                    self.macuserjob = False

                        else:
                            if not re.search('<integer>[0-9][0-9]{0,1}<\/integer>', contents[i]):
                                retval = False
                                self.detailedresults += "integer line wrong: " + str(contents[i]) + " in file: " + str(path) + "\n"
                                if re.search('report', path, re.IGNORECASE):
                                    self.macadminreportjob = False
                                if re.search('fix', path, re.IGNORECASE):
                                    self.macadminfixjob = False
                                if re.search('user', path, re.IGNORECASE):
                                    self.macuserjob = False

            # This part needs to be changed to work with re-designed servicehelperTwo
            self.ch.executeCommand("/bin/launchctl print-disabled system/")
            disabledserviceslist = self.ch.getOutput()
            retcode = self.ch.getReturnCode()
            if retcode != 0:
                errmsg = self.ch.getErrorString()
                self.logger.log(LogPriority.DEBUG, errmsg)
            for line in disabledserviceslist:
                for item in systemservicetargets:
                    if re.search(item + '\"\s+\=\>\s+true', line, re.IGNORECASE):
                        retval = False
                        self.detailedresults += "\nA required STONIX service: gov.lanl.stonix.user.plist is currently disabled"
#             for item in plistdict:
#                 itemlong = item
#                 if not re.search('user', itemlong, re.IGNORECASE):
#                     itemshort = item.split('/')[3][:-6]
#                 if not self.svchelper.auditService(itemlong, serviceTarget=itemshort):
#                     retval = False
#                     self.detailedresults += "\nRequired Stonix job: " + str(item) + " is not scheduled to run"

        except Exception:
            raise
        return retval

    def genRandCronTime(self):
        '''
        Generate a random time within 1 week period, format it for cron
        and return it as a string

        @return: crontimedict
        @rtype: dict

        @author: Breen Malmberg
        '''

        crontimedict = {}

        reportday = random.randrange(1, 7)
        reporthour = random.randrange(17, 23)
        reportminute = random.randrange(1, 59)

        fixday = random.randrange(1, 7)
        fixhour = random.randrange(17, 23)
        fixminute = random.randrange(1, 59)

        if reportday == fixday:
            self.genRandCronTime()

        crontimedict['report'] = str(reportminute) + ' ' + str(reporthour) + ' * * ' + str(reportday)
        crontimedict['fix'] = str(fixminute) + ' ' + str(fixhour) + ' * * ' + str(fixday)

        return crontimedict

    def fix(self):
        '''
        Mac OS X: Create or edit STONIX launchd jobs as necessary
        Linux: Create or edit STONIX Cron job entries as necessary

        @return: self.rulesuccess
        @rtype: bool

        @author: Breen Malmberg
        '''

        self.detailedresults = ""
        self.rulesuccess = True

        try:

            # If Mac OS, do fixes for Mac
            if self.environ.getostype() == "Mac OS X":
                if not self.fixMac():
                    self.rulesuccess = False
            # else do fixes for Linux
            else:
                if not self.fixLinux():
                    self.rulesuccess = False

        except(KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.detailedresults += traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
            self.rulesuccess = False
        self.formatDetailedResults("fix", self.rulesuccess, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.rulesuccess

    def fixLinux(self):
        '''
        Create or edit STONIX Cron jobs for Linux, as necessary

        @return: retval
        @rtype: bool

        @author: Breen Malmberg
        '''

        retval = True
        legacystonixcron = '/etc/legacy_stonix_cron'
        userscriptdir = '/etc/profile.d/user-stonix.py'

        crontimedict = self.genRandCronTime()

        # if the Cron time dictionary is empty, do not continue
        if len(crontimedict) == 0:
            fixresult = False
            self.rulesuccess = False
            self.detailedresults += "\nFailed to generate random times for Cron jobs!"
            self.formatDetailedResults("fix", fixresult, self.detailedresults)
            self.logdispatch.log(LogPriority.INFO, self.detailedresults)
            return fixresult

        # create the report and fix Cron entry strings
        reportstring = '\n' + str(crontimedict['report']) + ' root nice -n 19 ' + str(self.stonixpath) + '/stonix.py' + ' -cr'
        fixstring = '\n' + str(crontimedict['fix']) + ' root nice -n 19 ' + str(self.stonixpath) + '/stonix.py' + ' -cdf &> /var/log/stonix-lastfix.log\n'

        # create Cron file if it doesn't exist
        if not self.cronfileexists:
            contents = []
            f = open(self.cronfilelocation, 'w')
            contents.append('## This file created by STONIX\n\n')
            contents.append('SHELL=/bin/bash\n')
            contents.append('PATH=/sbin:/bin:/usr/sbin:/usr/bin\n')
            contents.append('MAILTO=root\n')
            contents.append(reportstring)
            contents.append(fixstring)
            f.writelines(contents)
            f.close()
            os.chown(self.cronfilelocation, 0, 0)
            os.chmod(self.cronfilelocation, 0644)
        else:

            contents = self.getFileContents(self.cronfilelocation)
    
            # remove old, incorrect STONIX Cron entry(ies)
            # (this should only run once per machine)
            if not os.path.exists(legacystonixcron):
                for line in contents:
                    if re.search('stonix.py', line, re.IGNORECASE):
                        contents = [c.replace(line, '') for c in contents]
                f = open(legacystonixcron, 'w')
                f.write("don't delete me")
                f.close()
                os.chown(legacystonixcron, 0, 0)
                os.chmod(legacystonixcron, 0640)
    
            # edit Cron file if it has incorrect or missing entries
            if not (self.reportjob and self.fixjob):
                contents.append('\n# Following line(s) added by STONIX\n')
    
                # add report line if it doesn't exist
                if not self.reportjob:
                    contents.append(reportstring)
        
                # add fix line if it doesn't exist
                if not self.fixjob:
                    contents.append(fixstring)
        
                f = open(self.cronfilelocation, 'w')
                f.writelines(contents)
                f.close()
                os.chown(self.cronfilelocation, 0, 0)
                os.chmod(self.cronfilelocation, 0644)

        # create the user script if it doesn't exist
        if not os.path.exists(userscriptdir):
            try:
                if not os.path.exists('/etc/profile.d'):
                    os.makedirs('/etc/profile.d', 0755)
                    os.chown('/etc/profile.d', 0, 0)

                f = open(userscriptdir, 'w')
                f.write(self.userstonixscript)
                f.close()

                os.chown(userscriptdir, 0, 0)
                os.chmod(userscriptdir, 0750)
            except Exception:
                retval = False

        # else edit the contents if it does exist
        else:
            contentlines = self.getFileContents(userscriptdir)

            userstonixscriptlist = self.userstonixscript.splitlines(True)

            try:

                if cmp(contentlines, userstonixscriptlist) != 0:
                    f = open(userscriptdir, 'w')
                    f.writelines(userstonixscriptlist)
                    f.close()

                    os.chown(userscriptdir, 0, 0)
                    os.chmod(userscriptdir, 0750)

            except Exception:
                retval = False

        return retval

    def fixMac(self):
        '''
        Create or edit STONIX launchd jobs for Mac OS X
        Create or edit the STONIX launch agent user job for Mac OS X

        @return: retval
        @rtype: bool

        @author Breen Malmberg
        '''

        retval = True
        self.macadminfixpath = "/Library/LaunchDaemons/gov.lanl.stonix.fix.plist"
        self.macadminreportpath = "/Library/LaunchDaemons/gov.lanl.stonix.report.plist"
        self.macuserpath = "/Library/LaunchAgents/gov.lanl.stonix.user.plist"

        # Flag that tells STONIX that old, incorrect STONIX launchd jobs
        # have been removed, so don't try to remove them again
        # (This is to fix an artifact of previous STONIX ScheduleStonix.py versions)
        legacystonixcron = '/etc/legacy_stonix_cron'

        # defaults
        servicedict = {'/Library/LaunchDaemons/gov.lanl.stonix.report.plist':
                       'gov.lanl.stonix.report',
                       '/Library/LaunchDaemons/gov.lanl.stonix.fix.plist':
                       'gov.lanl.stonix.fix',
                       '/Library/LaunchAgents/gov.lanl.stonix.user.plist':
                       'gov.lanl.stonix.user'}

        self.logger.log(LogPriority.DEBUG, "Running fixes for Mac OS")

        # the following code should only ever be run once on
        # any system
        try:
            # remove old, incorrect STONIX launchd job(s)            
            if not os.path.exists(legacystonixcron):
                for item in servicedict:
                    if os.path.exists(item):
                        os.remove(item)
                f = open(legacystonixcron, 'w')
                f.write("don't delete me")
                f.close()
                os.chown(legacystonixcron, 0, 0)
                os.chmod(legacystonixcron, 0o600)

        except Exception:
            pass

        # create the STONIX launchd jobs
        try:

            if not self.macadminreportjob:
                self.logger.log(LogPriority.DEBUG, "The admin report job is either missing or incorrect. Fixing...")

                # remove existing job file
                if os.path.exists(self.macadminreportpath):
                    os.remove(self.macadminreportpath)

                # create weekly report plist file
                f = open(self.macadminreportpath, 'w')
                f.write(self.stonixplistreport)
                f.close()
                os.chown(self.macadminreportpath, 0, 0)
                os.chmod(self.macadminreportpath, 0o644)
                self.logger.log(LogPriority.DEBUG, "Admin report job has been created and configured")

            if not self.macadminfixjob:
                self.logger.log(LogPriority.DEBUG, "The admin fix job is either missing or incorrect. Fixing...")

                # remove existing job file
                if os.path.exists(self.macadminfixpath):
                    os.remove(self.macadminfixpath)

                # create weekly fix plist file
                f = open(self.macadminfixpath, 'w')
                f.write(self.stonixplistfix)
                f.close()
                os.chown(self.macadminfixpath, 0, 0)
                os.chmod(self.macadminfixpath, 0o644)
                self.logger.log(LogPriority.DEBUG, "Admin fix job has been created and configured")

            if not self.macuserjob:
                self.logger.log(LogPriority.DEBUG, "The user job is either missing or incorrect. Fixing...")

                # remove existing job file
                if os.path.exists(self.macuserpath):
                    os.remove(self.macuserpath)

                # create once-daily user context plist file
                f = open(self.macuserpath, 'w')
                f.write(self.stonixplistuser)
                f.close()
                os.chown(self.macuserpath, 0, 0)
                os.chmod(self.macuserpath, 0o644)
                self.logger.log(LogPriority.DEBUG, "User job has been created and configured")

            self.logger.log(LogPriority.DEBUG, "Loading STONIX jobs...")
            # This part needs to be changed to work with re-designed servicehelperTwo
            for item in servicedict:
                if re.search("user", item, re.IGNORECASE):
                    self.logger.log(LogPriority.DEBUG, "Loading user job...")
                    self.ch.executeCommand("/bin/launchctl load " + item)
                else:
                    if re.search("fix", item, re.IGNORECASE):
                        self.logger.log(LogPriority.DEBUG, "Loading admin fix job...")
                    if re.search("report", item, re.IGNORECASE):
                        self.logger.log(LogPriority.DEBUG, "Loading admin report job...")
                    self.ch.executeCommand("/bin/launchctl enable system/" + str(servicedict[item]))

        except Exception:
            retval = False
            raise
        return retval
