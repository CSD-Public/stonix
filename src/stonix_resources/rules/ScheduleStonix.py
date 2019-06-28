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

"""
Created on Dec 12, 2013

Schedule Stonix to run randomly throughout the week and once in a user context
per day

@author: Breen Malmberg
@change: 2014/02/16 Ekkehard Implemented self.detailedresults flow
@change: 2014/02/16 Ekkehard Implemented isapplicable
@change: 2014/04/30 Dave Kennel Corrected bug where crons were created without -c
@change: 2014/04/30 Dave Kennel Added newline to crontab entries to prevent damage
@change: 2014/04/30 Dave Kennel Corrected overly greedy regexes
@change: 2014/09/02 Ekkehard self.rootrequired = True & OS X 10.10 compliant
@change: 2015/04/17 Dave Kennel updated for new isApplicable
@change: 2015/10/08 Eric Ball Help text cleanup

@change 2017/01/31 Breen Malmberg removed superfluous logging entries (now contained
        within ServiceHelper and SHlaunchd)
@change: 2017/10/23 Roy Nielsen - change to new service helper interface
@change: 2017/11/27 Breen Malmberg removed print statements
"""

from __future__ import absolute_import

import random
import os
import re
import traceback

from ..rule import Rule
from ..logdispatcher import LogPriority
from ..stonixutilityfunctions import readFile, getOctalPerms
from ..ServiceHelper import ServiceHelper
from ..CommandHelper import CommandHelper


class ScheduleStonix(Rule):
    """Schedule Stonix to run randomly throughout the week and once in a user
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


    """

    def __init__(self, config, environ, logger, statechglogger):
        """
        Constructor
        """

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

        datatype = "int"
        keyfd = "FIXDAY"
        keyfh = "FIXHOUR"
        keyfm = "FIXMINUTE"
        keyrd = "REPORTDAY"
        keyrh = "REPORTHOUR"
        keyrm = "REPORTMINUTE"
        keyufh = "USERCONTEXTFIXHOUR"
        keyufm = "USERCONTEXTFIXMINUTE"
        instruct_fd = "Enter the day of the week you would like the fix job to run (1-7). 1 = Monday. 7 = Sunday. This value cannot be the same as REPORTDAY value."
        instruct_fh = "Enter the hour of the day you would like the fix job to run (0-23). 0 = Midnight. This value cannot be the same as USERCONTEXTFIXHOUR value."
        instruct_fm = "Enter the minute of the hour you would like the fix job to run (0-59)."
        instruct_rd = "Enter the day of the week you would like the report job to run (1-7) 1 = Monday. 7 = Sunday. This value cannot be the same as FIXDAY value."
        instruct_rh = "Enter the hour of the day you would like the report job to run (0-23) 0 = Midnight. This value cannot be the same as USERCONTEXTFIXHOUR value."
        instruct_rm = "Enter the minute of the hour you would like the report job to run (0-59)."
        instruct_ufh = "Enter the hour of the day you would like the user-context fix job to run (0-23). This value cannot be the same as FIXHOUR value or REPORTHOUR value."
        instruct_ufm = "Enter the minute of the hour you would like the user-context fix job to run (0-59)."
        default = 0

        datatype2 = "bool"
        key2 = "CONFIGUREJOBTIMESMANUALLY"
        instruct2 = "Set the value of CONFIGUREJOBTIMESMANUALLY to True, in order to manually specify when each STONIX job should run (as opposed to using randomly generated times)."
        default2 = False
        self.manualjobtimesCI = self.initCi(datatype2, key2, instruct2, default2)

        datatype3 = "bool"
        key3 = "SCHEDULEFIXJOBS"
        instruct3 = "To prevent STONIX from being schedule to run in fix mode, set the value of SCHEDULEFIXJOBS to False"
        default3 = True
        self.schedulefixjobsCI = self.initCi(datatype3, key3, instruct3, default3)

        self.fixdayCI = self.initCi(datatype, keyfd, instruct_fd, default)
        self.fixhourCI = self.initCi(datatype, keyfh, instruct_fh, default)
        self.fixminuteCI = self.initCi(datatype, keyfm, instruct_fm, default)
        self.reportdayCI = self.initCi(datatype, keyrd, instruct_rd, default)
        self.reporthourCI = self.initCi(datatype, keyrh, instruct_rh, default)
        self.reportminuteCI = self.initCi(datatype, keyrm, instruct_rm, default)
        self.userfixhourCI = self.initCi(datatype, keyufh, instruct_ufh, default)
        self.userfixminuteCI = self.initCi(datatype, keyufm, instruct_ufm, default)

        self.initVars()
        if self.firstRun():
            self.initTimes()

    def initTimes(self):
        """ """

        self.genJobTimes()
        self.syncCITimes()
        if self.checkJobCollisions():
            return self.initTimes()

    def syncCITimes(self):
        """ """

        self.fixdayCI.updatecurrvalue(self.adminfixday)
        self.fixhourCI.updatecurrvalue(self.adminfixhour)
        self.fixminuteCI.updatecurrvalue(self.adminfixminute)
        self.reportdayCI.updatecurrvalue(self.adminreportday)
        self.reporthourCI.updatecurrvalue(self.adminreporthour)
        self.reportminuteCI.updatecurrvalue(self.adminreportminute)
        self.userfixhourCI.updatecurrvalue(self.userfixhour)
        self.userfixminuteCI.updatecurrvalue(self.userfixminute)

    def firstRun(self):
        """ """

        firstrun = True
        total = 0

        total = self.fixdayCI.getcurrvalue() + \
        self.fixhourCI.getcurrvalue() + \
        self.fixminuteCI.getcurrvalue() + \
        self.reportdayCI.getcurrvalue() + \
        self.reporthourCI.getcurrvalue() + \
        self.reportminuteCI.getcurrvalue() + \
        self.userfixhourCI.getcurrvalue() + \
        self.userfixminuteCI.getcurrvalue()

        if total > 0:
            firstrun = False

        return firstrun

    def buildFiles(self):
        """dynamically build the conf and script files
        based on the generated or entered times
        
        @author: Breen Malmberg


        """

        # define the Mac OS X weekly STONIX report launchd job
        self.stonixplistreport = """<?xml version="1.0" encoding="UTF-8"?>
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
            <integer>""" + str(self.adminreportday) + """</integer>
            <key>Hour</key>
            <integer>""" + str(self.adminreporthour) + """</integer>
            <key>Minute</key>
            <integer>""" + str(self.adminreportminute) + """</integer>
        </dict>
    </array>
</dict>
</plist>"""

        # define the Mac OS X weekly STONIX fix launchd job
        self.stonixplistfix = """<?xml version="1.0" encoding="UTF-8"?>
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
            <integer>""" + str(self.adminfixday) + """</integer>
            <key>Hour</key>
            <integer>""" + str(self.adminfixhour) + """</integer>
            <key>Minute</key>
            <integer>""" + str(self.adminfixminute) + """</integer>
        </dict>
    </array>
</dict>
</plist>"""

        # define the once-daily STONIX user-context launch agent job
        self.stonixplistuser = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>gov.lanl.stonix.user</string>
    <key>ProgramArguments</key>
    <array>
        <string>/Applications/stonix4mac.app/Contents/Resources/stonix.app/Contents/MacOS/stonix</string>
        <string>-c</string>
        <string>-""" + self.usermode + """</string>
    </array>
    <key>StartCalendarInterval</key>
    <array>
        <dict>
            <key>Hour</key>
            <integer>""" + str(self.userfixhour) + """</integer>
            <key>Minute</key>
            <integer>""" + str(self.userfixminute) + """</integer>
        </dict>
    </array>
</dict>
</plist>"""

        self.userstonixscript = """#! /usr/bin/env python

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
            os.system(stonixscriptpath + ' -c""" + self.usermode + """')

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
            exit(exitcode)"""

    def initVars(self):
        """initialize all of the time variables
        to be used by the class
        
        @author: Breen Malmberg


        """

        self.svchelper = ServiceHelper(self.environ, self.logger)

        # init cronfilelocation to blank
        self.cronfilelocation = "/etc/crontab"

        self.userscriptfile = "/etc/profile.d/user-stonix.py"

        self.crontimedict = {}

        # get the STONIX executable path
        self.stonixpath = self.environ.get_script_path()

        self.userfixhour = 0
        self.userfixminute = 0
        self.adminfixday = 0
        self.adminfixhour = 0
        self.adminfixminute = 0
        self.adminreportday = 0
        self.adminreporthour = 0
        self.adminreportminute = 0

    def setUserTimes(self):
        """ """

        self.adminfixday = self.fixdayCI.getcurrvalue()
        self.adminfixhour = self.fixhourCI.getcurrvalue()
        self.adminfixminute = self.fixminuteCI.getcurrvalue()
        self.adminreportday = self.reportdayCI.getcurrvalue()
        self.adminreporthour = self.reporthourCI.getcurrvalue()
        self.adminreportminute = self.reportminuteCI.getcurrvalue()
        self.userfixhour = self.userfixhourCI.getcurrvalue()
        self.userfixminute = self.userfixminuteCI.getcurrvalue()

        self.crontimedict['report'] = str(self.adminreportminute) + ' ' + str(self.adminreporthour) + ' \* \* ' + str(
            self.adminreportday)
        self.crontimedict['fix'] = str(self.adminfixminute) + ' ' + str(self.adminfixhour) + ' \* \* ' + str(
            self.adminfixday)

    def checkJobCollisions(self):
        """check to make sure none of the generated
        job times overlap, or are invalid
        return True if invalid or overlap
        return False if valid and not overlap


        :returns: collisions

        :rtype: list

@author: Breen Malmberg

        """

        self.logger.log(LogPriority.DEBUG, "Checking for job time collisions...")

        collisions = []

        # job collision validation
        if self.fixdayCI.getcurrvalue() == self.reportdayCI.getcurrvalue():
            collisions.append("afd")
        if self.userfixhourCI.getcurrvalue() == self.fixhourCI.getcurrvalue():
            collisions.append("ufh")
        if self.userfixhourCI.getcurrvalue() == self.reporthourCI.getcurrvalue():
            collisions.append("arh")

        if collisions:
            self.logger.log(LogPriority.DEBUG, "Job time collision detected.")

        return collisions

    def validateUserTimes(self):
        """check the entered user-defined cron job times to see if they are valid


        :returns: valid

        :rtype: bool
@author: Breen Malmberg

        """

        valid = True
        formatvalid = True
        rangevalid = True
        collisions = []

        fixday = self.fixdayCI.getcurrvalue()
        fixhour = self.fixhourCI.getcurrvalue()
        fixminute = self.fixminuteCI.getcurrvalue()
        reportday = self.reportdayCI.getcurrvalue()
        reporthour = self.reporthourCI.getcurrvalue()
        reportminute = self.reportminuteCI.getcurrvalue()
        userfixhour = self.userfixhourCI.getcurrvalue()
        userfixminute = self.userfixminuteCI.getcurrvalue()

        self.logger.log(LogPriority.DEBUG, "Validating user-entered job times...")

        self.logger.log(LogPriority.DEBUG, "Checking job times format (integer length).")

        # length (digits) input validation
        il = []
        if len(str(fixday).lstrip("0")) > 1:
            formatvalid = False
            il.append("fixday should be 1 integer in length")
        if len(str(reportday).lstrip("0")) > 1:
            formatvalid = False
            il.append("reportday should be 1 integer in length")
        if len(str(fixhour).lstrip("0")) > 2:
            formatvalid = False
            il.append("fixhour should be no more than 2 integers in length")
        if len(str(fixminute).lstrip("0")) > 2:
            formatvalid = False
            il.append("fixminute should be no more than 2 integers in length")
        if len(str(reporthour).lstrip("0")) > 2:
            formatvalid = False
            il.append("reporthour should be no more than 2 integers in length")
        if len(str(reportminute).lstrip("0")) > 2:
            formatvalid = False
            il.append("reportminute should be no more than 2 integers in length")
        if len(str(userfixhour).lstrip("0")) > 2:
            formatvalid = False
            il.append("userfixhour should be no more than 2 integers in length")
        if len(str(userfixminute).lstrip("0")) > 2:
            formatvalid = False
            il.append("userfixminute should be no more than 2 integers in length")

        if not formatvalid:
            self.detailedresults += "\nIncorrect job time format detected. Incorrect integer length:\n" + "\n".join(il)

        # range input validation
        oor = []
        if fixday not in range(1, 8):
            rangevalid = False
            oor.append("fixday: " + str(fixday))
        if reportday not in range(1, 8):
            rangevalid = False
            oor.append("reportday: " + str(reportday))
        if fixhour not in range(0, 24):
            rangevalid = False
            oor.append("fixhour: " + str(fixhour))
        if reporthour not in range(0, 24):
            rangevalid = False
            oor.append("reporthour: " + str(reporthour))
        if fixminute not in range(0, 60):
            rangevalid = False
            oor.append("fixminute: " + str(fixminute))
        if reportminute not in range(0, 60):
            rangevalid = False
            oor.append("reportminute: " + str(reportminute))
        if userfixhour not in range(0, 24):
            rangevalid = False
            oor.append("userfixhour: " + str(userfixhour))
        if userfixminute not in range(0, 60):
            oor.append("userfixminute: " + str(userfixminute))

        if not rangevalid:
            self.detailedresults += "\nIncorrect job time format detected. Job time(s) outside valid range:\n" + "\n".join(oor)

        # fix any job time collisions
        collisions = self.checkJobCollisions()
        if collisions:
            if "afd" in collisions:
                self.detailedresults += "\nThere is a time collision between admin fix day and admin report day"
            if "ufh" in collisions:
                self.detailedresults += "\nThere is a time collision between user fix hour and admin fix hour"
            if "urh" in collisions:
                self.detailedresults += "\nThere is a time collision between user fix hour and admin report hour"

        if not rangevalid:
            valid = False
        if not formatvalid:
            valid = False
        if collisions:
            valid = False

        if valid:
            self.detailedresults += "\nAll user-entered job times are valid. Proceeding..."
        else:
            self.detailedresults += "\nUser-entered job time(s) not valid. Please correct the issue(s) and run fix again, to set your custom job time(s)."

        return valid

    def randomExcept(self, lowest, highest, exclude=None):
        """generate a random number between lowest and highest (including lowest)
        but excluding the given number exclude
        (result will never be = highest)

        :param lowest: int; lower bound
        :param highest: int; upper bound
        :param exclude: int|list; integer or range of integers to exclude from result
                default value for exclude is None
        :returns: x
        :rtype: int

@author: Breen Malmberg

        """

        x = 0

        if lowest == highest:
            self.logger.log(LogPriority.WARNING, "lowest argument must be less than highest argument")
            if lowest != exclude:
                x = lowest
            return x

        if lowest > highest:
            self.logger.log(LogPriority.WARNING, "lowest argument must be less than highest argument")
            return x

        if type(exclude).__name__ == "str":
            exclude = int(exclude)
        elif type(exclude).__name__ == "NoneType":
            pass
        else:
            self.logger.log(LogPriority.WARNING, "Incorrect type for argument: exclude. Needs to be either list or int. Got: " + type(exclude).__name__)
            return x

        x = random.randrange(lowest, highest)
        if exclude == None:
            return x

        if type(exclude).__name__ == "list":
            if x in exclude:
                x = self.randomExcept(lowest, highest, exclude)
        elif type(exclude).__name__ == "int":
            if x == exclude:
                x = self.randomExcept(lowest, highest, exclude)

        return x

    def genJobTimes(self, *args):
        """Generate random times to run the STONIX jobs
        Build the crontimedict used by Linux
        
        @author: Breen Malmberg

        :param *args: 

        """

        genall = False

        self.logger.log(LogPriority.DEBUG, "Generating new, random job times...")

        if "all" in args:
            genall = True
        elif not args:
            genall = True
        else:
            if "afd" in args:
                self.adminfixday = random.randrange(1, 8)
            if "afh" in args:
                self.adminfixhour = random.randrange(17, 24)
            if "afm" in args:
                self.adminfixminute = random.randrange(0, 60)
            if "ard" in args:
                self.adminreportday = random.randrange(1, 8)
            if "arh" in args:
                self.adminreporthour = random.randrange(17, 24)
            if "arm" in args:
                self.adminreportminute = random.randrange(0, 60)
            if "ufh" in args:
                self.userfixhour = random.randrange(17, 24)
            if "ufm" in args:
                self.userfixminute = random.randrange(0, 60)

        if genall:
            self.adminfixday = random.randrange(1, 8)
            self.adminfixhour = random.randrange(17, 24)
            self.adminfixminute = random.randrange(0, 60)

            self.adminreportday = random.randrange(1, 8)
            self.adminreporthour = random.randrange(17, 24)
            self.adminreportminute = random.randrange(0, 60)

            self.userfixhour = random.randrange(17, 24)
            self.userfixminute = random.randrange(0, 60)

        self.crontimedict['report'] = str(self.adminreportminute) + ' ' + str(self.adminreporthour) + ' * * ' + str(self.adminreportday)
        self.crontimedict['fix'] = str(self.adminfixminute) + ' ' + str(self.adminfixhour) + ' * * ' + str(self.adminfixday)

    def getFileContents(self, filepath):
        """Read file contents from given filepath, into a list
        Return the list (of strings)
        Return empty list if given filepath does not exist

        :param filepath: 
        :returns: contents
        :rtype: list

@author: Breen Malmberg

        """

        contents = []

        if os.path.exists(filepath):
            f = open(filepath, 'r')
            contents = f.readlines()
            f.close()

        return contents

    def report(self):
        """Linux:
        Check that Cron file(s) exist and that they contain the correct job entries
        Check that the STONIX user script exists and contains the correct contents
        
        Mac:
        Check that the launchd files exist
        Check that each launchd file contains the correct contents


        :returns: self.compliant

        :rtype: bool

@author: Breen Malmberg

        """

        self.compliant = True
        self.detailedresults = ""
        self.ch = CommandHelper(self.logger)
        if self.schedulefixjobsCI.getcurrvalue():
            self.usermode = 'f'
        else:
            self.usermode = 'r'

        if self.manualjobtimesCI.getcurrvalue():
            self.logger.log(LogPriority.DEBUG, "Using user-configured job times...")
            if self.validateUserTimes():
                self.setUserTimes()
            else:
                self.compliant = False
                self.detailedresults += "\nThe user-specified cron job time was invalid."
                self.formatDetailedResults("report", self.compliant, self.detailedresults)
                self.logger.log(LogPriority.INFO, self.detailedresults)
                return self.compliant
            collisions = self.checkJobCollisions()
            for item in collisions:
                self.genJobTimes(item)
            if collisions:
                self.detailedresults += "\nOne of the times entered was invalid because it would cause more than one of the jobs to run at the same time. The offending time entry has been changed to a new, randomly generated one."
                self.syncCITimes()
        else:
            self.logger.log(LogPriority.DEBUG, "Using randomly generated job times...")
            if self.checkJobCollisions():
                self.genJobTimes()
                self.syncCITimes()

        self.logger.log(LogPriority.DEBUG, "Building configuration files text, using job times...")
        self.buildFiles()

        self.logger.log(LogPriority.DEBUG, "STONIX path set to: " + str(self.stonixpath))

        try:

            # if Mac OS, check Mac launch daemon and agent jobs
            if self.environ.getostype() == "Mac OS X":
                if not self.reportMac():
                    self.compliant = False
            else:
                # else check Linux cron jobs
                if not self.reportLinux():
                    self.compliant = False

        except(KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.detailedresults += "\n" + traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant, self.detailedresults)
        self.logger.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

    def reportLinux(self):
        """Check for STONIX Cron job entries in the Linux crontab


        :returns: retval

        :rtype: bool

@author: Breen Malmberg

        """

        retval = True

        self.cronfileexists = True
        self.reportjob = False
        self.fixjob = False
        self.userjob = True
        stonixreportjob = ' root nice -n 19 ' + str(self.stonixpath) + '/stonix.py -cr'
        stonixfixjob = ' root nice -n 19 ' + str(self.stonixpath) + '/stonix.py -cdf'

        # check for existence of system crontab file
        if not os.path.exists(self.cronfilelocation):
            self.cronfileexists = False
            self.detailedresults += '\nSystem crontab file does not exist'
        else:
            # check for STONIX cron job entries
            contents = self.getFileContents(self.cronfilelocation)
            if not contents:
                self.detailedresults += '\nSystem crontab file was empty'
            else:
                # report entry
                for line in contents:
                    self.logger.log(LogPriority.DEBUG, "Comparing line:\n" + str(line) + "to stonixreportjob:\n" + str(stonixreportjob))
                    if re.search(stonixreportjob, line, re.IGNORECASE):
                        self.logger.log(LogPriority.DEBUG, "REPORT JOB FOUND")
                        self.reportjob = True
                    else:
                        self.logger.log(LogPriority.DEBUG, "Lines do NOT match")

                if not self.reportjob:
                    self.detailedresults += '\nSTONIX report job not found\n'
                else:
                    self.detailedresults += '\nSTONIX report job found\n'

                self.logger.log(LogPriority.DEBUG, "After report entry check: reportjob is " + str(self.reportjob))

                # fix entry
                for line in contents:
                    self.logger.log(LogPriority.DEBUG, "Comparing line:\n" + str(line) + "to stonixfixjob:\n" + str(stonixfixjob))
                    if re.search(stonixfixjob, line, re.IGNORECASE):
                        self.logger.log(LogPriority.DEBUG, "FIX JOB FOUND")
                        self.fixjob = True
                    else:
                        self.logger.log(LogPriority.DEBUG, "Lines do NOT match")

                if not self.fixjob:
                    self.detailedresults += '\nSTONIX fix job not found\n'
                else:
                    self.detailedresults += '\nSTONIX fix job found\n'

                self.logger.log(LogPriority.DEBUG, "After fix entry check: fixjob is " + str(self.fixjob))

            self.logger.log(LogPriority.DEBUG, "Before permissions check: retval is " + str(retval))

            # check perms of system crontab
            crontabperms = getOctalPerms(self.cronfilelocation)
            if crontabperms != 600:
                self.logger.log(LogPriority.DEBUG, "crontab perms should be 600. Got: " + str(crontabperms))
                self.detailedresults += "\nIncorrect permissions detected on system crontab file"
                retval = False

        self.logger.log(LogPriority.DEBUG, "Before user script checks: retval is " + str(retval))

        # check user script
        if not os.path.exists(self.userscriptfile):
            self.userjob = False
            self.detailedresults += '\nSTONIX user script not found'
        else:
            self.detailedresults += '\nSTONIX user script found'
            contents = self.getFileContents(self.userscriptfile)

            userjobline = "os.system(stonixscriptpath + ' -c" + self.usermode + "')"

            stripped_contents = list(map(str.strip, contents))

            if userjobline not in stripped_contents:
                self.userjob = False
                self.detailedresults += '\nSTONIX user script has incorrect contents'
            else:
                self.detailedresults += '\nSTONIX user script has correct contents'
            # check perms on user script file
            userscriptperms = getOctalPerms(self.userscriptfile)
            if userscriptperms != 755:
                self.detailedresults += "\nIncorrect permissions detected on user script file: " + str(self.userscriptfile)

        self.logger.log(LogPriority.DEBUG, "Before Final Checks: retval is " + str(retval))

        if not self.cronfileexists:
            retval = False
        if not self.reportjob:
            retval = False
        if not self.fixjob:
            retval = False
        if not self.userjob:
            retval = False

        return retval

    def reportMac(self):
        """Check for the existence of the necessary STONIX launchd jobs
        Check that each STONIX launchd job contains the correct contents


        :returns: retval

        :rtype: bool

@author Breen Malmberg

        """

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
                    try:
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
                    except IndexError:
                        pass

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

        except Exception:
            raise
        return retval

    def fix(self):
        """Mac OS X: Create or edit STONIX launchd jobs as necessary
        Linux: Create or edit STONIX Cron job entries as necessary

        :return: self.rulesuccess
        :rtype: bool

        """

        self.detailedresults = ""
        self.rulesuccess = True

        try:

            if self.manualjobtimesCI.getcurrvalue():
                if not self.validateUserTimes():
                    self.rulesuccess = False
                    self.detailedresults += "\nThe user-specified cron job time was incorrectly specified."
                    self.formatDetailedResults("fix", self.rulesuccess, self.detailedresults)
                    self.logger.log(LogPriority.INFO, self.detailedresults)
                    return self.rulesuccess

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
            self.detailedresults += "\n" + traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
            self.rulesuccess = False
        self.formatDetailedResults("fix", self.rulesuccess, self.detailedresults)
        self.logger.log(LogPriority.INFO, self.detailedresults)

        return self.rulesuccess

    def fixLinux(self):
        """Create or edit STONIX Cron jobs for Linux, as necessary

        :return: retval
        :rtype: bool

        """

        retval = True

        # create the report and fix Cron entry strings
        reportstring = '\n' + str(self.reportminuteCI.getcurrvalue()) + ' ' + str(self.reporthourCI.getcurrvalue()) + ' * * ' + str(
            self.reportdayCI.getcurrvalue()) + ' root nice -n 19 ' + str(self.stonixpath) + '/stonix.py' + ' -cr'
        fixstring = '\n' + str(self.fixminuteCI.getcurrvalue()) + ' ' + str(self.fixhourCI.getcurrvalue()) + ' * * ' + str(
            self.fixdayCI.getcurrvalue()) + ' root nice -n 19 ' + str(self.stonixpath) + '/stonix.py' + ' -cdf &> /var/log/stonix-lastfix.log\n'

        # create Cron file if it doesn't exist
        if not self.cronfileexists:
            contents = []
            f = open(self.cronfilelocation, 'w')
            contents.append('## This file created by STONIX\n\n')
            contents.append(reportstring)
            if self.schedulefixjobsCI.getcurrvalue():
                contents.append(fixstring)
            f.writelines(contents)
            f.close()
        else:

            contents = self.getFileContents(self.cronfilelocation)

            # add report line if it doesn't exist
            if not self.reportjob:
                # remove any existing erroneous job times
                for line in contents:
                    if re.search("stonix.*-cr", line, re.IGNORECASE):
                        contents = [c.replace(line, '') for c in contents]
                contents.append(reportstring)

            if self.schedulefixjobsCI.getcurrvalue():
                # add fix line if it doesn't exist
                if not self.fixjob:
                    # remove any existing erroneous job times
                    for line in contents:
                        if re.search("stonix.*-cdf", line, re.IGNORECASE):
                            contents = [c.replace(line, '') for c in contents]
                    contents.append(fixstring)

            f = open(self.cronfilelocation, 'w')
            f.writelines(contents)
            f.close()
            os.chown(self.cronfilelocation, 0, 0)
            os.chmod(self.cronfilelocation, 0600)

        if not self.userjob:
            self.logger.log(LogPriority.DEBUG, "Fixing the STONIX user script...")
            # create the user script
            if not os.path.exists(self.userscriptfile):
                try:
                    if not os.path.exists('/etc/profile.d'):
                        os.makedirs('/etc/profile.d', 0755)
                        os.chown('/etc/profile.d', 0, 0)

                    self.logger.log(LogPriority.DEBUG, "Creating user script file and writing correct contents...")
                    f = open(self.userscriptfile, 'w')
                    f.write(self.userstonixscript)
                    f.close()

                    os.chown(self.userscriptfile, 0, 0)
                    os.chmod(self.userscriptfile, 0755)
                except Exception:
                    retval = False
                    self.logger.log(LogPriority.DEBUG, "Failed to create user script file")

            # write correct contents
            else:

                try:

                    self.logger.log(LogPriority.DEBUG, "Writing correct contents to user script file...")
                    f = open(self.userscriptfile, 'w')
                    f.write(self.userstonixscript)
                    f.close()

                    os.chown(self.userscriptfile, 0, 0)
                    os.chmod(self.userscriptfile, 0755)

                except Exception:
                    retval = False
                    self.logger.log(LogPriority.DEBUG, "Failed to write contents to user script file")

        self.logger.log(LogPriority.DEBUG, "Setting Permissions and Ownership on crontab file...")

        os.chown(self.cronfilelocation, 0, 0)
        os.chmod(self.cronfilelocation, 0600)

        return retval

    def fixMac(self):
        """Create or edit STONIX launchd jobs for Mac OS X
        Create or edit the STONIX launch agent user job for Mac OS X

        :return: retval
        :rtype: bool

        """

        retval = True
        self.macadminfixpath = "/Library/LaunchDaemons/gov.lanl.stonix.fix.plist"
        self.macadminreportpath = "/Library/LaunchDaemons/gov.lanl.stonix.report.plist"
        self.macuserpath = "/Library/LaunchAgents/gov.lanl.stonix.user.plist"

        # defaults
        servicedict = {'/Library/LaunchDaemons/gov.lanl.stonix.report.plist':
                       'gov.lanl.stonix.report',
                       '/Library/LaunchDaemons/gov.lanl.stonix.fix.plist':
                       'gov.lanl.stonix.fix',
                       '/Library/LaunchAgents/gov.lanl.stonix.user.plist':
                       'gov.lanl.stonix.user'}

        self.logger.log(LogPriority.DEBUG, "Running fixes for Mac OS")

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

                if self.schedulefixjobsCI.getcurrvalue():
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

#!FIXME This part needs to be changed to work with servicehelper
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
