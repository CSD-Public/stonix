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
'''
Created on May 20, 2013

@author: dwalker
@change: 02/16/2014 ekkehard Implemented self.detailedresults flow
@change: 02/16/2014 ekkehard Implemented isapplicable
@change: 04/21/2014 dkennel Updated CI invocation
@change: 2014/10/17 ekkehard OS X Yosemite 10.10 Update
@change: 2015/04/17 dkennel updated for new isApplicable
'''
from __future__ import absolute_import
from ..stonixutilityfunctions import iterate, readFile
from ..rule import Rule
from ..configurationitem import ConfigurationItem
from ..logdispatcher import LogPriority
from ..CommandHelper import CommandHelper
import traceback
import os
import stat
import re
import pwd


class SecureHomeDir(Rule):

    def __init__(self, config, environ, logger, statechglogger):
        Rule.__init__(self, config, environ, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 45
        self.rulename = "SecureHomeDir"
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.rootrequired = False
        self.helptext = '''Ensures that each user's home directory is not \
group writeable or world readable'''
        datatype = 'bool'
        key = 'SECUREHOME'
        instructions = '''To disable this rule set the value of SECUREHOME to \
False.'''
        default = True
        self.ci = self.initCi(datatype, key, instructions, default)
        self.guidance = ['NSA 2.3.4.2']
        self.applicable = {'type': 'white',
                           'family': ['linux', 'solaris', 'freebsd'],
                           'os': {'Mac OS X': ['10.9', 'r', '10.10.10']}}

        self.iditerator = 0
        self.cmdhelper = CommandHelper(self.logger)

###############################################################################

    def report(self):
        try:
            self.detailedresults = ""
            compliant = True

            self.wrong = {}
            self.homedirs = []
            if self.environ.getostype() == "Mac OS X":
                compliant = self.reportMac()
            else:
                compliant = self.reportOther()
            if compliant:
                self.compliant = True
            else:
                self.compliant = False
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

###############################################################################

    def reportMac(self):
        debug = ""
        users = []
        templist = []
        compliant = True
        if self.environ.geteuid() == 0:
            cmd = ["/usr/bin/dscl", ".", "-list", "/Users"]
            if not self.cmdhelper.executeCommand(cmd):
                debug += "Unable to run the /usr/bin/dscl command\n"
                self.logger.log(LogPriority.DEBUG, debug)
                return False
            output = self.cmdhelper.getOutput()
            error = self.cmdhelper.getError()
            if output:
                for item in output:
                    if not re.search("^_", item) and \
                                                  not re.search("^root", item):
                        users.append(item.strip())
            elif error:
                debug += "There was an error in getting users on system\n"
                self.logger.log(LogPriority.DEBUG, debug)
                return False
            if users:
                grpvals = ("7", "2", "3", "6")
                for user in users:
                    templist = []
                    currpwd = pwd.getpwnam(user)
                    try:
                        homedir = currpwd[5]
                        if not os.path.exists(homedir):
                            continue
                        try:
                            #get info about user's directory
                            statdata = os.stat(homedir)

                            #permission returns in integer format
                            mode = stat.S_IMODE(statdata.st_mode)

                            #convert permission to octal format
                            octval = oct(mode)

                            #remove leading 0
                            octval = re.sub("^0", "", octval)

                            #split numeric integer value of permissions
                            #into separate numbers
                            perms = list(octval)

                            grpval = perms[1]
                            world = perms[2]
                            #if the group value equals any of the
                            #following numbers, it is group writeable
                            if grpval in grpvals:
                                templist.append("gw")
                                compliant = False
                            if world != "0":
                                templist.append("wr")
                                compliant = False
                            if templist:
                                self.wrong[homedir] = templist
                        except IndexError:
                            compliant = False
                            debug += traceback.format_exc() + "\n"
                    except IndexError:
                        compliant = False
                        debug += "Not enough information to obtain home \
directory for user: " + user + "\n"
        else:
            currpwd = pwd.getpwuid(self.environ.geteuid())
            try:
                homedir = currpwd[5]
                if not os.path.exists(homedir):
                    compliant = False
                    debug += "This home directory doesn't exist: " + homedir + "\n"
                    try:
                        #get info about user's directory
                        statdata = os.stat(homedir)

                        #permission returns in integer format
                        mode = stat.S_IMODE(statdata.st_mode)

                        #convert permission to octal format
                        octval = oct(mode)

                        #remove leading 0
                        octval = re.sub("^0", "", octval)

                        #split numeric integer value of permissions
                        #into separate numbers
                        perms = list(octval)

                        grpval = perms[1]
                        world = perms[2]
                        #if the group value equals any of the
                        #following numbers, it is group writeable
                        if grpval in grpvals:
                            templist.append("gw")
                            compliant = False
                        if world != "0":
                            templist.append("wr")
                            compliant = False
                        if templist:
                            self.wrong[homedir] = templist
                    except IndexError:
                        compliant = False
                        debug += traceback.format_exc() + "\n"
            except IndexError:
                compliant = False
                debug += "Not enough information to obtain home directory\n"
        if self.wrong:
            badhomes = ""
            for item in self.wrong:
                badhomes += item + "\n"
            self.detailedresults += "The following directories were \
either group writeable or world readable:\n" + str(badhomes) + "\n" 
        if debug:
            self.logger.log(LogPriority.DEBUG, debug)
        return compliant

###############################################################################

    def reportOther(self):
        debug = ""
        uidmin = ""
        compliant = True
        templist = []
        remove = []
        grpvals = ("7", "2", "3", "6")
        unwanted = ["/root", "/", "/usr", "/var", "/lib", "/bin", "/sbin",
                    "/run", "/etc"]
        #we will look for home directories in /etc/passwd and in /home
        if self.environ.getosfamily() == "solaris":
            homebase = "/export/home/"
        else:
            homebase = "/home/"
        #read in /etc/passwd
        contents = readFile("/etc/passwd", self.logger)
        if not contents:
            self.detailedresults += "the /etc/passwd file is blank.  This \
rule cannot be run at all.\n"
            self.formatDetailedResults("report", False, self.detailedresults)
            compliant = False

        #user is root
        elif self.environ.geteuid() == 0:
            if os.path.exists("/etc/login.defs"):
                logindefs = readFile("/etc/login.defs", self.logger)
                for line in logindefs:
                    if re.search("^UID_MIN", line):
                        line = re.sub("\s+", " ", line)
                        temp = line.split()
                        try:
                            if isinstance(int(temp[1]), int):
                                uidmin = int(temp[1])
                        except IndexError:
                            compliant = False
                            debug = traceback.format_exc() + "\n"
                            debug += "Index out of range on line: " + line + "\n"

            #add home directories found in /etc/passwd
            if not uidmin:
                uidmin = 100
            for line in contents:
                if re.search("^#", line) or re.match("^\s*$", line):
                    continue
                if re.search(":", line):
                    temp = line.split(":")
                    try:
                        if re.search("/", temp[5]):
                            if int(temp[2]) >= uidmin and int(temp[2]) != 65534:
                                self.homedirs.append(temp[5])
                        else:
                            debug = "the /etc/passwd file is not in the \
correct format as of the line: " + line + "\n"
                    except IndexError:
                        compliant = False
                        debug = traceback.format_exc() + "\n"
                        debug += "Index out of range on line: " + line + "\n"

            #add home directories found
            output = os.listdir(homebase)
            for item in output:
                if item == "lost+found":
                    continue
                home = homebase + item
                if home not in self.homedirs:
                    self.homedirs.append(home)

            #clean up self.homedirs to not contain any of the root dirs
            for item in self.homedirs:
                for item2 in unwanted:
                    if item2 == "/":
                        if re.search("^" + item2 + "$", item):
                            remove.append(item)
                            break
                    elif re.search("^" + item2, item):
                        remove.append(item)
                        break
            for item in remove:
                self.homedirs.remove(item)

            #let's look at the home directories we found
            if self.homedirs:
                for home in self.homedirs:
                    user = ""
                    if not os.path.exists(home):
                        compliant = False
                        debug += "This home directory doesn't exist: " + home + "\n"
                        continue

                    #here we get just the username from the home directory
                    temphome = home.split("/")
                    try:
                        if temphome[-1] == "":
                            temphome.pop(-1)
                        if temphome[0] == "":
                            temphome.pop(0)
                        user = str(temphome[-1])
                    except IndexError:
                        compliant = False
                        debug += traceback.format_exc() + "\n"
                        debug += "Index out of range on line: " + line + "\n"
                        continue
                    output = os.listdir(homebase)
                    for directory in output:
                        templist = []
                        #we found the current user's home directory
                        if (user == directory):
                            try:
                                #get info about user's directory
                                statdata = os.stat(homebase + directory)

                                #permission returns in integer format
                                mode = stat.S_IMODE(statdata.st_mode)
                                
                                #convert permission to octal format
                                octval = oct(mode)
                                
                                #remove leading 0
                                octval = re.sub("^0", "", octval)
                                
                                #split numeric integer value of permissions
                                #into separate numbers
                                perms = list(octval)
                                
                                
                                grpval = perms[1]
                                world = perms[2]
                                #if the group value equals any of the 
                                #following numbers, it is group writeable
                                if grpval in grpvals:
                                    templist.append("gw")
                                    compliant = False
                                if world != "0":
                                    templist.append("wr")
                                    compliant = False
                                if templist:
                                    self.wrong[home] = templist
                                    break
                            except IndexError:
                                compliant = False
                                debug += traceback.format_exc() + "\n"
                                debug += "Index out of range on line: " + line + "\n"
                                break
                                
        else:
            user = os.getlogin()
            output = os.listdir(homebase)
            for line in output:
                #the current user has a home directory!
                if line == user:
                    home = homebase + line
                    try:
                        #get file information each file
                        statdata = os.stat(home)
                        
                        #permission returns in integer format
                        mode = stat.S_IMODE(statdata.st_mode)
                        
                        #convert permission to octal format
                        octval = oct(mode)
                        
                        #remove leading 0
                        octval = re.sub("^0", "", octval)
                        
                        #split numeric integer value of permissions
                        #into separate numbers
                        perms = list(octval)
                        
                        #group permissions
                        grpval = perms[1]
                        
                        #other permissions(world)
                        world = perms[2]
                        #if the group value equals any of the 
                        #following numbers, it is group writeable
                        if grpval in grpvals:
                            templist.append("gw")
                            compliant = False
                        if world != "0":
                            templist.append("wr")
                            compliant = False
                        if templist:
                            self.wrong[home] = templist
                            break
                    except IndexError:
                        compliant = False
                        debug += traceback.format_exc() + "\n"
                        debug += "Index out of range on line: " + line + "\n"
        if debug:
            self.logger.log(LogPriority.DEBUG, debug)
        return compliant
    
###############################################################################

    def fix(self):
        try:
            if not self.ci.getcurrvalue():
                return
            self.detailedresults = ""
            if self.environ.geteuid() == 0:
                self.iditerator = 0
                eventlist = self.statechglogger.findrulechanges(self.rulenumber)
                for event in eventlist:
                    self.statechglogger.deleteentry(event)
            unsuccessful = []
            if self.wrong:
                for home in self.wrong:
                    if not os.path.exists(home):
                        continue
                    wr, gw = False, False
                    self.iditerator += 1
                    statdata = os.stat(home)
                    owner = statdata.st_uid
                    group = statdata.st_gid
                    mode = stat.S_IMODE(statdata.st_mode)
                    myid = iterate(self.iditerator, self.rulenumber)
                    event = {'eventtype':'perm',
                             'startstate':[owner, group, mode],
                             'filepath':home}
                    subset = self.wrong[home]
                    if "gw" in subset:
                        cmd = ['chmod', 'g-w', home]
                        if self.cmdhelper.executeCommand(cmd):
                            gw = True
                    else:
                        gw = True
                    if "wr" in subset:
                        cmd = ['chmod', 'o-rwx', home]
                        if self.cmdhelper.executeCommand(cmd):
                            wr = True
                    else:
                        wr = True
                    if not gw or not wr:
                        unsuccessful.append(home)
                        continue
                    if self.environ.geteuid() == 0:
                        self.statechglogger.recordchgevent(myid, event)
                    
                if unsuccessful:
                    badhomes = ""
                    for item in unsuccessful:
                        badhomes += item + "\n"
                    self.rulesuccess = False
                    debug = "the following home directories were unsuccessful \
in setting the proper permissions: " + str(badhomes) + "\n"
                    self.logger.log(LogPriority.DEBUG, debug)
        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.rulesuccess
###############################################################################