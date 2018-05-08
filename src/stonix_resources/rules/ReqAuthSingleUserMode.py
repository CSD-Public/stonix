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
Created on Dec 4, 2012
The ReqAuthSingleUserMode class checks if the system currently requires
authentication for single-user mode or not, and if it does not then it makes
the necessary config file changes to require authentication for single-user
mode.

@author: bemalmbe
@change: 02/16/2014 ekkehard Implemented self.detailedresults flow
@change: 02/16/2014 ekkehard Implemented isapplicable
@change: 04/21/2014 dkennel Updated CI invocation, fixed bug where rule did not
reference the CI before executing FIX.
@Note: Does not work on OS X
@change: 5/3/2014 dwalker-removed self.environ, self.statechglogger,
    self.config self.compliant, self.rootrequired variables.  No need to
    override them. Refactoring rule completely, current implementation doesn't
    check efficiently enough for compliance.
@change: 2015/04/16 dkennel updated for new isApplicable
@change: 2015/10/07 eball Help text cleanup
'''

from __future__ import absolute_import
import os
import re
import traceback

from ..rule import Rule
from ..stonixutilityfunctions import readFile, writeFile, createFile, iterate
from ..stonixutilityfunctions import setPerms, checkPerms, resetsecon
from ..logdispatcher import LogPriority
from ..pkghelper import Pkghelper


class ReqAuthSingleUserMode(Rule):
    '''
    The ReqAuthSingleUserMode class checks if the system currently requires
    authentication for single-user mode or not, and if it does not then it makes
    the necessary config file changes to require authentication for single-user
    mode.
    '''

    def __init__(self, config, environ, logger, statechglogger):
        '''
        Constructor
        '''

        Rule.__init__(self, config, environ, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 38
        self.rulename = 'ReqAuthSingleUserMode'
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.sethelptext()
        self.guidance = ['CIS, NSA(2.3.5.3)']
        self.applicable = {'type': 'black',
                           'family': ['darwin']}
        datatype = 'bool'
        key = 'REQAUTHSINGLEUSERMODE'
        instructions = '''To prevent the requiring of authentication for \
single-user mode, set the value of REQAUTHSINGLEUSERMODE to False.'''
        default = True
        self.ci = self.initCi(datatype, key, instructions, default)
        self.iditerator = 0

###############################################################################

    def report(self):
        '''
        The report method examines the current configuration and determines
        whether or not it is correct. If the config is correct then the
        self.compliant, self.detailedresults and self.currstate properties are
        updated to reflect the system status. self.rulesuccess will be updated
        if the rule does not succeed.

        @return bool
        @author bemalmbe
        '''

        compliant = True
        try:
            self.detailedresults = ""
            self.ph = Pkghelper(self.logger, self.environ)
            #apt-get and zypper like systems automatically require a password
            #for single user mode and there is no way to disable it
            if not self.ph.manager == "apt-get" and not self.ph.manager == \
                                                                      "zypper":
                if self.ph.manager == "freebsd":
                    fp = "/etc/ttys"
                    if os.path.exists(fp):
                        if not checkPerms(fp, [0, 0, 420], self.logger):
                            self.detailedresults += "Permissions aren't \
correct for: " + fp + "\n"
                            compliant = False
                        contents = readFile(fp, self.logger)
                        if contents:
                            for line in contents:
                                if re.search("^tty", line):
                                    if re.search("secure", line):
                                        self.detailedresults += "file \
contents for: " + fp + " are not correct\n"
                                        compliant = False
                                        
                                        
                if self.ph.manager == "yum":
                    fp = "/etc/sysconfig/init"
                    if os.path.exists(fp):
                        if not checkPerms(fp, [0, 0, 420], self.logger):
                            self.detailedresults += "Permissions aren't \
correct for: " + fp + "\n"
                            compliant = False
                        contents = readFile(fp, self.logger)
                        if contents:
                            linefound = False
                            for line in contents:
                                if re.search("^SINGLE", line.strip()):
                                    if re.search("=", line):
                                        temp = line.split("=")
                                        try:
                                            if temp[1].strip() == "/sbin/sulogin":
                                                linefound = True
                                                break
                                            else:
                                                compliant = False
                                                break
                                        except IndexError:
                                            debug = traceback.format_exc() + "\n"
                                            debug += "Index out of range on line: " + line + "\n"
                                            self.logger.log(LogPriority.DEBUG, debug)
                            if not linefound:
                                self.detailedresults += "file contents \
for: " + fp + " are not correct\n"
                                compliant = False
                                
                                
#                 if self.ph.manager == "zypper":   
#                     fp = "/etc/inittab"   
#                     if os.path.exists(fp):
#                         if not checkPerms(fp, [0, 0, 420], self.logger):
#                             self.detailedresults += "Permissions aren't \
# correct for: " + fp + "\n"
#                             compliant = False
#                         contents = readFile(fp, self.logger)
#                         if contents:
#                             linefound = False
#                             for line in contents:
#                                 if re.search("^~~:S:wait:/sbin/sulogin", line.strip()):
#                                     linefound = True
#                             if not linefound:
#                                 self.detailedresults += "file contents \
# for: " + fp + " are not correct\n"
#                                 compliant = False
                                
                                
                if self.ph.manager == "solaris":
                    fp = "/etc/default/sulogin"
                    if os.path.exists(fp):
                        if not checkPerms(fp, [0, 0, 420], self.logger):
                            self.detailedresults += "Permissions aren't \
correct for: " + fp + "\n"
                            compliant = False
                        contents = readFile(fp, self.logger)
                        if contents:
                            linefound = False
                            for line in contents:
                                if re.search("^PASSREQ", line.strip()):
                                    if re.search("=", line):
                                        temp = line.split("=")
                                        try:
                                            if temp[1].strip() == "YES":
                                                linefound = True
                                        except IndexError:
                                            debug = traceback.format_exc() + "\n"
                                            debug += "Index out of range on line: " + line + "\n"
                                            self.logger.log(LogPriority.DEBUG, debug)
                            if not linefound:
                                self.detailedresults += "file contents \
for: " + fp + " are not correct\n"
                                compliant = False
            self.compliant = compliant
        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
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

    def fix(self):
        '''
        The fix method will apply the required settings to the system. 
        self.rulesuccess will be updated if the rule does not succeed.
        Enter the correct config entry in EITHER /etc/inittab OR 
        /etc/default/sulogin OR /etc/ttys OR /etc/sysconfig/init to require 
        authentication with single-user mode.

        @author bemalmbe
        '''
        try:
            if not self.ci.getcurrvalue():
                return
            
            success = True
            self.detailedresults = ""
            
            #clear out event history so only the latest fix is recorded
            self.iditerator = 0
            eventlist = self.statechglogger.findrulechanges(self.rulenumber)
            for event in eventlist:
                self.statechglogger.deleteentry(event)
                    
            #there is no way to disable the requirement of a password for 
            #apt-get systems so no need to do anything 
            if not self.ph.manager == "apt-get" and not self.ph.manager == \
                                                                      "zypper":
                
                #solution for bsd
                if self.ph.manager == "freebsd":
                    fp = "/etc/ttys"
                    tfp = fp + ".tmp"
                    created = False
                    badfile = False
                    if not os.path.exists(fp):
                        createFile(fp)
                        created = True
                    if os.path.exists(fp):
                        if not created:
                            #we check if file was previously created above
                            #if so, we don't want to record a permission
                            #change event, since the undo will be file deletion
                            if not checkPerms(fp, [0, 0, 420], self.logger):
                                self.iditerator += 1
                                myid = iterate(self.iditerator, self.rulenumber)
                                if setPerms(fp, [0, 0, 420], self.logger, 
                                                    self.statechglogger, myid):
                                    self.detailedresults += "Successfully \
corrected permissions on file: " + fp + "\n"
                                else:
                                    self.detailedresults += "Was not able to \
successfully set permissions on file: " + fp + "\n"
                                    success = False
                                    
                        #read in file
                        contents = readFile(fp, self.logger)
                        tempstring = ""
                        for line in contents:
                            #search for any line beginning with tty
                            if re.search("^tty", line):
                                linesplit = line.split()
                                try:
                                    #replace any line beginning with tty's
                                    #value with insecure if secure
                                    if linesplit[4] == "secure":
                                        linesplit[4] == "insecure"
                                        badfile = True
                                        tempstring += " ".join(linesplit) + "\n"
                                    else:
                                        tempstring += line
                                except IndexError:
                                    debug = traceback.format_exc() + "\n"
                                    debug += "Index out of range on line: " + line + "\n"
                                    self.logger.log(LogPriority.DEBUG, debug)
                            else:
                                tempstring += line
                        
                        #check to see if badfile is true which is set when
                        #checking contents of the file, if badfile is false
                        #we found everything in the file we needed, so no need
                        #to change
                        if badfile:
                            if writeFile(tfp, tempstring, self.logger):
                                self.iditerator += 1
                                myid = iterate(self.iditerator, 
                                                               self.rulenumber)
                                #if the file wasn't created earlier, then we
                                #will record the change event as a file change
                                if not created:
                                    event = {"eventtype":"conf",
                                             "filepath":fp}
                                    self.statechglogger.recordchgevent(myid, 
                                                                         event)
                                    self.statechglogger.recordfilechange(fp, 
                                                                     tfp, myid)
                                #if file was created earlier, then we will 
                                #record the change event as a file creation
                                #so that undo event will be a file deletion
                                else:
                                    event = {"eventtype":"conf",
                                             "filepath":fp}
                                    self.statechglogger.recordchgevent(myid,
                                                                         event)
                                self.detailedresults += "corrected contents \
and wrote to file: " + fp + "\n"
                                os.rename(tfp, fp)
                                os.chown(fp, 0, 0)
                                os.chmod(fp, 420)
                                resetsecon(fp)
                            else:
                                self.detailedresults += "Unable to \
successfully write the file: " + fp + "\n"
                                success = False
                                
                if self.ph.manager == "yum":
                    tempstring = ""
                    fp = "/etc/sysconfig/init"
                    tfp = fp + ".tmp"
                    created = False
                    badfile = False
                    if not os.path.exists(fp):
                        createFile(fp)
                        created = True
                    if os.path.exists(fp):
                        if not created:
                            #we check if file was previously created above
                            #if so, we don't want to record a permission
                            #change event, since the undo will be file deletion
                            if not checkPerms(fp, [0, 0, 420], self.logger):
                                self.iditerator += 1
                                myid = iterate(self.iditerator, self.rulenumber)
                                if setPerms(fp, [0, 0, 420], self.logger,
                                                    self.statechglogger, myid):
                                    self.detailedresults += "Successfully \
corrected permissions on file: " + fp + "\n"
                                else:
                                    self.detailedresults += "Was not able to \
successfully set permissions on file: " + fp + "\n"
                                    success = False
                        contents = readFile(fp, self.logger)
                        if contents:
                            linefound = False
                            for line in contents:
                                if re.search("^SINGLE", line.strip()):
                                    if re.search("=", line):
                                        temp = line.split("=")
                                        try:
                                            if temp[1].strip() == "/sbin/sulogin":
                                                tempstring += line
                                                linefound = True
                                        except IndexError:
                                            self.compliant = False
                                            debug = traceback.format_exc() + "\n"
                                            debug += "Index out of range on line: " + line + "\n"
                                            self.logger.log(LogPriority.DEBUG, debug)
                                else:
                                    tempstring += line
                            if not linefound:
                                badfile = True
                                tempstring += "SINGLE=/sbin/sulogin\n"
                                
                        #check to see if badfile is true which is set when
                        #checking contents of the file, if badfile is false
                        #we found everything in the file we needed, so no need
                        #to change
                        if badfile:
                            if writeFile(tfp, tempstring, self.logger):
                                self.iditerator += 1
                                myid = iterate(self.iditerator, 
                                                               self.rulenumber)
                                #if the file wasn't created earlier, then we
                                #will record the change event as a file change
                                if not created:
                                    event = {"eventtype":"conf",
                                             "filepath":fp}
                                    self.statechglogger.recordchgevent(myid, 
                                                                         event)
                                    self.statechglogger.recordfilechange(fp, 
                                                                     tfp, myid)
                                #if file was created earlier, then we will 
                                #record the change event as a file creation
                                #so that undo event will be a file deletion
                                else:
                                    event = {"eventtype":"creation",
                                             "filepath":fp}
                                    self.statechglogger.recordchgevent(myid,
                                                                         event)
                                self.detailedresults += "corrected contents \
and wrote to file: " + fp + "\n"
                                os.rename(tfp, fp)
                                os.chown(fp, 0, 0)
                                os.chmod(fp, 420)
                                resetsecon(fp)
                            else:
                                self.detailedresults += "Unable to \
successfully write the file: " + fp + "\n"
                                success = False
                                
                                
#                 if self.ph.manager == "zypper":
#                     tempstring = ""
#                     fp = "/etc/inittab"
#                     tfp = fp + ".tmp"
#                     created = False
#                     badfile = False
#                     if not os.path.exists(fp):
#                         self.createFile(fp)
#                         created = True
#                     if os.path.exists(fp):
#                         if not created:
#                             #we check if file was previously created above
#                             #if so, we don't want to record a permission
#                             #change event, since the undo will be file deletion
#                             if not checkPerms(fp, [0, 0, 420], self.logger):
#                                 self.iditerator += 1
#                                 myid = iterate(self.iditerator, self.rulenumber)
#                                 if setPerms(fp, [0, 0, 420], self.logger, "", 
#                                                     self.statechglogger, myid):
#                                     self.detailedresults += "Successfully \
# corrected permissions on file: " + fp + "\n"
#                                 else:
#                                     self.detailedresults += "Was not able to \
# successfully set permissions on file: " + fp + "\n"
#                                     success = False
#                         contents = readFile(fp, self.logger)
#                         if contents:
#                             linefound = False
#                             for line in contents:
#                                 if re.search("^~~:S:wait:/sbin/sulogin", line.strip()):
#                                     tempstring += line
#                                     linefound = True
#                                 else:
#                                     tempstring += line
#                             if not linefound:
#                                 badfile = True
#                                 tempstring += "~~:S:wait:/sbin/sulogin\n"
#                         #check to see if badfile is true which is set when
#                         #checking contents of the file, if badfile is false
#                         #we found everything in the file we needed, so no need
#                         #to change
#                         if badfile:
#                             if writeFile(tfp, self.logger, tempstring):
#                                 self.iditerator += 1
#                                 myid = iterate(self.iditerator, 
#                                                                self.rulenumber)
#                                 #if the file wasn't created earlier, then we
#                                 #will record the change event as a file change
#                                 if not created:
#                                     event = {"eventtype":"conf",
#                                              "filepath":fp}
#                                     self.statechglogger.recordchgevent(myid, 
#                                                                          event)
#                                     self.statechglogger.recordfilechange(fp, 
#                                                                      tfp, myid)
#                                 #if file was created earlier, then we will 
#                                 #record the change event as a file creation
#                                 #so that undo event will be a file deletion
#                                 else:
#                                     event = {"eventtype":"creation",
#                                              "filepath":fp}
#                                     self.statechglogger.recordchgevent(myid,
#                                                                          event)
#                                 self.detailedresults += "corrected contents \
# and wrote to file: " + fp + "\n"
#                                 os.rename(tfp, fp)
#                                 os.chown(fp, 0, 0)
#                                 os.chmod(fp, 420)
#                                 resetsecon(fp)
#                             else:
#                                 self.detailedresults += "Unable to \
# successfully write the file: " + fp + "\n"
#                                 success = False
                                
                #solution for solaris systems
                if self.ph.manager == "solaris":
                    tempstring = ""
                    fp = "/etc/default/sulogin"
                    tfp = fp + ".tmp"
                    created = False
                    badfile = False
                    
                    if not os.path.exists(fp):
                        createFile(fp)
                        created = True
                    if os.path.exists(fp):
                        if not created:
                            #we check if file was previously created above
                            #if so, we don't want to record a permission
                            #change event, since the undo will be file deletion
                            if not checkPerms(fp, [0, 0, 420], self.logger):
                                self.iditerator += 1
                                myid = iterate(self.iditerator, self.rulenumber)
                                if setPerms(fp, [0, 0, 420], self.logger,
                                                    self.statechglogger, myid):
                                    self.detailedresults += "Successfully \
corrected permissions on file: " + fp + "\n"
                                else:
                                    self.detailedresults += "Was not able to \
successfully set permissions on file: " + fp + "\n"
                                    success = False
                        contents = readFile(fp, self.logger)
                        if contents:
                            linefound = False
                            for line in contents:
                                if re.search("^PASSREQ", line.strip()):
                                    if re.search("=", line):
                                        temp = line.split("=")
                                        try:
                                            if temp[1].strip() == "YES":
                                                tempstring += line
                                                linefound = True
                                        except IndexError:
                                            debug = traceback.format_exc() + "\n"
                                            debug += "Index out of range on line: " + line + "\n"
                                            self.logger.log(LogPriority.DEBUG, debug)
                                else:
                                    tempstring += line
                            if not linefound:
                                badfile = True
                                tempstring += "PASSREQ=YES\n"
                        #check to see if badfile is true which is set when
                        #checking contents of the file, if badfile is false
                        #we found everything in the file we needed, so no need
                        #to change
                        if badfile:
                            if writeFile(tfp, tempstring, self.logger):
                                self.iditerator += 1
                                myid = iterate(self.iditerator, 
                                                               self.rulenumber)
                                #if the file wasn't created earlier, then we
                                #will record the change event as a file change
                                if not created:
                                    event = {"eventtype":"conf",
                                             "filepath":fp}
                                    self.statechglogger.recordchgevent(myid, 
                                                                         event)
                                    self.statechglogger.recordfilechange(fp, 
                                                                     tfp, myid)
                                #if file was created earlier, then we will 
                                #record the change event as a file creation
                                #so that undo event will be a file deletion
                                else:
                                    event = {"eventtype":"creation",
                                             "filepath":fp}
                                    self.statechglogger.recordchgevent(myid,
                                                                         event)
                                self.detailedresults += "corrected contents \
and wrote to file: " + fp + "\n"
                                os.rename(tfp, fp)
                                os.chown(fp, 0, 0)
                                os.chmod(fp, 420)
                                resetsecon(fp)
                            else:
                                self.detailedresults += "Unable to \
successfully write the file: " + fp + "\n"
                                success = False
            self.rulesuccess = success
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