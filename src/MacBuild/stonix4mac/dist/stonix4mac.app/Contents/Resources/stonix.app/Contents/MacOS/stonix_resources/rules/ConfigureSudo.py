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
Created on Mar 7, 2013

@author: dwalker
@change: 02/14/2014 ekkehard Implemented self.detailedresults flow
@change: 02/14/2014 ekkehard Implemented isapplicable
@change: 04/18/2014 dkennel Updated to use new style CI
@change: 2015/04/14 dkennel upddated to use new isApplicable
'''
from __future__ import absolute_import
from ..stonixutilityfunctions import setPerms, checkPerms, readFile
from ..stonixutilityfunctions import writeFile, resetsecon
from ..rule import Rule
from ..logdispatcher import LogPriority
from ..pkghelper import Pkghelper
import traceback
import os
import re


class ConfigureSudo(Rule):

    def __init__(self, config, environ, logger, statechglogger):
        Rule.__init__(self, config, environ, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 56
        self.rulename = "ConfigureSudo"
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.helptext = "Ensure that the group entered in the text field " + \
        "exists, and that the usernames of all administrators who should " + \
        "be allowed to execute commands as root are members of that " + \
        "group.  This rule will not be applicable to Solaris.  ***Please " + \
        "be aware that the default group for this rule if nothing is " + \
        "entered, is wheel.  If you would like to change the group, enter " + \
        "the desired group in the text field and hit save before running"

        self.guidance = ["NSA 2.3.1.3"]
        self.applicable = {'type': 'white',
                           'family': ['linux', 'solaris', 'freebsd'],
                           'os': {'Mac OS X': ['10.9', 'r', '10.11.10']}}

        #configuration item instantiation
        datatype = 'string'
        key = 'GROUPNAME'
        instructions = "The group listed is the group that will be placed " + \
        "into the sudoers file with permissions to run all commands."
        default = "wheel"
        self.ci = self.initCi(datatype, key, instructions, default)

        datatype2 = 'bool'
        key2 = 'CONFIGURESUDO'
        instructions2 = '''To disable this rule set the value of \
CONFIGURESUDO to False.'''
        default2 = True
        self.ci2 = self.initCi(datatype2, key2, instructions2, default2)

        self.wrongconfig = False

    def report(self):
        '''
        ConfigureScreenLocking.report() method to report whether system is
        configured with a sudoers group.
        @author: dwalker
        @param self - essential if you override this definition
        @return: bool - True if system is compliant, False if it isn't
        '''
        try:
            self.present = False
            compliant = True
            self.detailedresults = ""
            if self.environ.getosfamily() == "linux":
                self.ph = Pkghelper(self.logger, self.environ)
                self.path = "/etc/sudoers"
            elif self.environ.getostype() == "Mac OS X":
                self.path = "/private/etc/sudoers"
            elif self.environ.getosfamily() == "freebsd":
                self.ph = Pkghelper(self.logger, self.environ)
                self.path = "/usr/local/etc/sudoers"
            groupname = "%" + self.ci.getcurrvalue()
            if os.path.exists(self.path):
                contents = readFile(self.path, self.logger)
                
                #make sure sudoers file isn't blank
                if not contents:
                    info = "You have some serious issues, /etc/passwd " + \
                    "is blank"
                    self.detailedresults = info
                    self.logger.log(LogPriority.INFO, info)
                    compliant = False
                else:
                    for line in contents:
                        
                        #look for the specified group name in the sudoers file
                        if re.search("^" + groupname, line.strip()):
                            self.present = True
                            line = line.split()
                            try:
                                #different systems have different file formats
                                if self.environ.getostype() == "Mac OS X":
                                    if line[1] != "ALL=(ALL)" or line[2] \
                                                                       !="ALL":
                                        self.wrongconfig = True
                                elif self.ph.manager == "apt-get":
                                    if line[1] != "ALL=(ALL:ALL)" or line[2] \
                                                                       !="ALL":
                                        self.wrongconfig = True
                                else:
                                    if line[1] != "ALL=(ALL)" or line[2] \
                                                                       !="ALL":
                                        self.wrongconfig = True
                            except IndexError:
                                compliant = False
                                debug = traceback.format_exc() + "\n"
                                debug += "Index out of range on line: " + line + "\n"
                                self.logger.log(LogPriority.DEBUG, debug)
                                break
                    #make sure the sudoers file has correct permissions
                    if not checkPerms(self.path, [0, 0, 288], self.logger):
                        self.compliant = False
            if not self.present or self.wrongconfig:
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
        Fix method that writes specified or default sudo group to sudoers file
        if not present from the report method
        @author: dwalker
        @param self - essential if you override this definition
        @return: bool - True if fix is successful, False if it isn't
        '''
        try:
            self.detailedresults = ""
            if not self.ci2.getcurrvalue():
                return
            
            #clear out event history so only the latest fix is recorded
            self.iditerator = 0
            eventlist = self.statechglogger.findrulechanges(self.rulenumber)
            for event in eventlist:
                self.statechglogger.deleteentry(event)

            #we don't record a change event for permissions
            if not checkPerms(self.path, [0, 0, 288], self.logger):
                if not setPerms(self.path, [0, 0, 288], self.logger):
                    self.rulesuccess = False
            
            #get the string value of group name entered by user; default:wheel
            sudogroup = "%" + self.ci.getcurrvalue()
            tempstring = ""
            tmpfile = self.path + ".tmp"
            contents = readFile(self.path, self.logger)
            
            #make sure sudoers file isn't blank
            if contents:
                
                if self.environ.getostype() == "Mac OS X":
                    add = sudogroup + "     ALL=(ALL)         ALL\n"
                #apt-get systems have a different format
                elif self.ph.manager == "apt-get":
                    add = sudogroup + "     ALL=(ALL:ALL)     ALL\n"
                else:
                    add = sudogroup + "     ALL=(ALL)         ALL\n"
                
                #the group wasn't present at all
                if not self.present:
                    for line in contents:
                        tempstring = tempstring + line
                        
                #group was found but doesn't have proper contents
                elif self.wrongconfig:
                    for line in contents:
                        #we will exclude the line
                        if re.search("^" + sudogroup, line.strip()):
                            continue
                        else:
                            tempstring += line
                            
                #write new file and record event
                if tempstring:
                    tempstring += add
                    if not writeFile(tmpfile, tempstring, self.logger):
                        self.rulesuccess = False
                    else:
                        myid = "0056001"
                        event = {"eventtype": "conf",
                                 "filepath": self.path}
                        self.statechglogger.recordchgevent(myid, event)
                        self.statechglogger.recordfilechange(self.path, 
                                                                 tmpfile, myid)
                        os.rename(tmpfile, self.path)
                        setPerms(self.path, [0, 0, 288], self.logger)
                        resetsecon(self.path)
            else:
                self.detailedresults += "Sudoers file is blank.  Can't do " + \
                "anything.\n"
                self.rulesuccess = False
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