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
Created on May 3, 2011
This class checks the local accounts database for duplicate IDs. All accounts
on a system must have unique UIDs.
@author: dkennel
@change: 02/12/2014 ekkehard Implemented self.detailedresults flow
@change: 02/12/2014 ekkehard Implemented isapplicable
@change: 08/05/2014 ekkehard added duplicate uid & gid check for OS X
@change: 2015/04/14 dkennel updated to use new style isApplicable
@change: 2015/10/07 eball Help text cleanup
@change: 2015/10/28 ekkehard fix name and file name
@change: 2016/04/26 rsn add group checks per RHEL 7 STIG
@change: 2017/07/07 ekkehard - make eligible for macOS High Sierra 10.13
@change: 2017/08/28 ekkehard - Added self.sethelptext()
@change: 2017/11/13 ekkehard - make eligible for OS X El Capitan 10.11+
@change: 2018/06/08 ekkehard - make eligible for macOS Mojave 10.14
@change: 2019/03/12 ekkehard - make eligible for macOS Sierra 10.12+
'''
from __future__ import absolute_import
import os
import re
import traceback

# The period was making python complain. Adding the correct paths to PyDev
# made this the working scenario.
from ..rule import Rule
from ..logdispatcher import LogPriority
from ..CommandHelper import CommandHelper


class CheckDupIDs(Rule):
    '''This class checks the local accounts database for duplicate IDs. All
    accounts on a system must have unique UIDs. This class inherits the base
    Rule class, which in turn inherits observable.
    
    @note: Per RedHat STIG - CCE-RHEL7-CCE-TBD 2.4.1.2.3, check group references.
    
       All GIDs referenced in /etc/passwd must be defined in /etc/group
    
       Add a group to the system for each GID referenced without a
       corresponding group. Inconsistency in GIDs between /etc/passwd and
       /etc/group could lead to a user having unintended rights.
    
       Watch for LDAP issues (e.g. user default group changed to a group
       coming from LDAP).
    
       For Mac, also check that all the user's primary group ID's are in the
       local directory.


    '''

    def __init__(self, config, environ, logger, statechglogger):
        '''
        Constructor
        '''
        Rule.__init__(self, config, environ, logger, statechglogger)
        self.config = config
        self.environ = environ
        self.logger = logger
        self.commandhelper = CommandHelper(self.logger)
        self.statechglogger = statechglogger
        self.rulenumber = 58
        self.rulename = 'CheckDupIDs'
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.rootrequired = True
        self.guidance = ['CCE-RHEL7-CCE-TBD 2.4.1.2.3']
        self.sethelptext()
        self.applicable = {'type': 'white',
                           'family': ['linux', 'solaris', 'freebsd'],
                           'os': {'Mac OS X': ['10.12', 'r', '10.14.10']}}
        self.issuelist = []
        self.auditonly = True

    def report(self):
        '''CheckDuplicateIds.report(): produce a report on whether or not local
        accounts databases have duplicate UIDs present.

        :Authors:
            Dave Kennel

        '''
        try:
            self.detailedresults = ""
            self.issuelist = []
            if self.environ.getosfamily() == 'darwin':
                self.compliant = self.osxcheck()
            else:
                self.compliant = self.nixcheck()
            if self.compliant:
                self.detailedresults = "No duplicate IDs detected."
                self.currstate = 'configured'
            else:
                self.detailedresults = "One or more Duplicate IDs was " + \
                    "detected on this system. For accountability purposes " + \
                    "all accounts are required to have unique UID values. " + \
                    str(self.issuelist)
        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception, err:
            self.rulesuccess = False
            self.detailedresults = self.detailedresults + " " + str(err) + \
                " - " + str(traceback.format_exc())
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

    def osxcheck(self):
        '''This version of the check should work for all OS X systems.
        @author: ekkehard


        '''
        try:
            result = False
            nixcheckresult = self.nixcheck()
            oscheckresult = True
            issue = ""
# Check for duplicate users
            cmd = ["/usr/bin/dscl", ".", "list", "/users", "uid"]
            self.commandhelper.executeCommand(cmd)
            output = self.commandhelper.getOutput()
            userlist = []
            uidlist = []
            for line in output:
                linelist = line.split()
                user = linelist[0]
                uid = linelist[1]
                if user not in userlist:
                    userlist.append(user)
                else:
                    issue = "Duplicate User: '" + user + "' (UID = '" + uid + "')"
                    self.issuelist.append(issue)
                    oscheckresult = False
                if uid not in uidlist:
                    uidlist.append(uid)
                else:
                    issue = "Duplicate UID: '" + uid + "' (User = '" + user + "')"
                    self.issuelist.append(issue)
                    oscheckresult = False
# Check for duplicate groups
            cmd = ["/usr/bin/dscl", ".", "list", "/groups", "gid"]
            self.commandhelper.executeCommand(cmd)
            output = self.commandhelper.getOutput()
            grouplist = []
            gidlist = []
            for line in output:
                linelist = line.split()
                group = linelist[0]
                gid = linelist[1]
                if group not in grouplist:
                    grouplist.append(group)
                else:
                    issue = "Duplicate Group: '" + group + "' (GID = '" + gid + "')"
                    self.issuelist.append(issue)
                    oscheckresult = False
                if gid not in gidlist:
                    gidlist.append(gid)
                else:
                    issue = "Duplicate GID: '" + gid + "' (Group = '" + group + "')"
                    self.issuelist.append(issue)
                    oscheckresult = False

            if (nixcheckresult & oscheckresult):
                result = True
            else:
                result = False
            return result

        except (KeyboardInterrupt, SystemExit):
# User initiated exit
            raise
        except Exception, err:
            self.detailedresults = 'CheckDuplicateIds.osxcheck: '
            self.detailedresults = self.detailedresults + traceback.format_exc()
            self.rulesuccess = False
            self.logger.log(LogPriority.ERROR,
                            ['CheckDuplicateIds.osxcheck',
                             self.detailedresults])

    def nixcheck(self):
        '''This version of the check should work for all u systems. This
        is borrowed from the STOR code so the check methodology is well tested.
        
        @author: D. Kennel


        '''
        try:
            retval = True
            filelist = ['/etc/passwd', '/etc/group']
            for adb in filelist:
                if os.path.exists(adb):
                    self.logger.log(LogPriority.DEBUG,
                                    ['CheckDuplicateIds.nixcheck',
                                     "Checking : " + adb])
                    namelist = []
                    idlist = []
                    fdata = open(adb, 'r')
                    for line in fdata:
                        line = line.split(':')
                        try:
                            if len(line) > 2:
                                self.logger.log(LogPriority.DEBUG,
                                                ['CheckDuplicateIds.nixcheck',
                                                 "Checking line: " + str(line)])
                                name = line[0]
                                uid = line[2]
                                self.logger.log(LogPriority.DEBUG,
                                                "Checking account: " + name + ' ' + uid)
                                if name not in namelist:
                                    namelist.append(name)
                                else:
                                    issue = "Duplicate Name: NAME('" + name + "'; UID('" + uid + "')"
                                    self.issuelist.append(issue)
                                    retval = False
                                if uid not in idlist:
                                    idlist.append(uid)
                                else:
                                    issue = "Duplicate UID: NAME('" + name + "'; UID('" + uid + "')"
                                    self.issuelist.append(issue)
                        except(IndexError):
                            # Some systems have malformed lines in the
                            # accounts db due to poor administration
                            # practices. Go to the next record.
                            continue
                    self.logger.log(LogPriority.DEBUG,
                                    "NAMELIST: " + str(namelist))
                    self.logger.log(LogPriority.DEBUG,
                                    "IDLIST: " + str(idlist))
                    fdata.close()
            return retval

        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception:
            self.detailedresults = self.detailedresults + \
                traceback.format_exc()
            self.rulesuccess = False
            self.logger.log(LogPriority.ERROR, self.detailedresults)
            return False

    def getcolumn(self, file_to_read="", column=0, separator=":"):
        '''Get the data out of <file_to_read> column <column> using <separator>
        
        Intended for use with the /etc/group and /etc/password files for getting
        and comparing group information.
        
        @author: Roy Nielsen

        :param file_to_read:  (Default value = "")
        :param column:  (Default value = 0)
        :param separator:  (Default value = ":")

        '''
        if file_to_read and isinstance(column, int) and separator:
            reading = open(file_to_read, "r")

            for line in reading.readlines():
                try:
                    column_data = line.split(separator)[column]
                except IndexError:
                    continue
            return column_data

    def checkgrouprefs(self):
        '''Per RedHat STIG - CCE-RHEL7-CCE-TBD 2.4.1.2.3, check group references.
        
        All GIDs referenced in /etc/passwd must be defined in /etc/group
        
        Add a group to the system for each GID referenced without a
        corresponding group. Inconsistency in GIDs between /etc/passwd and
        /etc/group could lead to a user having unintended rights.
        
        Watch for LDAP issues (e.g. user default group changed to a group
        coming from LDAP).
        
        @author: Roy Nielsen


        '''
        group_groups = self.getcolumn("/etc/group", 2)
        pwd_groups = self.getcolumn("/etc/passwd", 3)

        for group in pwd_groups:
            if not group in group_groups:
                message = "Group: " + str(group) + " is not in the passwd file."
                self.logger.log(LogPriority.INFO, message)
                self.issuelist.append(message)

    def checkmacgrouprefs(self):
        '''Per RedHat STIG - CCE-RHEL7-CCE-TBD 2.4.1.2.3, check group references.
        
           All GIDs referenced in /etc/passwd must be defined in /etc/group
        
           Add a group to the system for each GID referenced without a
           corresponding group. Inconsistency in GIDs between /etc/passwd and
           /etc/group could lead to a user having unintended rights.
        
           Watch for LDAP issues (e.g. user default group changed to a group
           coming from LDAP).
        
        For Mac, check that al the user's primary group ID's are in the local
        directory.
        
        @author: Roy Nielsen


        '''
        self.dscl = "/usr/bin/dscl"
        user_groups = []
        dscl_users = [self.dscl, ".", "list", "/users"]
        self.commandhelper.executeCommand(dscl_users)
        output = self.commandhelper.getOutput()
        dscl_users = output

        system_users = ["avahi", "daemon", "nobody", "root" ]

        for user in dscl_users:
            if re.match("^_", user) or user in system_users:
                continue

            dscl_user_group = [self.dscl, ".", "read", "/Users/" + str(user), "gid"]
            self.commandhelper.executeCommand(dscl_user_group)
            output = self.commandhelper.getOutput()
            self.logger.log(LogPriority.INFO, "output: " + str(output))
            try:
                mygroup = output[0].split()[1]
                user_groups.append(mygroup)
            except KeyError, IndexError:
                pass

        dscl_groups = [self.dscl, ".", "list", "/Groups"]
        self.commandhelper.executeCommand(dscl_groups)
        output = self.commandhelper.getOutput()
        group_groups = output

        for group in user_groups:
            if not group in group_groups:
                message = "Group: " + str(group) + " is not in the passwd file."
                self.logger.log(LogPriority.INFO, message)
                self.issuelist.append(message)
