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
Created on Jun 10, 2016

@author: Breen Malmberg
@change: Breen Malmberg - 8/19/2016 - re-factored all methods to account for
new configuration file locations as well as multiple simultaneous
configuration file locations
@change: 2016/09/08 eball Moved self.localize() out of init. init runs on all
    platforms, not just applicable platforms, and this was causing errors on
    Macs
'''

from __future__ import absolute_import
import os
import re
import traceback

from ..rule import Rule
from ..localize import DHCPDict, DHCPSup
from ..logdispatcher import LogPriority
from ..stonixutilityfunctions import iterate


class MinimizeAcceptedDHCPOptions(Rule):
    '''
    By default, the DHCP client program, dhclient, requests and applies ten configuration options (in addition to the IP 
address) from the DHCP server. subnet-mask, broadcast-address, time-offset, routers, domain-name, domain-name-servers, 
host-name, nis-domain, nis-servers, and ntp-servers. Many of the options requested and applied by dhclient may be the 
same for every system on a network. It is recommended that almost all configuration options be assigned statically, and 
only options which must vary on a host-by-host basis be assigned via DHCP. This limits the damage which can be done by a
 rogue DHCP server
    '''

    def __init__(self, config, environ, logger, statechglogger):
        '''
        Constructor
        '''

        Rule.__init__(self, config, environ, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 95
        self.rulename = 'MinimizeAcceptedDHCPOptions'
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.sethelptext()
        self.rootrequired = True
        self.guidance = ['RHEL 7 STIG 3.8.4.1']
        self.applicable = {'type': 'white',
                           'family': ['linux']}
        # init CIs
        datatype = 'bool'
        key = 'MINIMIZEACCEPTEDDHCPOPTIONS'
        instructions = "To prevent the MinimizeAcceptedDHCPOptions rule from being run, set the value of MinimizeAcceptedDHCPOptions to False."
        default = True
        self.ci = self.initCi(datatype, key, instructions, default)

    def localize(self):
        '''
        set variables based on operating environment

        @return: void
        @author: Breen Malmberg
        '''

        self.filepaths = []

        try:

            if self.environ.getosfamily() != "darwin":

                # these are known canonical locations for the dhclient.conf file
                filepaths = ['/etc/dhcp/dhclient.conf', '/etc/dhclient.conf',
                             '/var/lib/NetworkManager/dhclient.conf']
    
                for fp in filepaths:
                    if os.path.exists(fp):
                        self.filepaths.append(fp)
    
                basedir = '/var/lib/NetworkManager/'
                if os.path.exists(basedir):
                    fileslist = os.listdir(basedir)
                    for f in fileslist:
                        if os.path.isfile(basedir + f):
                            if re.search('dhclient\-.*\.conf', f, re.IGNORECASE):
                                self.filepaths.append(basedir + f)
    
                if not self.filepaths:
                    self.logger.log(LogPriority.DEBUG,
                                    "Unable to locate required configuration file: dhclient.conf")

        except Exception:
            raise

    def getFileContents(self, filepath):
        '''
        get a file's contents and return them in list format

        @return: contents
        @rtype: list
        @author: Breen Malmberg
        '''

        contents = []

        try:

            if not isinstance(filepath, basestring):
                self.logger.log(LogPriority.DEBUG,
                                "Specified filepath argument needs to be of type: string!")
                return contents

            if not os.path.exists(filepath):
                self.logger.log(LogPriority.DEBUG,
                                "Specified filepath does not exist!")
                sfilepath = filepath.split('/')
                if len(sfilepath) > 1:
                    del sfilepath[-1]
                    subdir = '/'.join(sfilepath)
                    if not os.path.exists(subdir):
                        self.logger.log(LogPriority.DEBUG,
                                        "Sub directory of specified filepath does not exist!")
                return contents

            f = open(filepath, 'r')
            contents = f.readlines()
            f.close()

        except Exception:
            raise
        return contents

    def checkFile(self, filepath, checkfor):
        '''
        check a file's contents for a specific string or list of strings

        @param filepath: string full path to the file to check
        @param checkfor: dict dictionary of key:value pairs to check for in file contents
        @return: retval
        @rtype: bool
        @author: Breen Malmberg
        '''

        retval = True
        founddict = {}
        founddict2 = {}

        try:

            contents = self.getFileContents(filepath)

            if isinstance(checkfor, dict):

                for item in checkfor:
                    founddict[item] = False

                for item in checkfor:
                    for line in contents:
                        if re.search("^" + item + "\s*" + checkfor[item], line):
                            founddict[item] = True
                for item in founddict:
                    if not founddict[item]:
                        self.detailedresults += "Configuration option " + \
                            item + " is not configured correctly.\n"
                        retval = False

            elif isinstance(checkfor, list):

                for item in checkfor:
                    founddict2[item] = False

                for item in checkfor:
                    for line in contents:
                        if re.search("^" + item, line):
                            founddict2[item] = True

                for item in founddict2:
                    if not founddict2[item]:
                        self.detailedresults += "Required configuration option: " + \
                            item + "\nwas not found.\n"
                        retval = False

            else:
                self.logger.log(LogPriority.DEBUG,
                                "Argument checkfor needs to be of type: dict, or list")

        except Exception:
            raise
        return retval

    def report(self):
        '''
        verify whether the configuration for dhclient.conf is correct

        @return: self.compliant
        @rtype: bool
        @author: Breen Malmberg
        '''

        # UPDATE THIS SECTION IF YOU CHANGE THE CONSTANTS BEING USED IN THE RULE
        constlist = [DHCPDict, DHCPSup]
        if not self.checkConsts(constlist):
            self.compliant = False
            self.detailedresults = "\nPlease ensure that the constants: DHCPDict, DHCPSup, in localize.py, are defined and are not None. This rule will not function without them."
            self.formatDetailedResults("report", self.compliant, self.detailedresults)
            return self.compliant

        self.localize()

        # defaults
        self.compliant = True
        self.checkdict = {}
        self.checklist = []
        self.detailedresults = ""

        try:

            # build the check dictionary and list
            for item in DHCPDict:
                if DHCPDict[item] == "supersede":
                    self.checkdict["supersede " + item] = DHCPSup[item]

                if DHCPDict[item] == "request":
                    self.checklist.append("request " + item)
                    self.checklist.append("require " + item)

            for fp in self.filepaths:
                if not self.checkFile(fp, self.checkdict):
                    self.compliant = False

            for fp in self.filepaths:
                if not self.checkFile(fp, self.checklist):
                    self.compliant = False

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.compliant = False
            self.detailedresults = traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

    def fix(self):
        '''
        ensure that the file /etc/dhcp/dhclient.conf has the correct
        configuration options and values defined in it

        @return: self.rulesuccess
        @rtype: bool
        @author: Breen Malmberg
        '''

        # UPDATE THIS SECTION IF YOU CHANGE THE CONSTANTS BEING USED IN THE RULE
        constlist = [DHCPDict, DHCPSup]
        if not self.checkConsts(constlist):
            success = False
            self.formatDetailedResults("fix", success, self.detailedresults)
            return success

        # defaults
        self.detailedresults = ""
        contents = []
        self.iditerator = 0
        self.rulesuccess = True
        self.subdirperms = 0755
        self.fileperms = 0644
        self.fileowner = 0
        self.filegroup = 0

        try:

            if self.ci.getcurrvalue():

                # build the contents to write to file
                contents.append("## THE FOLLOWING ADDED BY STONIX\n\n")
                for item in DHCPDict:
                    if DHCPDict[item] == "supersede":
                        contents.append("supersede " + item + " " +
                                        str(DHCPSup[item]) + ";\n")
                    if DHCPDict[item] == "request":
                        contents.append("request " + item + ";\n")
                        contents.append("require " + item + ";\n")

                for fp in self.filepaths:
                    tmpfp = fp + '.stonixtmp'
                    # open the filepath and write the contents
                    tf = open(tmpfp, "w")
                    tf.writelines(contents)
                    tf.close()

                    # record the change, for undo
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    event = {'eventtype': 'conf',
                             'filepath': fp}
                    self.statechglogger.recordchgevent(myid, event)
                    self.statechglogger.recordfilechange(tmpfp, fp, myid)

                    # move the temporary file/changes to the actual path
                    # ensure correct permissions/ownership after changes are made
                    os.rename(tmpfp, fp)
                    os.chmod(fp, self.fileperms)
                    os.chown(fp, self.fileowner, self.filegroup)

            else:
                self.detailedresults += "The CI was not enabled for this rule. Nothing will be fixed, until the CI is enabled and then fix is run again."
                self.logger.log(LogPriority.DEBUG,
                                "The CI wasn't enabled. Nothing from fix() was run.")

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults = traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.rulesuccess
