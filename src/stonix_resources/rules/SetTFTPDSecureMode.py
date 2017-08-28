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
Created on Apr 20, 2016

@author: dwalker
@change: 2016/06/06 dwalker updated applicability to not run on Mac until
    configuration on Mac OS X is fully researched.
'''

from __future__ import absolute_import
from ..stonixutilityfunctions import iterate, checkPerms, setPerms, resetsecon
from ..stonixutilityfunctions import readFile, writeFile, getUserGroupName
from ..rule import Rule
from ..logdispatcher import LogPriority
from ..pkghelper import Pkghelper
import traceback
import os
import stat
import re
import grp
import pwd


class SetTFTPDSecureMode(Rule):

###############################################################################
    def __init__(self, config, environ, logger, statechglogger):
        Rule.__init__(self, config, environ, logger,
                              statechglogger)
        self.logger = logger
        self.rootrequired = True
        self.rulenumber = 98
        self.rulename = 'SetTFTPDSecureMode'
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.sethelptext()
        datatype = 'bool'
        key = 'SETTFTPDSECUREMODE'
        instructions = "To disable this rule set the value of " + \
            "SETTFTPDSECUREMODE to False"
        default = True
        self.tftpdci = self.initCi(datatype, key, instructions, default)

        self.guidance = ["NSA 3.1.5.4"]
        self.iditerator = 0
        self.editor = ""
        self.applicable = {'type': 'white',
                           'family': ['linux', 'solaris', 'freebsd'],
                           'os': {'Mac OS X': ['10.10.0', 'r', '10.10.10']}}
        
    def report(self):
        try:
            self.detailedresults = ""
            compliant = True
            if self.environ.getostype() == "Mac OS X":
                compliant = self.reportMac()
            else:
                self.ph = Pkghelper(self.logger, self.environ)
                if self.ph.manager == "apt-get":
                    pkg = "tftpd-hpa"
                    if self.ph.check(pkg):
                        self.tftpFile = "/etc/default/tftpd-hpa"
                        if os.path.exists(self.tftpFile):
                            compliant = self.reportDebianSys()
                else:
                    pkg = "tftp-server"
                    if self.ph.check(pkg):
                        self.tftpFile = "/etc/xinetd.d/tftp"
                        if os.path.exists(self.tftpFile):
                            compliant = self.reportOtherSys()
            self.compliant = compliant
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

    def reportMac(self):
        compliant = True
        self.detailedresults = ""
        self.plistpath = "/System/Library/LaunchDaemons/tftp.plist"
        self.plistcontents = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
     <key>Disabled</key>
     <true/>
     <key>Label</key>
     <string>com.apple.tftpd</string>
     <key>ProgramArguments</key>
     <array>
           <string>/usr/libexec/tftpd</string>
           <string>-i</string>
           <string>-s</string>
           <string>/private/tftpboot</string>
     </array>
     <key>inetdCompatibility</key>
     <dict>
          <key>Wait</key>
          <true/>
     </dict>
     <key>InitGroups</key>
     <true/>
     <key>Sockets</key>
     <dict>
          <key>Listeners</key>
          <dict>
               <key>SockServiceName</key>
               <string>tftp</string>
               <key>SockType</key>
               <string>dgram</string>
          </dict>
     </dict>
</dict>
</plist>'''
        self.plistregex = "<\?xml\ version\=\"1\.0\"\ encoding\=\"UTF\-8\"\?>" + \
            "<\!DOCTYPE\ plist\ PUBLIC\ \"\-//Apple//DTD\ PLIST\ 1\.0//EN\"\ \"http\://www\.apple\.com/DTDs/PropertyList\-1\.0\.dtd\">" + \
            "<plist version\=\"1\.0\"><dict><key>Disabled</key><true/><key>Label</key><string>com\.apple\.tftpd</string>" + \
            "<key>ProgramArguments</key><array><string>/usr/libexec/tftpd</string><string>\-i</string>" + \
            "<string>\-s</string><string>/private/tftpboot</string></array><key>inetdCompatibility</key><dict>" + \
            "<key>Wait</key><true/></dict><key>InitGroups</key><true/><key>Sockets</key><dict>" + \
            "<key>Listeners</key><dict><key>SockServiceName</key><string>tftp</string><key>SockType</key>" + \
            "<string>dgram</string></dict></dict></dict></plist>"
        if os.path.exists(self.plistpath):
            statdata = os.stat(self.plistpath)
            mode = stat.S_IMODE(statdata.st_mode)
            ownergrp = getUserGroupName(self.plistpath)
            owner = ownergrp[0]
            group = ownergrp[1]
            if mode != 420:
                compliant = False
                self.detailedresults += "permissions on " + self.plistpath + \
                    "aren't 644\n"
                debug = "permissions on " + self.plistpath + " aren't 644\n"
                self.logger.log(LogPriority.DEBUG, debug)
            if owner != "root":
                compliant = False
                self.detailedresults += "Owner of " + self.plistpath + \
                    " isn't root\n"
                debug = "Owner of " + self.plistpath + \
                    " isn't root\n"
                self.logger.log(LogPriority.DEBUG, debug)
            if group != "wheel":
                compliant = False
                self.detailedresults += "Group of " + self.plistpath + \
                    " isn't wheel\n"
                debug = "Group of " + self.plistpath + \
                    " isn't wheel\n"
                self.logger.log(LogPriority.DEBUG, debug)
            contents = readFile(self.plistpath, self.logger)
            contentstring = ""
            for line in contents:
                contentstring += line.strip()
            if not re.search(self.plistregex, contentstring):
                compliant = False
                self.detailedresults += "plist file doesn't contian the " + \
                    "correct contents\n"
        return compliant

    def reportDebianSys(self):
        contents = readFile(self.tftpFile, self.logger)
        found1 = False
        found2 = False
        compliant = True
        compliant1 = True
        compliant2 = True
        for line in contents:
            if re.search("TFTP_OPTIONS", line):
                found1 = True
                if re.search("=", line):
                    tmp = line.strip()
                    tmp = tmp.split("=")
                    try:
                        #remove beginning and ending spaces of the part
                        #after = if necessary
                        opts = tmp[1].strip()
                        #opts = "\" sdfads \""
                        #replace actual quotes with nothing
                        opts = re.sub("\"", "", opts)
                        #opts = " sdfads "
                        #once again replace any whitespace with just one space
                        opts = re.sub("/s+", " ", opts.strip())
                        #split by single whitespace
                        opts = opts.split(" ")
                        if "--secure" not in opts:
                            compliant1 = False 
                    except IndexError:
                        self.detailedresults += "No value after = \n" + \
                            "Bad file format.\n" 
                        compliant1 = False
            elif re.search("TFTP_DIRECTORY", line):
                found2 = True
                if re.search("=", line):
                    tmp = line.strip()
                    tmp = tmp.split("=")
                    try:
                        opts = tmp[1].strip()
                        opts = re.sub("\"", "", opts)
                        if not re.search("^/var/lib/tftpboot$", opts):
                            compliant2 = False 
                    except IndexError:
                        self.detailedresults += "No value after = \n" + \
                            "Bad file format.\n" 
                        compliant2 = False
        if not compliant1:
            self.detailedresults += self.tftpFile + " doesn't contain " + \
                "the --secure option for the TFTP_OPTIONS key\n"
            compliant = False
        if not compliant2:
            self.detailedresults += self.tftpFile + " doesn't contain " + \
                "the desired directory for the TFTP_DIRECTORY key\n"
            compliant = False
        if not found1:
            self.detailedresults += self.tftpFile + " doesn't contain " + \
                "the TFTP_OPTIONS key at all\n"
            compliant = False
        if not found2:
            self.detailedresults += self.tftpFile + " doesn't contain " + \
                "the TFTP_DIRECTORY key at all\n"
            compliant = False
        return compliant

    def reportOtherSys(self):
        tftpoptions, contents2 = [], []
        contents = readFile(self.tftpFile, self.logger)
        found = False
        compliant = True
        i = 0
        if not checkPerms(self.tftpFile, [0, 0, 420], self.logger):
            self.detailedresults += "Permissions on tftp file are incorrect\n"
            compliant = False   
        try:
            for line in contents:
                if re.search("service tftp", line.strip()):
                    contents2 = contents[i+1:]
                else:
                    i += 1
        except IndexError:
            pass
        if contents2:
            if contents2[0].strip() == "{":
                del(contents2[0])
                if contents2:
                    i = 0
                    while i <= len(contents2) and contents2[i].strip() != "}" and contents2[i].strip() != "{":
                        tftpoptions.append(contents2[i])
                        i += 1
                    if tftpoptions:
                        for line in tftpoptions:
                            if re.search("server_args", line):
                                found = True
                                if re.search("=", line):
                                    line = line.split("=")
                                    val = re.sub("\s+", " ", line[1].strip())
                                    if not re.search("\-s", val) and not re.search("\-\-search", val):
                                        compliant = False
                                        self.detailedresults += "server_args line " + \
                                            "doesn't contain the -s option\n"
                                    elif not re.search("\s?-s /var/lib/tftpboot", val) and not re.search("\s?--search /var/lib/tftpboot", val):
                                        compliant = False
                                        self.detailedresults += "server_args line " + \
                                            "doesn't contain the correct contents\n"
                                else:
                                    self.detailedresults += "server_args line " + \
                                        "found but contains no = sign, bad format.\n"
                                    compliant = False
                    else:
                        compliant = False
                        self.detailedresults += "There are no tftp " + \
                            "options inside tftp file\n"
        else:
            compliant = False
            self.detailedresults += "tftp file doesn't contain the " + \
                "line service tftp\nBad Format\n"
        if not found:
            self.detailedresults += "server_args line not found.\n"
            compliant = False
        elif found and not compliant:
            compliant = False
            self.detailedresults += "server_args line found but " + \
                "either doesn't contain -s argument or has bad " + \
                "format.\n"
        return compliant

    def fix(self):
        try:
            success = True
            self.detailedresults = ""
            # clear out event history so only the latest fix is recorded
            self.iditerator = 0
            eventlist = self.statechglogger.findrulechanges(self.rulenumber)
            for event in eventlist:
                self.statechglogger.deleteentry(event)
            if not self.tftpdci.getcurrvalue():
                return
            if self.environ.getostype() == "Mac OS X":
                success = self.fixMac()
            elif self.ph.manager == "apt-get":
                if os.path.exists(self.tftpFile):
                    success = self.fixDebianSys()
            else:
                if os.path.exists(self.tftpFile):
                    success = self.fixOtherSys()
            self.rulesuccess = success
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess,
                                                          self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.rulesuccess
    
    def fixOtherSys(self):
        success = True
        if not checkPerms(self.tftpFile, [0, 0, 420], self.logger):
            self.iditerator += 1
            myid = iterate(self.iditerator, self.rulenumber)
            if not setPerms(self.tftpFile, [0, 0, 420], self.logger,
                     self.statechglogger, myid):
                self.detailedresults += "Unable to set " + \
                    "permissions on " +  self.tftpFile + "\n"
                success = False
        try:
            contents = readFile(self.tftpFile, self.logger)
            found = False
            tempstring = ""
            i = 0
            tftplinefound = False
            for line in contents:
                if re.search("service tftp", line.strip()):
                    tempstring += line
                    tftplinefound = True
                    contents2 = contents[i+1:]
                    break
                else:
                    tempstring += line
                    i += 1
            if not tftplinefound:
                self.detailedresults += "tftp file doesn't contain " + \
                    "\"service tftp\" line.  Stonix will not attempt to " + \
                    "fix this.  This will require a manual fix\n"
                return False
            if contents2:
                if contents2[0].strip() == "{":
                    tempstring += contents2[0]
                    del(contents2[0])
                    if contents2:
                        for line in contents2:
                            if re.search("server_args", line):
                                found = True
                                if re.search("=", line):
                                    tmp = line.split("=")
                                    val = re.sub("/s+", " ", tmp[1].strip())
                                    if re.search("\-s", val) or re.search("\-\-secure", val):
                                        if not re.search("\-s /var/lib/tftpboot", val) and not re.search("\-\-secure /var/lib/tftpboot", val):
                                            val = re.sub("-s\s{0,1}/{0,1}.*\s{0,1}", "-s /var/lib/tftpboot", tmp[1])
                                            tempstring += "\tserver_args \t\t= " + val + "\n"
                                        else:
                                            tempstring += line
                                    else:
                                        tempstring += line + " -s /var/lib/tftpboot\n" 
                                else:
                                    tempstring += "\tserver_args\t\t= -s /var/lib/tftpboot\n"
                            elif re.search("}", line.strip()):
                                if not found:
                                    tempstring += "\tserver_args\t\t= -s /var/lib/tftpboot\n"
                                    tempstring += "}"
                                    break
                                else:
                                    tempstring = ""
                                    break
                            else:
                                tempstring += line
        except IndexError:
            self.detailedresults += "The tftp file is in bad format\n " + \
                "Will not attempt to correct this file.  Exiting\n"
            return False
        if not tempstring:
            return True
        tmpfile = self.tftpFile + ".tmp"
        if writeFile(tmpfile, tempstring, self.logger):
            self.iditerator += 1
            myid = iterate(self.iditerator, self.rulenumber)
            event = {"eventtype": "conf",
                     "filepath": self.tftpFile}
            self.statechglogger.recordchgevent(myid, event)
            self.statechglogger.recordfilechange(self.tftpFile,
                                                 tmpfile, myid)
            os.rename(tmpfile, self.tftpFile)
            os.chown(self.tftpFile, 0, 0)
            os.chmod(self.tftpFile, 420)
            resetsecon(self.tftpFile)
        else:
            self.detailedresults += "Unable to write new contents " + \
                "to " + self.tftpFile + " file.\n"
            success = False
        return success

    def fixDebianSys(self):
        success = True
        if not checkPerms(self.tftpFile, [0, 0, 420], self.logger):
            self.iditerator += 1
            myid = iterate(self.iditerator, self.rulenumber)
            if not setPerms(self.tftpFile, [0, 0, 420], self.logger,
                     self.statechglogger, myid):
                self.detailedresults += "Unable to set " + \
                    "permissions on " +  self.tftpFile + "\n"
                success = False
        contents = readFile(self.tftpFile, self.logger)
        found1 = False
        found2 = False
        tempstring = ""
        for line in contents:
            if re.search("TFTP_OPTIONS", line):
                if found1:
                    continue
                if re.search("=", line):
                    tmp = line.strip()
                    tmp = tmp.split("=")
                    try:
                        #remove beginning and ending spaces of the part
                        #after = if necessary
                        opts = tmp[1].strip()
                        #opts = "\" sdfads \""
                        #replace actual quotes with nothing
                        opts = re.sub("\"", "", opts)
                        #opts = " sdfads "
                        #once again replace any whitespace with just one space
                        opts = re.sub("/s+", " ", opts.strip())
                        #split by single whitespace
                        opts = opts.split(" ")
                        if "--secure" not in opts:
                            continue
                        else:
                            tempstring += line
                            found1 = True
                    except IndexError:
                        continue
                else:
                    continue
            elif re.search("TFTP_DIRECTORY", line):
                if found2:
                    continue
                
                if re.search("=", line):
                    tmp = line.strip()
                    tmp = tmp.split("=")
                    try:
                        opts = tmp[1].strip()
                        opts = re.sub("\"", "", opts)
                        if not re.search("^/var/lib/tftpboot$", opts):
                            continue
                        else:
                            tempstring += line
                            found2 = True
                    except IndexError:
                        continue
            else:
                tempstring += line
        if not found1:
            tempstring += "TFTP_OPTIONS=\"--secure\"\n"
        if not found2:
            tempstring += "TFTP_DIRECTORY=\"/var/lib/tftpboot\"\n"
        tmpfile = self.tftpFile + ".tmp"
        if writeFile(tmpfile, tempstring, self.logger):
            self.iditerator += 1
            myid = iterate(self.iditerator, self.rulenumber)
            event = {"eventtype": "conf",
                     "filepath": self.tftpFile}
            self.statechglogger.recordchgevent(myid, event)
            self.statechglogger.recordfilechange(self.tftpFile,
                                                 tmpfile, myid)
            os.rename(tmpfile, self.tftpFile)
            os.chown(self.tftpFile, 0, 0)
            os.chmod(self.tftpFile, 420)
            resetsecon(self.tftpFile)
        else:
            self.detailedresults += "Unable to write new contents " + \
                "to " + self.tftpFile + " file.\n"
            success = False
        return success
    
    def fixMac(self):
        success = True
        debug = ""
        if not os.path.exists(self.plistpath):
            debug = self.plistpath + " doesn't exist. " + \
                "Stonix will not attempt to create this file\n"
            self.logger.log(LogPriority.DEBUG, debug)
            return success
        uid, gid = "", ""
        statdata = os.stat(self.plistpath)
        mode = stat.S_IMODE(statdata.st_mode)
        ownergrp = getUserGroupName(self.plistpath)
        owner = ownergrp[0]
        group = ownergrp[1]
        if grp.getgrnam("wheel")[2] != "":
            gid = grp.getgrnam("wheel")[2]
        if pwd.getpwnam("root")[2] != "":
            uid = pwd.getpwnam("root")[2]
        if mode != 420 or owner != "root" or group != "wheel":
            origuid = statdata.st_uid
            origgid = statdata.st_gid
            if gid and uid:
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                event = {"eventtype": "perm",
                         "startstate": [origuid, origgid, mode],
                         "endstated": [uid, gid, 420],
                         "filepath": self.plistpath}
                self.statechglogger.recordchgevent(myid, event)
        contents = readFile(self.plistpath, self.logger)
        contentstring = ""
        for line in contents:
            contentstring += line.strip()
        if not re.search(self.plistregex, contentstring):
            tmpfile = self.plistpath + ".tmp"
            if not writeFile(tmpfile, self.plistcontents, self.logger):
                debug = "Unable to write correct contents to " + \
                    self.plistpath + "\n"
                success = False
            else:
                self.iditerator +=1 
                myid = iterate(self.iditerator, self.rulenumber)
                event = {"eventtype": "conf",
                         "filepath": self.plistpath}
                self.statechglogger.recordchgevent(myid, event)
                self.statechglogger.recordfilechange(self.plistpath, tmpfile, myid)
                os.rename(tmpfile, self.plistpath)
                if uid and gid:
                    os.chown(self.plistpath, uid, gid)
                os.chmod(self.plistpath, 420)
        return success