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
Created on Apr 20, 2016

@author: Derek Walker
@change: 2016/06/06 Derek Walker updated applicability to not run on Mac until
    configuration on Mac OS X is fully researched.
@change: 2017/11/13 ekkehard - make eligible for OS X El Capitan 10.11+
"""


from stonixutilityfunctions import iterate, checkPerms, setPerms, resetsecon
from stonixutilityfunctions import readFile, writeFile
from rule import Rule
from logdispatcher import LogPriority
from pkghelper import Pkghelper
import traceback
import os
import re


class SetTFTPDSecureMode(Rule):
    """

    """

    def __init__(self, config, environ, logger, statechglogger):
        """

        :param config:
        :param environ:
        :param logger:
        :param statechglogger:
        """

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
                           'family': ['linux', 'solaris', 'freebsd']}
        
    def report(self):
        """

        :return: self.compliant
        :rtype: bool
        """

        try:
            self.detailedresults = ""
            compliant = True

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
            self.compliant = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

    def reportDebianSys(self):
        """

        :return: compliant
        :rtype: bool
        """

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
        """

        :return: compliant
        :rtype: bool
        """

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
                                    if not re.search("-s", val) and not re.search("--search", val):
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
        """

        :return: self.rulesuccess
        :rtype: bool
        """

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
        self.formatDetailedResults("fix", self.rulesuccess, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.rulesuccess
    
    def fixOtherSys(self):
        """

        :return: success
        :rtype: bool
        """

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
            contents2 = []
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
                                    if re.search("-s", val) or re.search("--secure", val):
                                        if not re.search("-s /var/lib/tftpboot", val) and not re.search("--secure /var/lib/tftpboot", val):
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
        """

        :return: success
        :rtype: bool
        """

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
