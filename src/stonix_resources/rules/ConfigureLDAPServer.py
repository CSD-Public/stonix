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
Created on Aug 4, 2015

@author: dwalker
'''


from __future__ import absolute_import
from ..stonixutilityfunctions import iterate, getUserGroupName, checkPerms
from ..stonixutilityfunctions import setPerms, resetsecon
from ..rule import Rule
from ..logdispatcher import LogPriority
from ..pkghelper import Pkghelper
import traceback
import os
import glob
import stat
import grp
import pwd


class ConfigureLDAPServer(Rule):

    def __init__(self, config, enviro, logger, statechglogger):
        Rule.__init__(self, config, enviro, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 139
        self.rulename = "ConfigureLDAPServer"
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.helptext = '''This rule ensures that any ldap files present \
have the correct permissions.  However this rule only checks locations of \
files that LANL believes them to be in.  If your files and certificates \
are not in those locations, stonix will report compliance'''
        datatype = "bool"
        key = "CONFIGURELDAPSERV"
        instructions = '''To disable this rule set the value of \
CONFIGURELDAPSERV to False.'''
        default = True
        self.ci = self.initCi(datatype, key, instructions, default)

        self.guidance = []
        self.applicable = {"type": "white",
                           "family": ["linux"]}
        self.iditerator = 0
        self.created = False

    def report(self):
        ''''''
        try:
            compliant = True
            self.ph = Pkghelper(self.logger, self.environ)
            self.detailedresults = ""
            if self.ph.manager == "apt-get":
                self.ldap = "slapd"
            elif self.ph.manager == "zypper":
                self.ldap = "openldap2"
            else:
                self.ldap = "openldap-servers"
            if self.ph.check(self.ldap):
                #is ldap configured for tls?

                #do the ldap files have the correct permissions?
                slapd = "/etc/openldap/slapd.conf"
                if os.path.exists(slapd):
                    statdata = os.stat(slapd)
                    mode = stat.S_IMODE(statdata.st_mode)
                    ownergrp = getUserGroupName(slapd)
                    owner = ownergrp[0]
                    group = ownergrp[1]
                    if mode != 416:
                        self.detailedresults += "permissions on " + slapd + \
                            " aren't 640\n"
                        debug = "permissions on " + slapd + " aren't 640\n"
                        self.logger.log(LogPriority.DEBUG, debug)
                        compliant = False
                    if owner != "root":
                        self.detailedresults += "Owner of " + slapd + \
                            " isn't root\n"
                        debug = "Owner of " + slapd + " isn't root\n"
                        self.logger.log(LogPriority.DEBUG, debug)
                        compliant = False
                    if group != "ldap":
                        self.detailedresults += "Group owner of " + slapd + \
                            " isn't ldap\n"
                        debug = "Group owner of " + slapd + " isn't ldap\n"
                        self.logger.log(LogPriority.DEBUG, debug)
                        compliant = False
                #apt-get systems
                slapd = "/etc/ldap/ldap.conf"
                if os.path.exists(slapd):
                    statdata = os.stat(slapd)
                    mode = stat.S_IMODE(statdata.st_mode)
                    ownergrp = getUserGroupName(slapd)
                    owner = ownergrp[0]
                    group = ownergrp[1]
                    if mode != 420:
                        self.detailedresults += "permissions on " + slapd + \
                            " aren't 644\n"
                        debug = "permissions on " + slapd + " aren't 644\n"
                        self.logger.log(LogPriority.DEBUG, debug)
                        compliant = False
                    if owner != "root":
                        self.detailedresults += "Owner of " + slapd + \
                            " isn't root\n"
                        debug = "Owner of " + slapd + " isn't root\n"
                        self.logger.log(LogPriority.DEBUG, debug)
                        compliant = False
                    if group != "root":
                        self.detailedresults += "Group owner of " + slapd + \
                            " isn't root\n"
                        debug = "Group owner of " + slapd + " isn't root\n"
                        self.logger.log(LogPriority.DEBUG, debug)
                        compliant = False
                slapdd = "/etc/openldap/slapd.d/"
                if os.path.exists(slapdd):
                    dirs = glob.glob(slapdd + "*")
                    for loc in dirs:
                        if not os.path.isdir(loc):
                            statdata = os.stat(loc)
                            mode = stat.S_IMODE(statdata.st_mode)
                            ownergrp = getUserGroupName(loc)
                            owner = ownergrp[0]
                            group = ownergrp[1]
                            if mode != 416:
                                self.detailedresults += "Permissions " + \
                                    "aren't 640 on " + loc + "\n"
                                debug = "Permissions aren't 640 on " + loc + \
                                    "\n"
                                self.logger.log(LogPriority.DEBUG, debug)
                                compliant = False
                            if owner != "ldap":
                                self.detailedresults += "Owner of " + loc + \
                                    " isn't ldap\n"
                                debug = "Owner of " + loc + " isn't ldap\n"
                                self.logger.log(LogPriority.DEBUG, debug)
                                compliant = False
                            if group != "ldap":
                                self.detailedresults += "Group of " + loc + \
                                    " isn't ldap\n"
                                debug = "Group of " + loc + " isn't ldap\n"
                                self.logger.log(LogPriority.DEBUG, debug)
                                compliant = False
                #apt-get systems
                slapdd = "/etc/ldap/slapd.d/"
                if os.path.exists(slapdd):
                    dirs = glob.glob(slapdd + "*")
                    for loc in dirs:
                        if not os.path.isdir(loc):
                            statdata = os.stat(loc)
                            mode = stat.S_IMODE(statdata.st_mode)
                            ownergrp = getUserGroupName(loc)
                            owner = ownergrp[0]
                            group = ownergrp[1]
                            if mode != 384:
                                self.detailedresults += "Permissions " + \
                                    "aren't 640 on " + loc + "\n"
                                debug = "Permissions aren't 600 on " + loc + \
                                    "\n"
                                self.logger.log(LogPriority.DEBUG, debug)
                                compliant = False
                            if owner != "openldap":
                                self.detailedresults += "Owner of " + loc + \
                                    " isn't ldap\n"
                                debug = "Owner of " + loc + " isn't openldap\n"
                                self.logger.log(LogPriority.DEBUG, debug)
                                compliant = False
                            if group != "openldap":
                                self.detailedresults += "Group of " + loc + \
                                    " isn't ldap\n"
                                debug = "Group of " + loc + " isn't openldap\n"
                                self.logger.log(LogPriority.DEBUG, debug)
                                compliant = False
                cnconfig = "/etc/openldap/slapd.d/cn=config/"
                if os.path.exists(cnconfig):
                    dirs = glob.glob(cnconfig + "*")
                    for loc in dirs:
                        if not os.path.isdir(loc):
                            statdata = os.stat(loc)
                            mode = stat.S_IMODE(statdata.st_mode)
                            ownergrp = getUserGroupName(loc)
                            owner = ownergrp[0]
                            group = ownergrp[1]
                            if mode != 416:
                                self.detailedresults += "Permissions " + \
                                    "aren't 640 on " + loc + "\n"
                                debug = "Permissions aren't 640 on " + loc + \
                                    "\n"
                                self.logger.log(LogPriority.DEBUG, debug)
                                compliant = False
                            if owner != "ldap":
                                self.detailedresults += "Owner of " + loc + \
                                    " isn't ldap\n"
                                debug = "Owner of " + loc + " isn't ldap\n"
                                self.logger.log(LogPriority.DEBUG, debug)
                                compliant = False
                            if group != "ldap":
                                self.detailedresults += "Group of " + loc + \
                                    " isn't ldap\n"
                                debug = "Group of " + loc + " isn't ldap\n"
                                self.logger.log(LogPriority.DEBUG, debug)
                                compliant = False
                #apt-get systems
                cnconfig = "/etc/ldap/slapd.d/cn=config/"
                if os.path.exists(cnconfig):
                    dirs = glob.glob(cnconfig + "*")
                    for loc in dirs:
                        if not os.path.isdir(loc):
                            statdata = os.stat(loc)
                            mode = stat.S_IMODE(statdata.st_mode)
                            ownergrp = getUserGroupName(loc)
                            owner = ownergrp[0]
                            group = ownergrp[1]
                            if mode != 384:
                                self.detailedresults += "Permissions " + \
                                    "aren't 600 on " + loc + "\n"
                                debug = "Permissions aren't 600 on " + loc + \
                                    "\n"
                                self.logger.log(LogPriority.DEBUG, debug)
                                compliant = False
                            if owner != "openldap":
                                self.detailedresults += "Owner of " + loc + \
                                    " isn't openldap\n"
                                debug = "Owner of " + loc + " isn't openldap\n"
                                self.logger.log(LogPriority.DEBUG, debug)
                                compliant = False
                            if group != "openldap":
                                self.detailedresults += "Group of " + loc + \
                                    " isn't ldap\n"
                                debug = "Group of " + loc + " isn't openldap\n"
                                self.logger.log(LogPriority.DEBUG, debug)
                                compliant = False
                pki = "/etc/pki/tls/ldap/"
                if os.path.exists(pki):
                    dirs = glob.glob(pki + "*")
                    for loc in dirs:
                        if not os.path.isdir():
                            statdata = os.stat(loc)
                            mode = stat.S_IMODE(statdata.st_mode)
                            ownergrp = getUserGroupName(loc)
                            owner = ownergrp[0]
                            group = ownergrp[1]
                            if mode != 416:
                                self.detailedresults += "Permissions " + \
                                    "aren't 640 on " + loc + "\n"
                                debug = "Permissions aren't 640 on " + loc + \
                                    "\n"
                                self.logger.log(LogPriority.DEBUG, debug)
                                compliant = False
                            if owner != "root":
                                self.detailedresults += "Owner of " + loc + \
                                    " isn't root\n"
                                debug = "Owner of " + loc + " isn't root\n"
                                self.logger.log(LogPriority.DEBUG, debug)
                                compliant = False
                            if group != "ldap":
                                self.detailedresults += "Group of " + loc + \
                                    " isn't ldap\n"
                                debug = "Group of " + loc + " isn't ldap\n"
                                self.logger.log(LogPriority.DEBUG, debug)
                                compliant = False
                if os.path.exists("/etc/pki/tls/CA/"):
                    dirs = glob.glob("/etc/pki/tls/CA/*")
                    for loc in dirs:
                        if not os.path.isdir():
                            if not checkPerms(loc, [0, 0, 420], self.logger):
                                compliant = False
                                self.detailedresults += "Permissions " + \
                                    "aren't correct on " + loc + " file\n"
                                debug = "Permissions aren't correct on " + \
                                    loc + " file\n"
                                self.logger.log(LogPriority.DEBUG, debug)
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
        self.compliant = compliant

###############################################################################

    def fix(self):
        try:
            if not self.ci.getcurrvalue():
                return
            success = True
            self.iditerator = 0
            eventlist = self.statechglogger.findrulechanges(self.rulenumber)
            for event in eventlist:
                self.statechglogger.deleteentry(event)
            if self.ph.check(self.ldap):
                #is ldap configured for tls?

                #do the ldap files have the correct permissions?
                slapd = "/etc/openldap/slapd.conf"
                if os.path.exists(slapd):
                    statdata = os.stat(slapd)
                    mode = stat.S_IMODE(statdata.st_mode)
                    ownergrp = getUserGroupName(slapd)
                    owner = ownergrp[0]
                    group = ownergrp[1]
                    if mode != 416 or owner != "root" or group != "ldap":
                        origuid = statdata.st_uid
                        origgid = statdata.st_gid
                        if grp.getgrnam("ldap")[2]:
                            gid = grp.getgrnam("ldap")[2]
                            self.iditerator += 1
                            myid = iterate(self.iditerator, self.rulenumber)
                            event = {"eventtype": "perm",
                                     "startstate": [origuid, origgid, mode],
                                     "endstate": [0, gid, 416],
                                     "filepath": slapd}
                            self.statechglogger.recordchgevent(myid, event)
                            os.chmod(slapd, 416)
                            os.chown(slapd, 0, gid)
                            resetsecon(slapd)
                        else:
                            success = False
                            debug = "Unable to determine the id " + \
                                "number of ldap group.  Will not change " + \
                                "permissions on " + slapd + " file\n"
                            self.logger.log(LogPriority.DEBUG, debug)
                #apt-get systems
                slapd = "/etc/ldap/ldap.conf"
                if os.path.exists(slapd):
                    statdata = os.stat(slapd)
                    mode = stat.S_IMODE(statdata.st_mode)
                    ownergrp = getUserGroupName(slapd)
                    owner = ownergrp[0]
                    group = ownergrp[1]
                    if mode != 420 or owner != "root" or group != "root":
                        origuid = statdata.st_uid
                        origgid = statdata.st_gid
                        if grp.getgrnam("root")[2] != "":
                            gid = grp.getgrnam("root")[2]
                            self.iditerator += 1
                            myid = iterate(self.iditerator, self.rulenumber)
                            event = {"eventtype": "perm",
                                     "startstate": [origuid, origgid, mode],
                                     "endstate": [0, gid, 420],
                                     "filepath": slapd}
                            self.statechglogger.recordchgevent(myid, event)
                            os.chmod(slapd, 420)
                            os.chown(slapd, 0, gid)
                            resetsecon(slapd)
                        else:
                            success = False
                            debug = "Unable to determine the id " + \
                                "number of root group.  Will not change " + \
                                "permissions on " + slapd + " file\n"
                            self.logger.log(LogPriority.DEBUG, debug)
                slapdd = "/etc/openldap/slapd.d/"
                if os.path.exists(slapdd):
                    dirs = glob.glob(slapdd + "*")
                    for loc in dirs:
                        if not os.path.isdir(loc):
                            statdata = os.stat(loc)
                            mode = stat.S_IMODE(statdata.st_mode)
                            ownergrp = getUserGroupName(loc)
                            owner = ownergrp[0]
                            group = ownergrp[1]
                            if mode != 416 or owner != "ldap" or group \
                                    != "ldap":
                                origuid = statdata.st_uid
                                origgid = statdata.st_gid
                                if grp.getgrnam("ldap")[2] != "":
                                    if pwd.getpwnam("ldap")[2] != "":
                                        gid = grp.getgrnam("ldap")[2]
                                        uid = pwd.getpwnam("ldap")[2]
                                        self.iditerator += 1
                                        myid = iterate(self.iditerator,
                                                       self.rulenumber)
                                        event = {"eventtype": "perm",
                                                 "startstate": [origuid,
                                                                origgid, mode],
                                                 "endstate": [uid, gid, 416],
                                                 "filepath": loc}
                                        self.statechglogger.recordchgevent(myid, event)
                                        os.chmod(loc, 416)
                                        os.chown(loc, uid, gid)
                                        resetsecon(loc)
                                    else:
                                        debug = "Unable to determine the " + \
                                            "id number of ldap user.  " + \
                                            "Will not change permissions " + \
                                            "on " + loc + " file\n"
                                        self.logger.log(LogPriority.DEBUG, debug)
                                        success = False
                                else:
                                    success = False
                                    debug = "Unable to determine the id " + \
                                        "number of ldap group.  Will not " + \
                                        "change permissions on " + loc + \
                                        " file\n"
                                    self.logger.log(LogPriority.DEBUG, debug)
                #apt-get systems
                slapdd = "/etc/ldap/slapd.d/"
                if os.path.exists(slapdd):
                    dirs = glob.glob(slapdd + "*")
                    for loc in dirs:
                        if not os.path.isdir(loc):
                            statdata = os.stat(loc)
                            mode = stat.S_IMODE(statdata.st_mode)
                            ownergrp = getUserGroupName(loc)
                            owner = ownergrp[0]
                            group = ownergrp[1]
                            if mode != 384 or owner != "openldap" or group \
                                    != "openldap":
                                origuid = statdata.st_uid
                                origgid = statdata.st_gid
                                if grp.getgrnam("openldap")[2] != "":
                                    if pwd.getpwnam("openldap")[2] != "":
                                        gid = grp.getgrnam("openldap")[2]
                                        uid = pwd.getpwnam("openldap")[2]
                                        self.iditerator += 1
                                        myid = iterate(self.iditerator,
                                                       self.rulenumber)
                                        event = {"eventtype": "perm",
                                                 "startstate": [origuid,
                                                                origgid, mode],
                                                 "endstate": [uid, gid, 384],
                                                 "filepath": loc}
                                        self.statechglogger.recordchgevent(myid, event)
                                        os.chmod(loc, 384)
                                        os.chown(loc, uid, gid)
                                        resetsecon(loc)
                                    else:
                                        debug = "Unable to determine the " + \
                                            "id number of ldap user.  " + \
                                            "Will not change permissions " + \
                                            "on " + loc + " file\n"
                                        self.logger.log(LogPriority.DEBUG, debug)
                                        success = False
                                else:
                                    success = False
                                    debug = "Unable to determine the id " + \
                                        "number of ldap group.  Will not " + \
                                        "change permissions on " + loc + \
                                        " file\n"
                                    self.logger.log(LogPriority.DEBUG, debug)
                cnconfig = "/etc/openldap/slapd.d/cn=config/"
                if os.path.exists(cnconfig):
                    dirs = glob.glob(cnconfig + "*")
                    for loc in dirs:
                        if not os.path.isdir(loc):
                            statdata = os.stat(loc)
                            mode = stat.S_IMODE(statdata.st_mode)
                            ownergrp = getUserGroupName(loc)
                            owner = ownergrp[0]
                            group = ownergrp[1]
                            if mode != 416 or owner != "ldap" or group != "ldap":
                                origuid = statdata.st_uid
                                origgid = statdata.st_gid
                                if grp.getgrnam("ldap")[2] != "":
                                    if pwd.getpwnam("ldap")[2] != "":
                                        gid = grp.getgrnam("ldap")[2]
                                        uid = pwd.getpwnam("ldap")[2]
                                        self.iditerator += 1
                                        myid = iterate(self.iditerator,
                                                       self.rulenumber)
                                        event = {"eventtype": "perm",
                                                 "startstate": [origuid,
                                                                origgid, mode],
                                                 "endstate": [uid, gid, 416],
                                                 "filepath": loc}
                                        self.statechglogger.recordchgevent(myid, event)
                                        os.chmod(loc, 416)
                                        os.chown(loc, uid, gid)
                                        resetsecon(loc)
                                    else:
                                        debug = "Unable to determine the " + \
                                            "id number of ldap user.  " + \
                                            "Will not change permissions " + \
                                            "on " + loc + " file\n"
                                        self.logger.log(LogPriority.DEBUG, debug)
                                        success = False
                                else:
                                    success = False
                                    debug = "Unable to determine the id " + \
                                        "number of ldap group.  Will not " + \
                                        "change permissions on " + loc + \
                                        " file\n"
                                    self.logger.log(LogPriority.DEBUG, debug)
                #apt-get systems
                cnconfig = "/etc/ldap/slapd.d/cn=config/"
                if os.path.exists(cnconfig):
                    dirs = glob.glob(cnconfig + "*")
                    for loc in dirs:
                        if not os.path.isdir(loc):
                            statdata = os.stat(loc)
                            mode = stat.S_IMODE(statdata.st_mode)
                            ownergrp = getUserGroupName(loc)
                            owner = ownergrp[0]
                            group = ownergrp[1]
                            if mode != 384 or owner != "openldap" or group != "openldap":
                                origuid = statdata.st_uid
                                origgid = statdata.st_gid
                                if grp.getgrnam("openldap")[2] != "":
                                    if pwd.getpwnam("openldap")[2] != "":
                                        gid = grp.getgrnam("openldap")[2]
                                        uid = pwd.getpwnam("openldap")[2]
                                        self.iditerator += 1
                                        myid = iterate(self.iditerator,
                                                       self.rulenumber)
                                        event = {"eventtype": "perm",
                                                 "startstate": [origuid,
                                                                origgid, mode],
                                                 "endstate": [uid, gid, 384],
                                                 "filepath": loc}
                                        self.statechglogger.recordchgevent(myid, event)
                                        os.chmod(loc, 384)
                                        os.chown(loc, uid, gid)
                                        resetsecon(loc)
                                    else:
                                        debug = "Unable to determine the " + \
                                            "id number of ldap user.  " + \
                                            "Will not change permissions " + \
                                            "on " + loc + " file\n"
                                        self.logger.log(LogPriority.DEBUG, debug)
                                        success = False
                                else:
                                    success = False
                                    debug = "Unable to determine the id " + \
                                        "number of ldap group.  Will not " + \
                                        "change permissions on " + loc + \
                                        " file\n"
                                    self.logger.log(LogPriority.DEBUG, debug)
                pki = "/etc/pki/tls/ldap/"
                if os.path.exists(pki):
                    dirs = glob.glob(pki + "*")
                    for loc in dirs:
                        if not os.path.isdir():
                            statdata = os.stat(loc)
                            mode = stat.S_IMODE(statdata.st_mode)
                            ownergrp = getUserGroupName(loc)
                            owner = ownergrp[0]
                            group = ownergrp[1]
                            if mode != 416 or owner != "root" or group != "ldap":
                                origuid = statdata.st_uid
                                origgid = statdata.st_gid
                                if grp.getgrnam("ldap")[2] != "":
                                    gid = grp.getgrnam("ldap")[2]
                                    self.iditerator += 1
                                    myid = iterate(self.iditerator, self.rulenumber)
                                    event = {"eventtype": "perm",
                                             "startstate": [origuid, origgid, mode],
                                             "endstate": [0, gid, 416],
                                             "filepath": loc}
                                    self.statechglogger.recordchgevent(myid, event)
                                    os.chmod(slapd, 416)
                                    os.chown(slapd, 0, gid)
                                    resetsecon(slapd)
                                else:
                                    success = False
                                    debug = "Unable to determine the id " + \
                                        "number of ldap group.  Will not change " + \
                                        "permissions on " + loc + " file\n"
                                    self.logger.log(LogPriority.DEBUG, debug)
                if os.path.exists("/etc/pki/tls/CA/"):
                    dirs = glob.glob("/etc/pki/tls/CA/*")
                    for loc in dirs:
                        if not os.path.isdir():
                            if not checkPerms(loc, [0, 0, 420], self.logger):
                                self.iditerator += 1
                                myid = iterate(self.iditerator, self.rulenumber)
                                if not setPerms(loc, [0, 0, 420], self.logger,
                                                self.statechglogger, myid):
                                    debug = "Unable to set permissions on " + \
                                        loc + " file\n"
                                    self.logger.log(LogPriority.DEBUG, debug)
                                    success = False
                                else:
                                    resetsecon(loc)
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
