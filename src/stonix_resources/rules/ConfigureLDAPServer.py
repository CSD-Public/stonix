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
Created on Aug 4, 2015

@author: Derek Walker
@change: 2017/08/28 Ekkehard - Added self.sethelptext()
@change: 2019/06/12 Breen Malmberg - refactored rule
"""



import traceback
import os
import glob
import stat
import grp
import pwd

from stonixutilityfunctions import iterate, getUserGroupName, resetsecon
from rule import Rule
from logdispatcher import LogPriority


class ConfigureLDAPServer(Rule):
    """
    """

    def __init__(self, config, enviro, logger, statechglogger):
        """

        :param config:
        :param enviro:
        :param logger:
        :param statechglogger:
        """

        Rule.__init__(self, config, enviro, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 139
        self.rulename = "ConfigureLDAPServer"
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.sethelptext()
        datatype = "bool"
        key = "CONFIGURELDAPSERV"
        instructions = """To disable this rule set the value of CONFIGURELDAPSERV to False."""
        default = True
        self.ci = self.initCi(datatype, key, instructions, default)

        self.guidance = []
        self.applicable = {"type": "white",
                           "family": ["linux"]}

    def report(self):
        """
        report on system's ldap server configuration compliance status

        :return: self.compliant
        :rtype: bool
        """

        self.detailedresults = ""
        self.compliant = True
        self.incorrect_perms_files = {}
        self.incorrect_ownership_files = {}

        try:

            # start building ldap configuration files and permissions/ownership dictionary
            self.ldap_conf_files = {"/etc/openldap/slapd.conf": ["root", "ldap", 416],
                               "/etc/ldap/ldap.conf": ["root", "root", 420]}

            ldap_conf_dirs = {"/etc/openldap/slapd.d/*": ["ldap", "ldap", 420],
                               "/etc/ldap/slapd.d/*": ["openldap", "openldap", 384],
                               "/etc/openldap/slapd.d/cn=config/*": ["ldap", "ldap", 416],
                               "/etc/ldap/slapd.d/cn=config/*": ["openldap", "openldap", 384],
                               "/etc/pki/tls/ldap/*": ["root", "ldap", 416],
                               "/etc/pki/tls/CA/*": ["root", "root", 420]}

            # add all files in certain ldap directories to the ldap_conf_files dict
            for cd in ldap_conf_dirs:
                self.logger.log(LogPriority.DEBUG, "Checking directory: " + str(cd)[:-1] + " for ldap configuration files")
                if os.path.exists(cd):
                    files = glob.glob(cd)
                else:
                    files = []
                if not files:
                    self.logger.log(LogPriority.DEBUG, "Didn't find any ldap configuration files in directory: " + str(cd)[:-1])
                else:
                    for f in files:
                        if os.path.isfile(f):
                            self.logger.log(LogPriority.DEBUG, "Adding ldap configuration file: " + str(f) + " to list")
                            self.ldap_conf_files[f] = ldap_conf_dirs[cd]

            # check all ldap files for correct ownership and permissions
            for cf in self.ldap_conf_files:
                if os.path.exists(cf):
                    self.logger.log(LogPriority.DEBUG, "Checking file: " + str(cf) + " for permissions/ownership")

                    # gather permissions and ownership data
                    statdata = os.stat(cf)
                    mode = stat.S_IMODE(statdata.st_mode)
                    ownergrp = getUserGroupName(cf)
                    owner = ownergrp[0]
                    group = ownergrp[1]
                    uid = pwd.getpwnam(self.ldap_conf_files[cf][0])
                    gid = grp.getgrnam(self.ldap_conf_files[cf][1])

                    # record non compliant files for reporting
                    if mode != self.ldap_conf_files[cf][2]:
                        self.incorrect_perms_files[cf] = mode
                    if owner != self.ldap_conf_files[cf][0]:
                        self.incorrect_ownership_files[cf] = [uid,gid]
                    # elif so we don't have duplicate entries in the report
                    elif group != self.ldap_conf_files[cf][1]:
                        self.incorrect_ownership_files[cf] = [uid, gid]
                else:
                    self.logger.log(LogPriority.DEBUG, "LDAP Configuration file: " + str(cf) + " does not exist")

            if self.incorrect_ownership_files:
                self.detailedresults += "\nThe following files have incorrect ownership set:\n" + "\n".join(self.incorrect_ownership_files)
                self.compliant = False
            if self.incorrect_perms_files:
                self.detailedresults += "\nThe following files have incorrect permissions set:\n" + "\n".join(self.incorrect_perms_files)
                self.compliant = False

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.compliant = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)

        return self.compliant

    def fix(self):
        """
        correct permissions and ownership on all ldap server configuration files

        :return: self.rulesuccess
        :rtype: bool
        """

        self.detailedresults = ""
        self.rulesuccess = True
        self.iditerator = 0

        self.logger.log(LogPriority.DEBUG, "Clearing old event list before proceeding to fix")

        eventlist = self.statechglogger.findrulechanges(self.rulenumber)
        for event in eventlist:
            self.statechglogger.deleteentry(event)

        try:

            # if CI is not enabled, do not continue
            if not self.ci.getcurrvalue():
                self.logger.log(LogPriority.DEBUG, "CI was not enabled. Fix was not performed.")
                return self.rulesuccess

            self.logger.log(LogPriority.DEBUG, "Making permissions and ownership corrections on list of ldap conf files")

            # correct permissions and ownership on all ldap conf files
            for f in self.ldap_conf_files:
                self.logger.log(LogPriority.DEBUG, "Fixing permissions/ownership for file: " + str(f))
                try:

                    # get original permission and ownership info
                    orig_uid = pwd.getpwnam(self.incorrect_ownership_files[f][0])
                    orig_gid = grp.getgrnam(self.incorrect_ownership_files[f][1])
                    orig_mode = self.incorrect_perms_files[f][0]

                    # get new permission and ownership info (stored from report())
                    uid = pwd.getpwnam(self.ldap_conf_files[f][0])
                    gid = grp.getgrnam(self.ldap_conf_files[f][1])
                    mode = self.ldap_conf_files[f][2]

                    # undo event stuff
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)

                    event = {"eventtype": "perm",
                             "startstate": [orig_uid, orig_gid, orig_mode],
                             "endstate": [uid, gid, mode],
                             "filepath": f}
                    self.statechglogger.recordchgevent(myid, event)

                    # make the permissions and ownership corrections
                    os.chown(f, uid, gid)
                    os.chmod(f, mode)
                    resetsecon(f)

                except (IndexError, KeyError):
                    pass

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)

        return self.rulesuccess
