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
This rule configures LDAP and Kerberos to LANL specifications. Based on code
from LANL-stor.

@author: Eric Ball
@change: 2015/08/11 eball - Original implementation
'''
from __future__ import absolute_import
import os
import re
import traceback
from ..stonixutilityfunctions import writeFile, readFile, createFile
from ..stonixutilityfunctions import iterate, resetsecon, checkPerms, setPerms
from ..rule import Rule
from ..CommandHelper import CommandHelper
from ..KVEditorStonix import KVEditorStonix
from ..logdispatcher import LogPriority
from ..pkghelper import Pkghelper
from ..ServiceHelper import ServiceHelper


class ConfigureLANLLDAP(Rule):

    def __init__(self, config, enviro, logger, statechglogger):
        Rule.__init__(self, config, enviro, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 254
        self.rulename = "ConfigureLANLLDAP"
        self.formatDetailedResults("initialize")
        self.mandatory = False
        self.helptext = "This rule will configure LDAP for use at LANL. " + \
            "It should be run AFTER ConfigureKerberos"
        self.applicable = {'type': 'white',
                           'family': ['linux']}

        # Configuration item instantiation
        datatype = "bool"
        key = "CONFIGURELANLLDAP"
        instructions = "To disable this rule, set the value of " + \
                       "ConfigureLANLLDAP to false."
        default = True
        self.ci = self.initCi(datatype, key, instructions, default)

        datatype = "string"
        key = "LDAPServer"
        instructions = "The default LDAP server should be set in " + \
            "localize.py. Alternatively, you may specify a server here."
        default = "ldap.lanl.gov"
        self.ldapci = self.initCi(datatype, key, instructions, default)

        datatype = "bool"
        key = "PAMCONF"
        instructions = "PAMCONF will write a known good config into " + \
            "/etc/pam.d/system-auth and /etc/pam.d/password-auth. This " + \
            "will completely overwrite any previous settings or changes."
        # TODO: Set default to false
        default = True
        self.pamci = self.initCi(datatype, key, instructions, default)

        self.ch = CommandHelper(self.logger)
        self.ph = Pkghelper(self.logger, self.environ)
        self.sh = ServiceHelper(self.environ, self.logger)
        self.iditerator = 0

    def report(self):
        try:
            compliant = True
            results = ""
            server = self.ldapci.getcurrvalue()
            osver = int(self.environ.getosver().split(".")[0])
            if not self.ph.determineMgr() == "apt-get":
                authfile = '/etc/sysconfig/authconfig'
                self.authfile = authfile
                authconfig = {"USEPAMACCESS": "yes",
                              "CACHECREDENTIALS": "no",
                              "USESSSDAUTH": "no",
                              "USESHADOW": "yes",
                              "USEWINBIND": "no",
                              "USESSSD": "no",
                              "PASSWDALGORITHM": "sha512",
                              "FORCELEGACY": "yes",
                              "USEFPRINTD": "no",
                              "USEHESIOD": "no",
                              "FORCESMARTCARD": "no",
                              "USELDAPAUTH": "no",
                              "USELDAP": "yes",
                              "USECRACKLIB": "no",
                              "USEWINBINDAUTH": "no",
                              "USESMARTCARD": "no",
                              "USELOCAUTHORIZE": "yes",
                              "USENIS": "no",
                              "USEKERBEROS": "yes",
                              "USESYSNETAUTH": "no",
                              "USESMBAUTH": "no",
                              "USEDB": "no"}
                if osver == 6:
                    authconfig["USEPASSWDQC"] = "yes"
                self.authconfig = authconfig
                tmppath = authfile + ".tmp"
                if os.path.exists(authfile):
                    self.editor = KVEditorStonix(self.statechglogger,
                                                 self.logger, "conf", authfile,
                                                 tmppath, authconfig,
                                                 "present", "closedeq")
                    if not self.editor.report():
                        compliant = False
                        results += "Settings in " + authfile + \
                            " are not correct\n"
                    elif not checkPerms(authfile, [0, 0, 0644], self.logger):
                        compliant = False
                        results += "Settings in " + authfile + \
                            " are correct, but the file's permissions are " + \
                            "incorrect\n"
                else:
                    compliant = False
                    results += authfile + " does not exist.\n"

            ldapfile = "/etc/nslcd.conf"
            self.ldapfile = ldapfile
            if self.ph.determineMgr() == "apt-get":
                gid = "gid nslcd"
            else:
                gid = "gid ldap"
            if re.match('ldap.lanl.gov', server):
                ldapsettings = ['uri ldap://ldap.lanl.gov',
                                'base dc=lanl,dc=gov',
                                'base passwd ou=unixsrv,dc=lanl,dc=gov',
                                'uid nslcd',
                                gid,
                                'ssl no',
                                'nss_initgroups_ignoreusers root']
            else:
                uri = 'uri ldap://' + server
                ldapsettings = [uri, 'base dc=lanl,dc=gov', 'uid nslcd',
                                gid, 'ssl no',
                                'nss_initgroups_ignoreusers root']
            self.ldapsettings = ldapsettings
            if os.path.exists(ldapfile):
                ldapconf = readFile(ldapfile, self.logger)
                if not self.__checkconf(ldapconf, ldapsettings):
                    compliant = False
                    results += "Settings in " + ldapfile + \
                        " are not correct.\n"
                elif not checkPerms(ldapfile, [0, 0, 0600], self.logger):
                    compliant = False
                    results += "Settings in " + ldapfile + " are correct, " + \
                        "but the file's permissions are incorrect\n"
            else:
                compliant = False
                results += ldapfile + " does not exist.\n"

            nsswitchpath = "/etc/nsswitch.conf"
            self.nsswitchpath = nsswitchpath
            nsswitchsettings = ['passwd:    files ldap',
                                'shadow:    files ldap',
                                'group:     files ldap']
            self.nsswitchsettings = nsswitchsettings
            if os.path.exists(nsswitchpath):
                nsconf = readFile(nsswitchpath, self.logger)
                if not self.__checkconf(nsconf, nsswitchsettings):
                    compliant = False
                    results += "Settings in " + nsswitchpath + \
                        " are not correct.\n"
                elif not checkPerms(nsswitchpath, [0, 0, 0644], self.logger):
                    compliant = False
                    results += "Settings in " + ldapfile + " are correct, " + \
                        "but the file's permissions are incorrect\n"
            else:
                compliant = False
                results += nsswitchpath + " does not exist\n"

            self.compliant = compliant
            self.detailedresults = results
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

    def __checkconf(self, contents, settings):
        '''Private method to audit a conf file to ensure that it contains all
        of the required directives.

        @param contents: contents of the configfile as returned by readFile
        @param settings: list of settings that should be present in the conf
        @return: Bool Returns True if all settings are present.
        @author: Eric Ball
        '''
        if len(contents) == 0:
            debug = "File contents passed to __checkconf is empty"
            self.logger.log(LogPriority.DEBUG, debug)
            return False
        if len(settings) == 0:
            debug = "Settings list passed to __checkconf is empty"
            self.logger.log(LogPriority.DEBUG, debug)
            return False

        contentsSplit = []
        comment = re.compile('^#')
        for line in contents:
            if not comment.match(line):
                contentsSplit.append(line.strip().split())
        for setting in settings:
            if setting.split() not in contentsSplit:
                return False
        return True

    def fix(self):
        try:
            if not self.ci.getcurrvalue():
                return
            success = True
            results = ""
            self.iditerator = 0
            eventlist = self.statechglogger.findrulechanges(self.rulenumber)
            for event in eventlist:
                self.statechglogger.deleteentry(event)

            packagesRpm = ["pam_ldap", "nss-pam-ldapd", "openldap-clients",
                           "oddjob-mkhomedir"]
            packagesDeb = ["libpam-ldapd", "libpam-passwdqc", "libpam-krb5"]
            if self.ph.determineMgr() == "apt-get":
                packages = packagesDeb
            else:
                packages = packagesRpm

            for package in packages:
                if not self.ph.check(package):
                    if not self.ph.install(package):
                        success = False
                        results += "Unable to install " + package + "\n"
            if not self.ph.determineMgr() == "apt-get":
                authfile = self.authfile
                authconfig = self.authconfig
                tmppath = authfile + ".tmp"
                if not os.path.exists(authfile):
                    createFile(authfile, self.logger)
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    event = {"eventtype": "creation", "filepath": authfile}
                    self.statechglogger.recordchgevent(myid, event)
                    self.editor = KVEditorStonix(self.statechglogger,
                                                 self.logger, "conf", authfile,
                                                 tmppath, authconfig,
                                                 "present", "closedeq")
                    self.editor.report()
                if self.editor.fixables:
                    if self.editor.fix():
                        if self.editor.commit():
                            debug = "The contents of " + authfile + \
                                " have been corrected\n."
                            self.logger.log(LogPriority.DEBUG, debug)
                            resetsecon(authfile)
                        else:
                            debug = "KVEditor commit to " + authfile + \
                                " was not successful.\n"
                            self.logger.log(LogPriority.DEBUG, debug)
                            success = False
                    else:
                        debug = "KVEditor fix of " + authfile + \
                            " was not successful.\n"
                        self.logger.log(LogPriority.DEBUG, debug)
                        success = False
                myid = iterate(self.iditerator, self.rulenumber)
                setPerms(authfile, [0, 0, 0644], self.logger,
                         self.statechglogger, myid)
                resetsecon(authfile)

            ldapfile = self.ldapfile
            tmppath = ldapfile + ".tmp"
            ldapsettings = self.ldapsettings
            if os.path.exists(ldapfile):
                nonkv = []
                ldapdict = dict()

                # Use self.ldapsettings for loop, so that remove() will not
                # wreak havoc with the loop's index.
                for setting in self.ldapsettings:
                    # For anything that can be seen as a key:value pair, it
                    # will be easier to set it using a KVEditor. For other
                    # settings, a less refined approach is used.
                    split = setting.split()
                    if len(split) == 2:
                        ldapdict[split[0]] = split[1]
                    else:
                        nonkv.append(setting)
                        ldapsettings.remove(setting)
                editor2 = KVEditorStonix(self.statechglogger, self.logger,
                                         "conf", ldapfile, tmppath,
                                         ldapdict, "present", "space")
                editor2.report()
                if editor2.fixables:
                    if editor2.fix():
                        if editor2.commit():
                            debug = "The contents of " + ldapfile + \
                                " have been corrected\n."
                            self.logger.log(LogPriority.DEBUG, debug)
                        else:
                            debug = "KVEditor commit to " + ldapfile + \
                                " was not successful\n"
                            self.logger.log(LogPriority.DEBUG, debug)
                            success = False
                    else:
                        debug = "KVEditor fix of " + ldapfile + \
                            " was not successful\n"
                        self.logger.log(LogPriority.DEBUG, debug)
                        success = False

                ldapconf = readFile(ldapfile, self.logger)
                for setting in nonkv:
                    if not self.__checkconf(ldapconf, [setting]):
                        ldapconf.append(setting + "\n")

                if not self.__writeFile(ldapfile, "".join(ldapconf),
                                        [0, 0, 0600]):
                    success = False
                    results += "Problem writing new contents to " + ldapfile
            else:
                createFile(ldapfile, self.logger)
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                event = {"eventtype": "creation", "filepath": ldapfile}
                self.statechglogger.recordchgevent(myid, event)

                if not self.__writeFile(ldapfile, "\n".join(ldapsettings),
                                        [0, 0, 0600]):
                    success = False
                    results += "Problem writing new contents to " + ldapfile

            if not self.__fixnss(self.nsswitchpath, self.nsswitchsettings):
                success = False
                results += "Problem writing new contents to " + \
                    self.nsswitchpath

            if self.pamci.getcurrvalue():
                if not self.__fixpam():
                    success = False
                    results += "An error occurred while trying to write " + \
                        "the PAM files\n"

            if self.ph.determineMgr() == "apt-get":
                cmd = ["/etc/init.d/nscd", "restart"]
                self.ch.executeCommand(cmd)
                cmd = ["/etc/init.d/nslcd", "restart"]
                self.ch.executeCommand(cmd)
                self.sh.enableservice("nscd")
                self.sh.enableservice("nslcd")
            else:
                cmd = ["authconfig", "--enablemkhomedir", "--updateall"]
                self.ch.executeCommand(cmd)

            self.detailedresults = results
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

    def __fixnss(self, path, settings):
        '''Private method made specifically for fixing the nsswitch.conf file

        @param path: Path to the nsswitch.conf file
        @param settings: List of settings that should be present in the file
        @return: Bool Returns True if all settings are found or written
        @author: Eric Ball
        '''
        try:
            if os.path.exists(path):
                nsConfLines = readFile(path, self.logger)
                nsConf = "".join(nsConfLines)
                settingsSplit = []
                for setting in settings:
                    settingsSplit.append(setting.split())
                for ind, setting in enumerate(settingsSplit):
                    reString = "^(" + setting[0] + ".*)$"
                    match = re.search(reString, nsConf, re.M)
                    if match:
                        confLine = match.group(1)
                        confLineSplit = confLine.split()
                        if not confLineSplit == setting:
                            # Due to LANL's use of Python 2.6, the multiline
                            # flag is not supported. Hence the use of newlines
                            reString = "\n" + setting[0] + ".*"
                            nsConf = re.sub(reString, "\n" + settings[ind],
                                            nsConf)
                        nsConf += "\n" + settings[ind] + "\n"

                return self.__writeFile(path, nsConf, [0, 0, 0644])
            else:
                createFile(path, self.logger)
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                event = {"eventtype": "creation", "filepath": path}
                self.statechglogger.recordchgevent(myid, event)

                return self.__writeFile(path, "\n".join(settings),
                                        [0, 0, 0644])
        except Exception:
            raise

    def __fixpam(self):
        '''Private method for writing PAM configuration files. This is a
        chainsaw-not-scalpel type of method; it simply rewrites the config
        files with the configuration.

        @return: Bool Returns True if all settings are found or written
        @author: Eric Ball
        '''
        result = False
        if self.ph.determineMgr() == "apt-get":
            prefix = "/etc/pam.d/common-"
            auth = prefix + "auth"
            acc = prefix + "account"
            passwd = prefix + "password"
            sess = prefix + "session"

            authconf = '''auth        required      pam_env.so
auth        required      pam_tally2.so silent deny=4  unlock_time=15
auth        sufficient    pam_unix.so nullok try_first_pass
auth        requisite     pam_succeed_if.so uid >= 500 quiet
auth        sufficient    pam_krb5.so use_first_pass
auth        required      pam_deny.so
'''
            accconf = '''account     required      pam_tally2.so
account     required      pam_access.so
account     required      pam_unix.so broken_shadow
account     sufficient    pam_localuser.so
account     sufficient    pam_succeed_if.so uid < 500 quiet
account     [default=bad success=ok user_unknown=ignore] pam_krb5.so
account     required      pam_permit.so
'''
            passwdconf = '''password    requisite     \
pam_passwdqc.so min=disabled,disabled,16,12,8
password    sufficient    pam_unix.so sha512 shadow nullok try_first_pass \
use_authtok remember=5
password    sufficient    pam_krb5.so use_authtok
password    required      pam_deny.so
'''
            sessconf = '''session     optional      pam_keyinit.so revoke
session     required      pam_limits.so
session     [success=1 default=ignore] pam_succeed_if.so service in crond \
quiet use_uid
session     required      pam_unix.so
session     optional      pam_krb5.so
session     required      pam_mkhomedir.so skel=/etc/skel umask=0022
'''
            try:
                result = self.__writeFile(auth, authconf, [0, 0, 0644])
                result &= self.__writeFile(acc, accconf, [0, 0, 0644])
                result &= self.__writeFile(passwd, passwdconf, [0, 0, 0644])
                result &= self.__writeFile(sess, sessconf, [0, 0, 0644])
            except Exception:
                raise
        else:
            sysauth = "/etc/pam.d/system-auth"
            passauth = "/etc/pam.d/password-auth"
            pamconf = '''#%PAM-1.0
# This file is auto-generated.
# User changes will be destroyed the next time authconfig is run.
auth        required      pam_env.so
auth        required      pam_faillock.so preauth silent deny=4  unlock_time=15
auth        sufficient    pam_unix.so nullok try_first_pass
auth        requisite     pam_succeed_if.so uid >= 500 quiet
auth        sufficient    pam_krb5.so use_first_pass
auth        [default=die] pam_faillock.so authfail deny=4  unlock_time=15
auth        required      pam_deny.so

account     required      pam_faillock.so
account     required      pam_access.so
account     required      pam_unix.so broken_shadow
account     sufficient    pam_localuser.so
account     sufficient    pam_succeed_if.so uid < 500 quiet
account     [default=bad success=ok user_unknown=ignore] pam_krb5.so
account     required      pam_permit.so

password    requisite     pam_passwdqc.so min=disabled,disabled,16,12,8
password    sufficient    pam_unix.so sha512 shadow nullok try_first_pass \
use_authtok remember=5
password    sufficient    pam_krb5.so use_authtok
password    required      pam_deny.so

session     optional      pam_keyinit.so revoke
session     required      pam_limits.so
session     [success=1 default=ignore] pam_succeed_if.so service in crond \
quiet use_uid
session     required      pam_unix.so
session     optional      pam_krb5.so
'''
            try:
                result = self.__writeFile(sysauth, pamconf, [0, 0, 0644])
                result &= self.__writeFile(passauth, pamconf, [0, 0, 0644])
            except Exception:
                raise
        return result

    def __writeFile(self, path, contents, perms):
        try:
            tmppath = path + ".tmp"
            success = writeFile(tmppath, contents, self.logger)
            self.iditerator += 1
            myid = iterate(self.iditerator, self.rulenumber)
            event = {"eventtype": "conf", "filepath": path}
            self.statechglogger.recordchgevent(myid, event)
            self.statechglogger.recordfilechange(path, tmppath, myid)
            os.rename(tmppath, path)
            myid = iterate(self.iditerator, self.rulenumber)
            success &= setPerms(path, perms, self.logger,
                                self.statechglogger, myid)
            resetsecon(path)
            return success
        except Exception:
            raise
