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
@change: 2015/10/01 eball - Refactoring Red Hat code for sssd
@change: 2015/10/23 eball - Adding undo methods to new code in fix()
@change: 2015/11/16 eball - Moving RHEL6 back to nslcd
@change: 2016/01/25 eball - Changed pw policies to meet RHEL 7 STIG standards
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
        self.helptext = """This rule will configure LDAP for use at LANL. \
For full functionality, the ConfigureKerberos rule will also need to be run.
Note that there is a configuration item below, "MAKEHOMEDIRS", which is \
disabled by default for security reasons. For graphical logins, this item \
should be enabled.
On Debian and Ubuntu systems, this rule will require a restart to take \
effect."""
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
        key = "MAKEHOMEDIRS"
        instructions = "To have a home directory automatically created " + \
            "upon a user's first login, enable MAKEHOMEDIRS. Note that " + \
            "this may be required for GUI logins of LDAP accounts."
        default = False
        self.mkhomedirci = self.initCi(datatype, key, instructions, default)

        self.ch = CommandHelper(self.logger)
        self.ph = Pkghelper(self.logger, self.environ)
        self.sh = ServiceHelper(self.environ, self.logger)
        self.iditerator = 0

    def report(self):
        try:
            compliant = True
            results = ""
            server = self.ldapci.getcurrvalue()
            self.myos = self.environ.getostype().lower()
            self.majorVer = self.environ.getosver().split(".")[0]
            self.majorVer = int(self.majorVer)

            # All systems except RHEL 6 and Ubuntu use sssd
            if (re.search("red hat", self.myos) and self.majorVer < 7) or \
               re.search("ubuntu", self.myos):
                self.nslcd = True
            else:
                self.nslcd = False

            packagesRpm = ["nss-pam-ldapd", "openldap-clients", "sssd",
                           "krb5-workstation", "oddjob-mkhomedir",
                           "libpwquality"]
            packagesRhel6 = ["pam_ldap", "nss-pam-ldapd", "openldap-clients",
                             "oddjob-mkhomedir", "libpwquality"]
            packagesUbu = ["libpam-ldapd", "libpam-cracklib",
                           "libpam-krb5"]
            packagesDeb = ["sssd", "libnss-sss", "libpam-sss",
                           "libpam-cracklib", "libpam-krb5"]
            packagesSuse = ["yast2-auth-client", "sssd-krb5", "pam_ldap",
                            "pam_pwquality", "sssd", "krb5"]
            if self.ph.determineMgr() == "apt-get":
                if re.search("ubuntu", self.myos):
                    packages = packagesUbu
                else:
                    packages = packagesDeb
            elif self.ph.determineMgr() == "zypper":
                packages = packagesSuse
            elif re.search("red hat", self.myos) and self.majorVer < 7:
                packages = packagesRhel6
            else:
                packages = packagesRpm
            self.packages = packages
            for package in packages:
                if not self.ph.check(package) and \
                   self.ph.checkAvailable(package):
                    compliant = False
                    results += package + " is not installed\n"

            pamconf = self.__getpamconf()
            self.pamconf = pamconf
            for conffile in pamconf:
                currentConf = readFile(conffile, self.logger)
                if not self.__checkconf(currentConf,
                                        pamconf[conffile].split("\n")):
                    compliant = False
                    results += "Settings in " + conffile + " are incorrect\n"

            if not self.nslcd:
                sssdconfpath = "/etc/sssd/sssd.conf"
                self.sssdconfpath = sssdconfpath
                sssdconfdict = {"services": "nss, pam",
                                "filter_users": "root",
                                "filter_groups": "root",
                                "ldap_uri": "ldap://" + server,
                                "id_provider": "ldap",
                                "auth_provider": "krb5",
                                "krb5_realm": "lanl.gov",
                                "krb5_server": "kerberos.lanl.gov," +
                                "kerberos-slaves.lanl.gov"}
                self.sssdconfdict = sssdconfdict
                if not self.sh.auditservice("sssd"):
                    compliant = False
                    results += "sssd service is not activated\n"
                if os.path.exists(sssdconfpath):
                    tmppath = sssdconfpath + ".tmp"
                    self.editor = KVEditorStonix(self.statechglogger,
                                                 self.logger, "conf",
                                                 sssdconfpath,
                                                 tmppath, sssdconfdict,
                                                 "present", "openeq")
                    if not self.editor.report():
                        compliant = False
                        results += "The correct settings were not found in " + \
                            sssdconfpath + "\n" + str(self.editor.fixables) + \
                            "\n"
                else:
                    compliant = False
                    results += sssdconfpath + " does not exist\n"

                nsswitchpath = "/etc/nsswitch.conf"
                self.nsswitchpath = nsswitchpath
                nsswitchsettings = ['passwd:    compat sss',
                                    'shadow:    compat sss',
                                    'group:     compat sss']
                self.nsswitchsettings = nsswitchsettings
                if os.path.exists(nsswitchpath):
                    nsconf = readFile(nsswitchpath, self.logger)
                    if not self.__checkconf(nsconf, nsswitchsettings):
                        compliant = False
                        results += "Settings in " + nsswitchpath + \
                            " are not correct.\n"
                    elif not checkPerms(nsswitchpath, [0, 0, 0644],
                                        self.logger):
                        compliant = False
                        results += "Settings in " + nsswitchpath + " are " + \
                            "correct, but the file's permissions are " + \
                            "incorrect\n"
                else:
                    compliant = False
                    results += nsswitchpath + " does not exist\n"
            else:
                if not self.sh.auditservice("nslcd"):
                    compliant = False
                    results += "nslcd service is not activated\n"

                ldapfile = "/etc/nslcd.conf"
                self.ldapfile = ldapfile
                if re.search("ubuntu", self.myos):
                    gid = "gid nslcd"
                else:
                    gid = "gid ldap"
                if re.match('ldap.lanl.gov', server):
                    self.ldapsettings = ['uri ldap://' +
                                         self.ldapci.getcurrvalue(),
                                         'base dc=lanl,dc=gov',
                                         'base passwd ou=unixsrv,dc=lanl,' +
                                         'dc=gov',
                                         'uid nslcd',
                                         gid,
                                         'ssl no',
                                         'nss_initgroups_ignoreusers root']
                ldapsettings = self.ldapsettings
                if os.path.exists(ldapfile):
                    ldapconf = readFile(ldapfile, self.logger)
                    if not self.__checkconf(ldapconf, ldapsettings):
                        compliant = False
                        results += "Settings in " + ldapfile + \
                            " are not correct.\n"
                    elif not checkPerms(ldapfile, [0, 0, 0600], self.logger):
                        compliant = False
                        results += "Settings in " + ldapfile + " are " + \
                            "correct, but the file's permissions are " + \
                            "incorrect\n"
                else:
                    compliant = False
                    results += ldapfile + " does not exist.\n"

                # nsswitch settings. Deb distros prefer "compat" to "files" as
                # the default, but LANL does not use NSS netgroups, so we will
                # use "files ldap" for all systems
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
                    elif not checkPerms(nsswitchpath, [0, 0, 0644],
                                        self.logger):
                        compliant = False
                        results += "Settings in " + nsswitchpath + " are " + \
                            "correct, but the file's permissions are " + \
                            "incorrect\n"
                else:
                    compliant = False
                    results += nsswitchpath + " does not exist\n"

                # On Ubuntu, Unity/LightDM requires an extra setting to add an
                # option to the login screen for network users
                if re.search("ubuntu", self.myos):
                    lightdmconf = "/etc/lightdm/lightdm.conf"
                    self.lightdmconf = lightdmconf
                    tmppath = lightdmconf + ".tmp"
                    manLogin = {"greeter-show-manual-login": "true"}
                    self.editor2 = KVEditorStonix(self.statechglogger,
                                                  self.logger, "conf",
                                                  lightdmconf,
                                                  tmppath, manLogin,
                                                  "present", "closedeq")
                    if not self.editor2.report():
                        compliant = False
                        results += '"greeter-show-manual-login=true" not ' + \
                            "present in " + lightdmconf + "\n"

            self.compliant = compliant
            self.detailedresults = results
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
                contentsSplit.append(line.split())
        for setting in settings:
            if setting == "":
                continue
            if not comment.match(setting) and \
               setting.split() not in contentsSplit:
                debug = str(setting.split()) + " not in " + str(contentsSplit)
                self.logger.log(LogPriority.DEBUG, debug)
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

            packages = self.packages
            for package in packages:
                if not self.ph.check(package):
                    if self.ph.checkAvailable(package):
                        if not self.ph.install(package):
                            success = False
                            results += "Unable to install " + package + "\n"
                        else:
                            self.iditerator += 1
                            myid = iterate(self.iditerator, self.rulenumber)
                            event = {"eventtype": "pkghelper",
                                     "pkgname": package,
                                     "startstate": "removed",
                                     "endstate": "installed"}
                            self.statechglogger.recordchgevent(myid, event)

            if not self.__fixnss(self.nsswitchpath, self.nsswitchsettings):
                success = False
                results += "Problem writing new contents to " + \
                    self.nsswitchpath + "\n"

            if not self.__fixpam(self.pamconf):
                success = False
                results += "An error occurred while trying to write " + \
                    "the PAM files\n"

            if not self.nslcd:
                if not self.__fixsssd():
                    success = False
                    results += "Failed to write good configuration to " + \
                        self.sssdconfpath + "\n"
                if not self.sh.disableservice("nscd"):
                    success = False
                    results += "Failed to disable nscd\n"
                else:
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    event = {"eventtype": "servicehelper",
                             "servicename": "nscd",
                             "startstate": "enabled",
                             "endstate": "disabled"}
                    self.statechglogger.recordchgevent(myid, event)
                if self.sh.isrunning("sssd"):
                    if not self.sh.reloadservice("sssd"):
                        success = False
                        results += "Failed to reload sssd service\n"
                if not self.sh.auditservice("sssd"):
                    if not self.sh.enableservice("sssd"):
                        success = False
                        results += "Failed to enable sssd service\n"
                    else:
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        event = {"eventtype": "servicehelper",
                                 "servicename": "sssd",
                                 "startstate": "disabled",
                                 "endstate": "enabled"}
                        self.statechglogger.recordchgevent(myid, event)
            else:
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
                    ldapKVE = KVEditorStonix(self.statechglogger, self.logger,
                                             "conf", ldapfile, tmppath,
                                             ldapdict, "present", "space")
                    ldapKVE.report()
                    if ldapKVE.fixables:
                        if ldapKVE.fix():
                            if ldapKVE.commit():
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
                        results += "Problem writing new contents to " + \
                            ldapfile
                else:
                    createFile(ldapfile, self.logger)
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    event = {"eventtype": "creation", "filepath": ldapfile}
                    self.statechglogger.recordchgevent(myid, event)

                    if not self.__writeFile(ldapfile, "\n".join(ldapsettings),
                                            [0, 0, 0600]):
                        success = False
                        results += "Problem writing new contents to " + \
                            ldapfile

                if re.search("ubuntu", self.myos):
                    lightdmconf = self.lightdmconf
                    if self.editor2.fixables:
                        if self.editor2.fix():
                            if self.editor2.commit():
                                debug = "The contents of " + lightdmconf + \
                                    " have been corrected\n."
                                self.logger.log(LogPriority.DEBUG, debug)
                            else:
                                debug = "KVEditor commit to " + lightdmconf + \
                                    " was not successful\n"
                                self.logger.log(LogPriority.DEBUG, debug)
                                success = False
                        else:
                            debug = "KVEditor fix of " + lightdmconf + \
                                " was not successful\n"
                            self.logger.log(LogPriority.DEBUG, debug)
                            success = False

                if os.path.exists("/etc/init.d/nscd"):
                    cmd = ["/etc/init.d/nscd", "restart"]
                    self.ch.executeCommand(cmd)
                cmd = ["/etc/init.d/nslcd", "restart"]
                self.ch.executeCommand(cmd)
                self.sh.enableservice("nscd")
                self.sh.enableservice("nslcd")

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
                            nsConf = re.sub(confLine, settings[ind],
                                            nsConf)
                        else:
                            nsConf += "\n" + settings[ind] + "\n"
                    else:
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

    def __fixsssd(self):
        sssdconf = '''[sssd]
config_file_version = 2
services = nss, pam
domains = lanlldap

[nss]
filter_users = root
filter_groups = root

[pam]

[domain/lanlldap]
id_provider = ldap
auth_provider = krb5
ldap_schema = rfc2307
ldap_uri = ldap://ldap.lanl.gov
ldap_search_base = dc=lanl,dc=gov

krb5_server = kerberos.lanl.gov,kerberos-slaves.lanl.gov
krb5_realm = lanl.gov
'''
        sssdconfpath = self.sssdconfpath
        sssdconfdict = self.sssdconfdict
        tmppath = sssdconfpath + ".tmp"
        if not os.path.exists(sssdconfpath):
            createFile(sssdconfpath, self.logger)
            self.iditerator += 1
            myid = iterate(self.iditerator, self.rulenumber)
            event = {"eventtype": "creation", "filepath": sssdconfpath}
            self.statechglogger.recordchgevent(myid, event)

        # Though we are using the KVEditor to check for valid config details,
        # the exact format of sssd.conf is too complicated for a KVEditor.
        # Therefore, we will simply write a good config to the file.
        self.editor = KVEditorStonix(self.statechglogger, self.logger, "conf",
                                     sssdconfpath, tmppath, sssdconfdict,
                                     "present", "openeq")
        if self.editor.report():
            return True
        else:
            return self.__writeFile(sssdconfpath, sssdconf, [0, 0, 0600])

    def __getpamconf(self):
        pamconf = {}
        if self.ph.determineMgr() == "apt-get":
            prefix = "/etc/pam.d/common-"
            auth = prefix + "auth"
            acc = prefix + "account"
            passwd = prefix + "password"
            sess = prefix + "session"
            pamconf[auth] = '''auth        required      pam_env.so
auth        required      pam_tally2.so deny=5 unlock_time=600 onerr=fail
auth        sufficient    pam_unix.so nullok try_first_pass
auth        requisite     pam_succeed_if.so uid >= 500 quiet
auth        sufficient    pam_krb5.so use_first_pass
auth        required      pam_deny.so
'''
            pamconf[acc] = '''account     required      pam_tally2.so
account     required      pam_access.so
account     required      pam_unix.so broken_shadow
account     sufficient    pam_localuser.so
account     sufficient    pam_succeed_if.so uid < 500 quiet
account     [default=bad success=ok user_unknown=ignore] pam_krb5.so
account     required      pam_permit.so
'''
            pamconf[passwd] = '''password    requisite     \
pam_cracklib.so minlen=14 minclass=4 difok=7 dcredit=0 ucredit=0 lcredit=0 \
ocredit=0 retry=3
password    sufficient    pam_unix.so sha512 shadow nullok try_first_pass \
use_authtok remember=10
password    sufficient    pam_krb5.so use_authtok
password    required      pam_deny.so
'''
            pamconf[sess] = '''session     optional      pam_keyinit.so revoke
session     required      pam_limits.so
session     [success=1 default=ignore] pam_succeed_if.so service in crond \
quiet use_uid
session     required      pam_unix.so
session     optional      pam_krb5.so
-session    optional      pam_systemd.so
'''
            if self.mkhomedirci.getcurrvalue():
                pamconf[sess] += "session     required      " + \
                    "pam_mkhomedir.so skel=/etc/skel umask=0077\n"

        elif self.ph.determineMgr() == "zypper":
            prefix = "/etc/pam.d/common-"
            auth = prefix + "auth"
            acc = prefix + "account"
            passwd = prefix + "password"
            sess = prefix + "session"
            pamconf[auth] = '''auth    required        pam_env.so
auth    required        pam_tally2.so deny=5 unlock_time=600 onerr=fail
auth    optional        pam_gnome_keyring.so
auth    sufficient      pam_unix.so     try_first_pass
auth    required        pam_sss.so      use_first_pass
'''
            pamconf[acc] = '''account requisite       pam_unix.so     try_first_pass
account sufficient      pam_localuser.so
account required        pam_sss.so      use_first_pass
'''
            pamconf[passwd] = '''password        requisite       \
pam_pwquality.so minlen=14 minclass=4 difok=7 dcredit=0 ucredit=0 lcredit=0 \
ocredit=0 retry=3
password        sufficient      pam_unix.so sha512 shadow nullok \
try_first_pass use_authtok remember=10
password        optional        pam_gnome_keyring.so    use_authtok
password        required        pam_sss.so      use_authtok
'''
            pamconf[sess] = '''session required        pam_limits.so
session required        pam_unix.so     try_first_pass
session optional        pam_sss.so
session optional        pam_umask.so
session optional        pam_systemd.so
session optional        pam_gnome_keyring.so    auto_start \
only_if=gdm,gdm-password,lxdm,lightdm
session optional        pam_env.so
'''
            if self.mkhomedirci.getcurrvalue():
                pamconf[sess] += "session     required      " + \
                    "pam_mkhomedir.so skel=/etc/skel umask=0077\n"

        elif self.nslcd:
            sysauth = "/etc/pam.d/system-auth"
            passauth = "/etc/pam.d/password-auth"
            config = '''#%PAM-1.0
# This file is auto-generated.
# User changes will be destroyed the next time authconfig is run.
auth        required      pam_env.so
auth        required      pam_faillock.so preauth silent audit deny=5 \
unlock_time=900
auth        sufficient    pam_unix.so nullok try_first_pass
auth        requisite     pam_succeed_if.so uid >= 500 quiet
auth        sufficient    pam_krb5.so use_first_pass
auth        [default=die] pam_faillock.so authfail audit deny=5
auth        required      pam_deny.so

account     required      pam_faillock.so
account     required      pam_access.so
account     required      pam_unix.so broken_shadow
account     sufficient    pam_localuser.so
account     sufficient    pam_succeed_if.so uid < 500 quiet
account     [default=bad success=ok user_unknown=ignore] pam_krb5.so
account     required      pam_permit.so

password    requisite     pam_pwquality.so minlen=14 minclass=4 difok=7 \
dcredit=0 ucredit=0 lcredit=0 ocredit=0 retry=3
password    sufficient    pam_unix.so sha512 shadow \
nullok try_first_pass use_authtok remember=10
password    sufficient    pam_krb5.so use_authtok
password    required      pam_deny.so

session     optional      pam_keyinit.so revoke
session     required      pam_limits.so
'''
            if self.mkhomedirci.getcurrvalue():
                config += "session     optional      " + \
                    "pam_mkhomedir.so umask=0077\n"
            config += '''session     [success=1 default=ignore] \
pam_succeed_if.so service in crond quiet use_uid
session     required      pam_unix.so
session     optional      pam_krb5.so
'''
            pamconf[sysauth] = config
            pamconf[passauth] = config

        else:
            sysauth = "/etc/pam.d/system-auth"
            passauth = "/etc/pam.d/password-auth"
            config = '''#%PAM-1.0
# This file is auto-generated.
# User changes will be destroyed the next time authconfig is run.
auth        required      pam_env.so
auth        required      pam_faillock.so preauth silent audit deny=5 \
unlock_time=900
auth        sufficient    pam_unix.so nullok try_first_pass
auth        requisite     pam_succeed_if.so uid >= 500 quiet
auth        sufficient    pam_sss.so use_first_pass
auth        sufficient    pam_krb5.so use_first_pass
auth        [default=die] pam_faillock.so authfail audit deny=5
auth        required      pam_deny.so

account     required      pam_faillock.so
account     required      pam_access.so
account     required      pam_unix.so broken_shadow
account     sufficient    pam_localuser.so
account     sufficient    pam_succeed_if.so uid < 500 quiet
account     [default=bad success=ok user_unknown=ignore] pam_sss.so
account     [default=bad success=ok user_unknown=ignore] pam_krb5.so
account     required      pam_permit.so

password    requisite     pam_pwquality.so minlen=14 minclass=4 difok=7 \
dcredit=0 ucredit=0 lcredit=0 ocredit=0 retry=3
password    sufficient    pam_unix.so sha512 shadow \
nullok try_first_pass use_authtok remember=10
password    sufficient    pam_sss.so use_authtok
password    sufficient    pam_krb5.so use_authtok
password    required      pam_deny.so

session     optional      pam_keyinit.so revoke
session     required      pam_limits.so
-session    optional      pam_systemd.so
'''
            if self.mkhomedirci.getcurrvalue():
                config += "session     optional      " + \
                    "pam_mkhomedir.so umask=0077\n"
            config += '''session     [success=1 default=ignore] \
pam_succeed_if.so service in crond quiet use_uid
session     required      pam_unix.so
session     optional      pam_sss.so
session     optional      pam_krb5.so
'''
            pamconf[sysauth] = config
            pamconf[passauth] = config
        return pamconf

    def __fixpam(self, pamconf):
        '''Private method for writing PAM configuration files. This is a
        chainsaw-not-scalpel type of method; it simply rewrites the config
        files with the configuration.

        @param pamconf: Dict that resolves filenames to their intended configs
        @return: Bool Returns True if all settings are found or written
        @author: Eric Ball
        '''
        result = True
        try:
            for conffile in pamconf:
                result &= self.__writeFile(os.path.realpath(conffile),
                                           pamconf[conffile],
                                           [0, 0, 0644])
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
