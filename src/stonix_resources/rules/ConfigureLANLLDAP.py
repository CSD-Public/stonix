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
This rule configures LDAP and Kerberos to LANL specifications. Based on code
from LANL-stor.

@author: Eric Ball
@change: 2015/08/11 eball - Original implementation
@change: 2015/10/01 eball - Refactoring Red Hat code for sssd
@change: 2015/10/23 eball - Adding undo methods to new code in fix()
@change: 2015/11/16 eball - Moving RHEL6 back to nslcd
@change: 2016/01/25 eball - Changed pw policies to meet RHEL 7 STIG standards
@change: 2016/01/28 eball - Improved handling for LDAPServer CI
@change: 2016/11/14 eball - Moved PAM configurations to localize.py
@change: 2016/12/21 eball - Separated required packages for report, put package
    localization into individual methods
@change: 2017/01/12 eball - Modified __checkconf to read file contents within
    the method. This allows for more specific feedback on file content issues.
@change: 2017/11/06 bgonz12 - Changed service helper function calls to use
    camel case instead of all lowercase. 
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
from ..localize import AUTH_APT, ACCOUNT_APT, PASSWORD_APT, SESSION_APT, \
    SESSION_HOME_APT, AUTH_NSLCD, ACCOUNT_NSLCD, PASSWORD_NSLCD, \
    SESSION_NSLCD, SESSION_HOME_NSLCD, AUTH_YUM, ACCOUNT_YUM, PASSWORD_YUM, \
    SESSION_YUM, SESSION_HOME_YUM, AUTH_ZYPPER, ACCOUNT_ZYPPER, \
    PASSWORD_ZYPPER, SESSION_ZYPPER, SESSION_HOME_ZYPPER, \
    PWQUALITY_HIGH_REGEX, PWQUALITY_REGEX, CRACKLIB_HIGH_REGEX, \
    CRACKLIB_REGEX, PAMFAIL_REGEX, PAMTALLY_REGEX
from ..logdispatcher import LogPriority
from ..pkghelper import Pkghelper
from ..ServiceHelper import ServiceHelper


class ConfigureLANLLDAP(Rule):
    '''
    '''

    def __init__(self, config, enviro, logger, statechglogger):
        '''
        '''

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
            "localize.py. Alternatively, you may specify a server here. " + \
            "Please do not include \"ldap://\" at the beginning of the " + \
            "address."
        default = "ldap.lanl.gov"
        self.ldapci = self.initCi(datatype, key, instructions, default)

        datatype = "bool"
        key = "MAKEHOMEDIRS"
        instructions = "To have a home directory automatically created " + \
            "upon a user's first login, enable MAKEHOMEDIRS. Note that " + \
            "this may be required for GUI logins of LDAP accounts."
        default = True
        self.mkhomedirci = self.initCi(datatype, key, instructions, default)

        self.ch = CommandHelper(self.logger)
        self.ph = Pkghelper(self.logger, self.environ)
        self.sh = ServiceHelper(self.environ, self.logger)
        self.iditerator = 0
        self.nslcd = False
        self.pwcompliant = True
        self.lockcompliant = True
        self.sesscompliant = True
        self.acccompliant = True
        self.created1 = False
        self.created2 = False
        self.created3 = False
        self.localize()
        
    def localize(self):
        '''
        '''

        myos = self.environ.getostype().lower()
        if re.search("red hat.*?release 6", myos):
            self.password = PASSWORD_NSLCD
            self.auth = AUTH_NSLCD
            self.acct = ACCOUNT_NSLCD
            if self.mkhomedirci.getcurrvalue():
                self.session = SESSION_HOME_NSLCD
            else:
                self.session = SESSION_NSLCD
            self.nslcd = True
            self.pampassfile = "/etc/pam.d/password-auth-ac"
            self.pamauthfile = "/etc/pam.d/system-auth-ac"
        elif re.search("suse", myos):
            self.password = PASSWORD_ZYPPER
            self.auth = AUTH_ZYPPER
            self.acct = ACCOUNT_ZYPPER
            if self.mkhomedirci.getcurrvalue():
                self.session = SESSION_HOME_ZYPPER
            else:
                self.session = SESSION_ZYPPER
            self.pampassfile = "/etc/pam.d/common-password-pc"
            self.pamauthfile = "/etc/pam.d/common-auth-pc"
            self.pamacctfile = "/etc/pam.d/common-account-pc"
            self.pamsessfile = "/etc/pam.d/common-session-pc"
        elif re.search("debian|ubuntu", myos):
            self.password = PASSWORD_APT
            self.auth = AUTH_APT
            self.acct = ACCOUNT_APT
            if self.mkhomedirci.getcurrvalue():
                self.session = SESSION_HOME_APT
            else:
                self.session = SESSION_APT
            if re.search("ubuntu", myos):
                self.nslcd = True
            self.pampassfile = "/etc/pam.d/common-password"
            self.pamauthfile = "/etc/pam.d/common-auth"
            self.pamacctfile = "/etc/pam.d/common-account"
            self.pamsessfile = "/etc/pam.d/common-session"
        else:
            self.password = PASSWORD_YUM
            self.auth = AUTH_YUM
            self.acct = ACCOUNT_YUM
            if self.mkhomedirci.getcurrvalue():
                self.session = SESSION_HOME_YUM
            else:
                self.session = SESSION_YUM
            self.pampassfile = "/etc/pam.d/password-auth-ac"
            self.pamauthfile = "/etc/pam.d/system-auth-ac"

    def report(self):
        '''
        '''

        self.detailedresults = ""
        compliant = True
        debug = ""

        try:
#             if self.ph.manager in ("zypper"):
#                 return

            server = self.ldapci.getcurrvalue()
            self.ldapsettings = ""
            self.myos = self.environ.getostype().lower()
            self.majorVer = self.environ.getosver().split(".")[0]
            self.majorVer = int(self.majorVer)
            self.validLdap = True
            self.pwqeditor = ""
            self.usingpwquality, self.usingcracklib = False, False
            self.usingpamtally2, self.usingpamfail = False, False
            self.cracklibpkgs = ["libpam-cracklib",
                                 "cracklib"]
            self.pwqualitypkgs = ["libpam-pwquality",
                                  "pam_pwquality",
                                  "libpwquality"]
            self.packages = ["openldap-clients", "sssd",
                       "krb5-workstation", "pam_ldap", "nss-pam-ldapd",
                       "libpam-ldapd", "libpam-krb5",
                       "libnss-sss", "libpam-sss", "yast2-auth-client",
                       "sssd-krb5", "krb5"]
            if self.ph.manager == "dnf":
                self.packages.remove("pam_ldap")
                self.packages.remove("krb5")
                self.packages.remove("libpam-ldapd")
                self.packages.remove("libpam-krb5")
                self.packages.remove("libnss-sss")
                self.packages.remove("libpam-sss")
                self.packages.remove("yast2-auth-client")
            if self.ph.manager == "zypper":
                self.packages.remove("pam_ldap")
            for package in self.packages:
                if not self.ph.check(package) and \
                   self.ph.checkAvailable(package):
                    compliant = False
                    self.detailedresults += package + " is not installed\n"
            if not self.checkpasswordreqs():
                self.pwcompliant = False
                debug += "checkpasswordreqs method is False compliancy\n"
                compliant = False
            if not self.checkaccountlockout():
                self.lockcompliant = False
                debug += "checkaccountlockout method is False compliancy\n"
                compliant = False
            if not self.checkotherpam():
                self.ci4comp = False
                debug += "checkotherpam method is False compliancy\n"
                compliant = False
            if not self.nslcd:
                if self.ph.manager == "dnf":
                    sssdconfpath = "/etc/sssd/conf.d/sssd.conf"
                else:
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
                if not self.sh.auditService("sssd"):
                    compliant = False
                    self.detailedresults += "sssd service is not activated\n"
                if os.path.exists(sssdconfpath):
                    tmppath = sssdconfpath + ".tmp"
                    self.editor = KVEditorStonix(self.statechglogger,
                                                 self.logger, "conf",
                                                 sssdconfpath,
                                                 tmppath, sssdconfdict,
                                                 "present", "openeq")
                    if not self.editor.report():
                        compliant = False
                        self.detailedresults += "The correct settings were not found in " + \
                            sssdconfpath + "\n" + str(self.editor.fixables) + \
                            "\n"
                else:
                    compliant = False
                    self.detailedresults += sssdconfpath + " does not exist\n"
  
                nsswitchpath = "/etc/nsswitch.conf"
                self.nsswitchpath = nsswitchpath
                nsswitchsettings = ['passwd:    files compat sss',
                                    'shadow:    files compat sss',
                                    'group:     files compat sss']
                self.nsswitchsettings = nsswitchsettings
                if os.path.exists(nsswitchpath):
                    if not self.__checkconf(nsswitchpath, nsswitchsettings):
                        compliant = False
                    elif not checkPerms(nsswitchpath, [0, 0, 0644],
                                        self.logger):
                        compliant = False
                        self.detailedresults += "Settings in " + nsswitchpath + " are " + \
                            "correct, but the file's permissions are " + \
                            "incorrect\n"
                else:
                    compliant = False
                    self.detailedresults += nsswitchpath + " does not exist\n"
            else:
                if not self.sh.auditService("nslcd"):
                    compliant = False
                    self.detailedresults += "nslcd service is not activated\n"
  
                ldapfile = "/etc/nslcd.conf"
                self.ldapfile = ldapfile
                if re.search("ubuntu", self.myos):
                    gid = "gid nslcd"
                else:
                    gid = "gid ldap"
                if re.match('ldap.lanl.gov$', server):
                    self.ldapsettings = ['uri ldap://' + server,
                                         'base dc=lanl,dc=gov',
                                         'base passwd ou=unixsrv,dc=lanl,' +
                                         'dc=gov',
                                         'uid nslcd',
                                         gid,
                                         'ssl no',
                                         'nss_initgroups_ignoreusers root']
                else:
                    serversplit = server.split(".")
                    if len(serversplit) != 3:
                        compliant = False
                        self.validLdap = False
                        error = "Custom LDAPServer does not follow " + \
                            "convention of \"[server].[domain].[tld]\". " + \
                            "ConfigureLANLLDAP cannot automate your LDAP " + \
                            "setup."
                        self.logger.log(LogPriority.ERROR, error)
                        self.detailedresults += "ERROR: " + error + "\n"
                    else:
                        self.ldapsettings = ['uri ldap://' + server,
                                             'base dc=' + serversplit[1] +
                                             ",dc=" + serversplit[2],
                                             'uid nslcd',
                                             gid,
                                             'ssl no',
                                             'nss_initgroups_ignoreusers root']
                ldapsettings = self.ldapsettings
                if os.path.exists(ldapfile):
                    if not self.__checkconf(ldapfile, ldapsettings):
                        compliant = False
                    elif not checkPerms(ldapfile, [0, 0, 0600], self.logger):
                        compliant = False
                        self.detailedresults += "Settings in " + ldapfile + " are " + \
                            "correct, but the file's permissions are " + \
                            "incorrect\n"
                else:
                    compliant = False
                    self.detailedresults += ldapfile + " does not exist.\n"
  
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
                    if not self.__checkconf(nsswitchpath, nsswitchsettings):
                        compliant = False
                    elif not checkPerms(nsswitchpath, [0, 0, 0644],
                                        self.logger):
                        compliant = False
                        self.detailedresults += "Settings in " + nsswitchpath + " are " + \
                            "correct, but the file's permissions are " + \
                            "incorrect\n"
                else:
                    compliant = False
                    self.detailedresults += nsswitchpath + " does not exist\n"
  
                # On Ubuntu, Unity/LightDM requires an extra setting to add an
                # option to the login screen for network users
  
                if re.search("ubuntu", self.myos):
                    # search for versions 16-19 (may have to update later if they change
                    # the way lightdm is configured again in the future..
                    if re.search('[1][6-9]\.', self.environ.getosver(), re.IGNORECASE):
                        lightdmconf = "/etc/lightdm/lightdm.conf.d/50-unity-greeter.conf"
                        self.lightdmconf = lightdmconf
                        tmppath = lightdmconf + ".tmp"
                        manLogin = {"Seat:*": {"greeter-session": "unity-greeter",
                                               "greeter-show-manual-login": "true"}}
                        self.editor2 = KVEditorStonix(self.statechglogger,
                                                      self.logger, "tagconf",
                                                      lightdmconf,
                                                      tmppath, manLogin,
                                                      "present", "closedeq")
                    else:
                        lightdmconf = "/etc/lightdm/lightdm.conf"
                        self.lightdmconf = lightdmconf
                        tmppath = lightdmconf + ".tmp"
                        manLogin = {"Seat:*": {"greeter-session": "unity-greeter",
                                               "greeter-show-manual-login": "true"}}
                        self.editor2 = KVEditorStonix(self.statechglogger,
                                                      self.logger, "tagconf",
                                                      lightdmconf,
                                                      tmppath, manLogin,
                                                      "present", "closedeq")
                    if not self.editor2.report():
                        compliant = False
                        self.detailedresults += '"greeter-show-manual-login=true" not ' + \
                            "present in " + lightdmconf + "\n"

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

    def __checkconf(self, filepath, settings):
        '''
        Private method to audit a conf file to ensure that it contains all
        of the required directives.

        @param file: configuration file to load current settings from
        @param settings: list of settings that should be present in the conf
        @return: Bool Returns True if all settings are present.
        @author: Eric Ball
        '''

        if os.path.exists(filepath):
            contents = readFile(filepath, self.logger)
        else:
            debug = "File passed to __checkconf does not exist"
            self.logger.log(LogPriority.DEBUG, debug)
            return False
        if len(contents) == 0:
            debug = "File passed to __checkconf is empty"
            self.logger.log(LogPriority.DEBUG, debug)
            return False
        if len(settings) == 0:
            debug = "Settings list passed to __checkconf is empty"
            self.logger.log(LogPriority.DEBUG, debug)
            return False

        contentsSplit = []
        comment = re.compile('^#')
        results = ""
        foundAll = True
        for line in contents:
            if not comment.match(line):
                contentsSplit.append(line.split())
        for setting in settings:
            if setting == "" or comment.match(setting):
                continue
            settingOpts = setting.split("|")
            found = False
            for opt in settingOpts:
                if opt.split() in contentsSplit:
                    found = True
            if not found:
                results += 'Could not find line "' + settingOpts[0].strip() + \
                    '"'
                for opt in settingOpts[1:]:
                    results += ' or line "' + opt + '"'
                results += " in file " + filepath + "\n"
                foundAll = False
        self.detailedresults += results
        return foundAll

    def fix(self):
        '''
        '''

        self.detailedresults = ""
        success = True

        try:
#             if self.ph.manager == "zypper":
#                 return
            if not self.ci.getcurrvalue() and self.validLdap:
                return

            self.iditerator = 0
            eventlist = self.statechglogger.findrulechanges(self.rulenumber)
            for event in eventlist:
                self.statechglogger.deleteentry(event)
            if os.path.exists(self.pampassfile):
                createFile(self.pampassfile + ".backup", self.logger)
            if os.path.exists(self.pamauthfile):
                createFile(self.pamauthfile + ".backup", self.logger)
            if self.ph.manager not in ("yum", "dnf"):
                if os.path.exists(self.pamsessfile):
                    createFile(self.pamsessfile + ".backup", self.logger)
                if os.path.exists(self.pamacctfile):
                    createFile(self.pamacctfile + ".backup", self.logger)
            for package in self.packages:
                if not self.ph.check(package):
                    if self.ph.checkAvailable(package):
                        if not self.ph.install(package):
                            self.rulesuccess = False
                            self.detailedresults += "Unable to install " + \
                                package + ".  Will not continue with fix\n"
                            self.formatDetailedResults("fix", self.rulesuccess,
                                                       self.detailedresults)
                            self.logdispatch.log(LogPriority.INFO,
                                                 self.detailedresults)
                            return False
                        else:
                            self.iditerator += 1
                            myid = iterate(self.iditerator, self.rulenumber)
                            event = {"eventtype": "pkghelper",
                                     "pkgname": package,
                                     "startstate": "removed",
                                     "endstate": "installed"}
                            self.statechglogger.recordchgevent(myid, event)
            if not self.pwcompliant:
                if self.usingpwquality:
                    self.password = re.sub("pam_cracklib\.so", "pam_pwquality.so",
                                       self.password)
                    if self.environ.getsystemfismacat() == "high":
                        self.password = re.sub("minlen=8", "minlen=14", self.password)
                        self.password = re.sub("minclass=3", "minclass=4", self.password)
                        regex = PWQUALITY_HIGH_REGEX
                    else:
                        regex = PWQUALITY_REGEX
                    if self.pwqinstalled:
                        if not self.setpasswordsetup(regex):
                            success = False
                        elif self.ph.manager in ("yum", "dnf"):
                            self.sesscompliant = True
                            self.acccompliant = True
                            self.lockcompliant = True
                    else:
                        if not self.setpasswordsetup(regex, self.pwqualitypkgs):
                            success = False
                        elif self.ph.manager in ("yum", "dnf"):
                            self.sesscompliant = True
                            self.acccompliant = True
                            self.lockcompliant = True
                elif self.usingcracklib:
                    self.password = re.sub("pam_pwquality\.so", "pam_cracklib.so",
                                       self.password)
                    if self.environ.getsystemfismacat() == "high":
                        self.password = re.sub("minlen=8", "minlen=14", self.password)
                        self.password = re.sub("minclass=3", "minclass=4", self.password)
                        regex = CRACKLIB_HIGH_REGEX
                    else:
                        regex = CRACKLIB_REGEX
                    if self.clinstalled:
                        if not self.setpasswordsetup(regex):
                            success = False
                        elif self.ph.manager in ("yum", "dnf"):
                            self.sesscompliant = True
                            self.acccompliant = True
                    else:
                        if not self.setpasswordsetup(regex, self.cracklibpkgs):
                            success = False
                        elif self.ph.manager in ("yum", "dnf"):
                            self.sesscompliant = True
                            self.acccompliant = True
                else:
                    error = "Could not find pwquality/cracklib pam " + \
                        "module. Fix failed."
                    self.logger.log(LogPriority.ERROR, error)
                    self.detailedresults += error + "\n"
                    return False
            if not self.lockcompliant:
                if self.usingpamfail:
                    regex = PAMFAIL_REGEX
                    if not self.setaccountlockout(regex):
                        success = False
                        self.detailedresults += "Unable to configure pam " + \
                            "for faillock\n"
                    elif self.ph.manager in ("yum", "dnf"):
                        self.sesscompliant = True
                        self.acccompliant = True
                elif self.usingpamtally2:
                    regex = PAMTALLY_REGEX
                    if not self.setaccountlockout(regex):
                        success = False
                        self.detailedresults += "Unable to configure pam " + \
                            "for pam_tally2\n"
                    elif self.ph.manager in ("yum", "dnf"):
                        self.sesscompliant = True
                        self.acccompliant = True
                else:
                    self.detailedresults += "There is no account lockout " + \
                        "program available for this system\n"
                    success = False
            if not self.sesscompliant:
                success = self.setotherpamsession()
            if not self.acccompliant:
                success = self.setotherpamaccount()
            if not self.__fixnss(self.nsswitchpath, self.nsswitchsettings):
                success = False
                self.detailedresults += "Problem writing new contents to " + \
                    self.nsswitchpath + "\n"
 
            if not self.nslcd:
                if not self.__fixsssd():
                    success = False
                    self.detailedresults += "Failed to write good configuration to " + \
                        self.sssdconfpath + "\n"
                if not self.sh.disableservice("nscd"):
                    warning = "Failed to disable nscd. This may require " + \
                        "an administrator to disable this service after a " + \
                        "reboot."
                    self.logger.log(LogPriority.WARNING, warning)
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
                        warning = "Failed to reload sssd service; the " + \
                            "system should be rebooted to finalize the " + \
                            "configuration."
                        self.logger.log(LogPriority.WARNING, warning)
                if not self.sh.auditService("sssd"):
                    if not self.sh.enableservice("sssd"):
                        success = False
                        self.detailedresults += "Failed to enable sssd service\n"
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
                    # Back up detailedresults, so that we can ignore the
                    # report-focused output from checkconf()
                    results = self.detailedresults
                    for setting in nonkv:
                        if not self.__checkconf(ldapfile, [setting]):
                            ldapconf.append(setting + "\n")
                    self.detailedresults = results
  
                    if not self.__writeFile(ldapfile, "".join(ldapconf),
                                            [0, 0, 0600], self.created3):
                        success = False
                        self.detailedresults += "Problem writing new contents to " + \
                            ldapfile
                else:
                    createFile(ldapfile, self.logger)
                    self.created3 = True
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    event = {"eventtype": "creation", "filepath": ldapfile}
                    self.statechglogger.recordchgevent(myid, event)
  
                    if not self.__writeFile(ldapfile, "\n".join(ldapsettings),
                                            [0, 0, 0600], self.created3):
                        success = False
                        self.detailedresults += "Problem writing new contents to " + \
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
            self.rulesuccess = success
        except AssertionError:
            if not self.ci.getcurrvalue():
                self.detailedresults = "Primary CI for this rule is not " + \
                    "enabled"
            elif not self.validLdap:
                self.detailedresults = "Invalid LDAP server address"
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
        '''
        Private method made specifically for fixing the nsswitch.conf file

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
                return self.__writeFile(path, nsConf, [0, 0, 0644],
                                        self.created1)
            else:
                createFile(path, self.logger)
                self.created1 = True
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                event = {"eventtype": "creation", "filepath": path}
                self.statechglogger.recordchgevent(myid, event)
                return self.__writeFile(path, "\n".join(settings),
                                        [0, 0, 0644], self.created1)
        except Exception:
            raise

    def __fixsssd(self):
        '''
        '''

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
            self.created2 = True
            self.iditerator += 1
            myid = iterate(self.iditerator, self.rulenumber)
            event = {"eventtype": "creation",
                     "filepath": sssdconfpath}
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
            return self.__writeFile(sssdconfpath, sssdconf, [0, 0, 0600],
                                    self.created2)

    def checkpasswordreqs(self):
        '''
        Method to check which password checking program the system
        is or should be using.

        @author: dwalker
        @return: bool
        '''

        self.pwqinstalled, self.clinstalled = False, False
        self.pwqpkg, self.crackpkg = "", ""
        '''Check if either pam_pwquality or cracklib are installed'''
        for pkg in self.pwqualitypkgs:
            if self.ph.check(pkg):
                self.pwqinstalled = True
        for pkg in self.cracklibpkgs:
            if self.ph.check(pkg):
                self.clinstalled = True
        '''if pwquality is installed we check to see if it's configured'''
        if self.pwqinstalled:
            '''If it's not, since it is already installed we want to
            configure pwquality and not cracklib since it's better'''
            if not self.checkpasswordsetup("pwquality"):
                self.usingpwquality = True
                self.detailedresults += "System is using pwquality but " + \
                    "it's not configured properly in PAM\n"
                return False
            else:
                '''pwquality is installed and configured'''
                return True
        elif self.clinstalled:
            '''Although we want pwquality over cracklib, if cracklib is
            already installed and configured correctly, we will go with that'''
            if not self.checkpasswordsetup("cracklib"):
                '''cracklib is not configured correctly so we check
                if pwquality is available for install'''
                for pkg in self.pwqualitypkgs:
                    if self.ph.checkAvailable(pkg):
                        self.usingpwquality = True
                        self.pwqpkg = pkg
                        self.detailedresults += "System has cracklib " + \
                            "installed but is not configured properly with " + \
                            "PAM and pwquality is available for install. " + \
                            "will install and configure pwquality\n"
                        return False
                self.detailedresults += "cracklib installed but not " + \
                    "configured properly\n"
                self.usingcracklib = True
            else:
                '''cracklib is installed and configured'''
                return True
        else:
            '''neither pwquality or cracklib is installed, we prefer
            pwquality so we check if it's available for install'''
            for pkg in self.pwqualitypkgs:
                if self.ph.checkAvailable(pkg):
                    self.usingpwquality = True
                    self.pwqpkg = pkg
                    self.detailedresults += "pwquality is available for " + \
                        "install\n"
                    return False
            '''pwquality wasn't available for install, check for cracklib'''
            for pkg in self.cracklibpkgs:
                if self.ph.checkAvailable(pkg):
                    self.usingcracklib = True
                    self.crackpkg = pkg
                    self.detailedresults += "cracklib is available for " + \
                        "install\n"
                    return False
            return False
    
    def checkpasswordsetup(self, package):
        '''
        Method called from within checkpasswordreqs method

        @author: dwalker
        @param package: pwquality or cracklib
        @return: bool
        '''

        compliant = True
        if package == "pwquality":
            self.password = re.sub("pam_cracklib\.so", "pam_pwquality.so",
                                       self.password)
            if self.environ.getsystemfismacat() == "high":
                self.password = re.sub("minlen=8", "minlen=14", self.password)
                self.password = re.sub("minclass=3", "minclass=4", self.password)
                regex1 = PWQUALITY_HIGH_REGEX
            else:
                regex1 = PWQUALITY_REGEX
            if not self.chkpwquality():
                compliant = False
        elif package == "cracklib":
            self.password = re.sub("pam_pwquality\.so", "pam_cracklib.so",
                                       self.password)
            if self.environ.getsystemfismacat() == "high":
                self.password = re.sub("minlen=8", "minlen=14", self.password)
                self.password = re.sub("minclass=3", "minclass=4", self.password)
                regex1 = CRACKLIB_HIGH_REGEX
            else:
                regex1 = CRACKLIB_REGEX
        regex2 = "^password[ \t]+sufficient[ \t]+pam_unix.so sha512 shadow " + \
            "try_first_pass use_authtok remember=10"
        pamfiles = []
        if self.ph.manager in ("yum", "dnf"):
            pamfiles.append(self.pamauthfile)
            pamfiles.append(self.pampassfile)
        else:
            pamfiles.append(self.pampassfile)
        for pamfile in pamfiles:
            found1, found2 = False, False
            if not os.path.exists(pamfile):
                self.detailedresults += pamfile + " doesn't exist\n"
                compliant = False
            else:
                if not checkPerms(pamfile, [0, 0, 0o644], self.logger):
                    self.detailedresults += "Permissions aren't correct " + \
                        "on " + pamfile + "\n"
                    compliant = False
                contents = readFile(pamfile, self.logger)
                if not contents:
                    self.detailedresults += pamfile + " is blank\n"
                    compliant = False
                else:
                    for line in contents:
                        if re.search(regex1, line.strip()):
                            found1 = True
                        if re.search(regex2, line.strip()):
                            found2 = True
                    if not found1 or not found2:
                        self.detailedresults += pamfile + " doesn't " + \
                            "contain correct password restrictions portion\n"
                        compliant = False
        return compliant

    def setpasswordsetup(self, regex1, pkglist = ""):
        '''
        '''

        regex2 = "^password[ \t]+sufficient[ \t]+pam_unix.so sha512 shadow " + \
            "try_first_pass use_authtok remember=10"
        success = True
        pamfiles = []
        installed = False
        if pkglist:
            for pkg in pkglist:
                if self.ph.check(pkg):
                    installed = True
                    break
        else:
            installed = True
        if not installed:
            for pkg in pkglist:
                if self.ph.checkAvailable(pkg):
                    if not self.ph.install(pkg):
                        self.detailedresults += "Unable to install pkg " + \
                            pkg + "\n" 
                        return False
                    else:
                        installed = True
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        comm = self.ph.getRemove() + pkg
                        event = {"eventtype": "commandstring",
                                 "command": comm}
                        self.statechglogger.recordchgevent(myid, event)
                        break
        if not installed:
            self.detailedresults += "No password checking program available\n"
            return False
        if self.usingpwquality:
            if not self.setpwquality():
                success = False
        if self.ph.manager in ("yum", "dnf"):
            writecontents = self.auth + "\n" + self.acct + "\n" + \
                self.password + "\n" + self.session
            pamfiles.append(self.pamauthfile)
            pamfiles.append(self.pampassfile)
        else:
            writecontents = self.password
            pamfiles.append(self.pampassfile)
        for pamfile in pamfiles:
            if not os.path.exists(pamfile):
                self.detailedresults += pamfile + " doesn't exist.\n" + \
                    "Stonix will not attempt to create this file " + \
                    "and the fix for the this rule will not continue\n"
                return False
        '''Check permissions on pam file(s)'''
        for pamfile in pamfiles:
            if not checkPerms(pamfile, [0, 0, 0o644], self.logger):
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                if not setPerms(pamfile, [0, 0, 0o644], self.logger, self.statechglogger, myid):
                    success = False
                    self.detailedresults += "Unable to set " + \
                        "correct permissions on " + pamfile + "\n"
            contents = readFile(pamfile, self.logger)
            found1, found2 = False, False
            for line in contents:
                if re.search(regex1, line.strip()):
                    found1 = True
                if re.search(regex2, line.strip()):
                    found2 = True
            if not found1 or not found2:
                tmpfile = pamfile + ".tmp"
                if writeFile(tmpfile, writecontents, self.logger):
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    event = {'eventtype': 'conf',
                             'filepath': pamfile}
                    self.statechglogger.recordchgevent(myid, event)
                    self.statechglogger.recordfilechange(pamfile, tmpfile, myid)
                    os.rename(tmpfile, pamfile)
                    os.chown(pamfile, 0, 0)
                    os.chmod(pamfile, 0o644)
                    resetsecon(pamfile)
                else:
                    self.detailedresults += "Unable to write to " + pamfile + "\n"
                    success = False
        return success

    def checkaccountlockout(self):
        '''
        Method to determine which account locking program to
        use if any.

        @author: dwalker
        @return: bool
        '''

        which = "/usr/bin/which "
        cmd1 = which + "faillock"
        cmd2 = which + "pam_tally2"
        ch = CommandHelper(self.logger)
        pamfiles = []
        compliant = True
        if ch.executeCommand(cmd1):
            debug = "ran " + cmd1 + " successfully\n"
            self.logger.log(LogPriority.DEBUG, debug)
            if ch.getReturnCode() == 0:
                debug = "return code of 0 and using faillock\n"
                self.logger.log(LogPriority.DEBUG, debug)
                self.usingpamfail = True
            elif ch.executeCommand(cmd2):
                debug = "ran " + cmd2 + " successfully\n"
                self.logger.log(LogPriority.DEBUG, debug)
                if ch.getReturnCode() == 0:
                    debug = "return code of 0 and using pam_tally2\n"
                    self.logger.log(LogPriority.DEBUG, debug)
                    self.usingpamtally2 = True
            else:
                self.detailedresults += "There is no account " + \
                        "locking program available for this " + \
                        "distribution\n"
                return False
        elif ch.executeCommand(cmd2):
                debug = "ran " + cmd2 + " successfully\n"
                self.logger.log(LogPriority.DEBUG, debug)
                if ch.getReturnCode() == 0:
                    debug = "return code of 0 and using pam_tally2\n"
                    self.logger.log(LogPriority.DEBUG, debug)
                    self.usingpamtally2 = True
                else:
                    self.detailedresults += "There is no account " + \
                        "locking program available for this " + \
                        "distribution\n"
                    return False
        else:
            self.detailedresults += "There is no account " + \
                "locking program available for this " + \
                "distribution\n"
            return False
        if self.usingpamfail:
            regex = PAMFAIL_REGEX
        elif self.usingpamtally2:
            regex = PAMTALLY_REGEX
        if self.ph.manager in("yum", "dnf"):
            pamfiles.append(self.pamauthfile)
            pamfiles.append(self.pampassfile)
        else:
            pamfiles.append(self.pamauthfile)
        for pamfile in pamfiles:
            found = False
            if not os.path.exists(pamfile):
                self.detailedresults += "Critical pam file " + pamfile + \
                    "doesn't exist\n"
                compliant = False
            else:
                if not checkPerms(pamfile, [0, 0, 0o644], self.logger):
                    self.detailedresults += "Permissions aren't correct " + \
                        "on " + pamfile + "\n"
                    self.ci3comp = False
                    compliant = False
                contents = readFile(pamfile, self.logger)
                if not contents:
                    self.detailedresults += pamfile + " is blank\n"
                    self.ci3comp = False
                    compliant = False
                else:
                    for line in contents:
                        if re.search(regex, line.strip()):
                            found = True
                    if not found:
                        self.detailedresults += pamfile + " doesn't " + \
                            "contain correct account locking portion\n"
                        self.ci3comp = False
                        compliant = False
        return compliant

    def setaccountlockout(self, regex):
        '''
        '''

        success = True
        pamfiles = []
        if self.ph.manager in ("yum", "dnf"):
            pamfiles.append(self.pamauthfile)
            pamfiles.append(self.pampassfile)
            writecontents = self.auth + "\n" + self.acct + "\n" + \
                        self.password + "\n" + self.session
        else:
            pamfiles.append(self.pamauthfile)
            writecontents = self.auth
        for pamfile in pamfiles:
            if not os.path.exists(pamfile):
                self.detailedresults += pamfile + " doesn't exist.\n" + \
                    "Stonix will not attempt to create this file " + \
                    "and the fix for the this rule will not continue\n"
                return False
        '''Check permissions on pam file(s)'''
        for pamfile in pamfiles:
            if not checkPerms(pamfile, [0, 0, 0o644], self.logger):
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                if not setPerms(pamfile, [0, 0, 0o644], self.logger, self.statechglogger, myid):
                    success = False
                    self.detailedresults += "Unable to set " + \
                        "correct permissions on " + pamfile + "\n"
            contents = readFile(pamfile, self.logger)
            found = False
            for line in contents:
                if re.search(regex, line.strip()):
                    found = True
            if not found:
                tmpfile = pamfile + ".tmp"
                if writeFile(tmpfile, writecontents, self.logger):
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    event = {'eventtype': 'conf',
                             'filepath': pamfile}
                    self.statechglogger.recordchgevent(myid, event)
                    self.statechglogger.recordfilechange(pamfile, tmpfile, myid)
                    os.rename(tmpfile, pamfile)
                    os.chown(pamfile, 0, 0)
                    os.chmod(pamfile, 0o644)
                    resetsecon(pamfile)
                else:
                    self.detailedresults += "Unable to write to " + pamfile + "\n"
                    success = False
        return success
    
    def checkotherpam(self):
        '''
        '''

        pamfiles = []
        compliant = True
        compliant1 = True
        compliant2 = True
        '''check session pam portion'''
        if self.ph.manager in ("yum", "dnf"):
            pamfiles.append(self.pamauthfile)
            pamfiles.append(self.pampassfile)
        else:
            pamfiles.append(self.pamsessfile)
        for pamfile in pamfiles:
            if not os.path.exists(pamfile):
                self.detailedresults += pamfile + " doesn't exist\n"
                compliant1 = False
            else:
                if not checkPerms(pamfile, [0, 0, 0o644], self.logger):
                    self.detailedresults += "Permissions aren't correct " + \
                        "on " + pamfile + "\n"
                    compliant1 = False
                contents = readFile(pamfile, self.logger)
                if not contents:
                    self.detailedresults += pamfile + " is blank\n"
                    compliant1 = False
                else:
                    tempstring = ''''''
                    for line in contents:
                        if re.search("^session", line.strip()) or \
                            re.search("^-session", line.strip()):
                            tempstring += line
                    if tempstring != self.session:
                        self.detailedresults += pamfile + " doesn't " + \
                            "contain correct session portion\n"
                        compliant1 = False
        pamfiles = []
        if not compliant1:
            self.sesscompliant = False
        '''check account pam portion'''
        if self.ph.manager in ("yum", "dnf"):
            pamfiles.append(self.pamauthfile)
            pamfiles.append(self.pampassfile)
        else:
            pamfiles.append(self.pamacctfile)
        for pamfile in pamfiles:
            if not os.path.exists(pamfile):
                self.detailedresults += pamfile + " doesn't exist\n"
                compliant2 = False
            else:
                if not checkPerms(pamfile, [0, 0, 0o644], self.logger):
                    self.detailedresults += ""
                    compliant2 = False
                contents = readFile(pamfile, self.logger)
                if not contents:
                    self.detailedresults += pamfile + " is blank\n"
                    compliant2 = False
                else:
                    tempstring = ''''''
                    for line in contents:
                        if re.search("^account", line.strip()):
                            tempstring += line
                    if tempstring != self.acct:
                        self.detailedresults += pamfile + " doesn't " + \
                            "contain correct account portion\n"
                        compliant2 = False
        if not compliant2:
            self.acccompliant = False
        if not compliant1 and compliant2:
            compliant = False
        return compliant
    
    def setotherpamsession(self):
        '''
        '''

        success = True
        pamfiles = []
        if self.ph.manager in ("yum", "dnf"):
            writecontents = self.auth + "\n" + self.acct + "\n" + \
                self.password + "\n" + self.session
            pamfiles.append(self.pamauthfile)
            pamfiles.append(self.pampassfile)
        else:
            writecontents = self.session
            pamfiles.append(self.pamsessfile)
        for pamfile in pamfiles:
            if not os.path.exists(pamfile):
                self.detailedresults += pamfile + " doesn't exist.\n" + \
                    "Stonix will not attempt to create this file " + \
                    "and the fix for the this rule will not continue\n"
                return False
        for pamfile in pamfiles:
            if not checkPerms(pamfile, [0, 0, 0o644], self.logger):
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                if not setPerms(pamfile, [0, 0, 0o644], self.logger, self.statechglogger, myid):
                    success = False
                    self.detailedresults += "Unable to set " + \
                        "correct permissions on " + pamfile + "\n"
            tmpfile = pamfile + ".tmp"
            if writeFile(tmpfile, writecontents, self.logger):
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                event = {'eventtype': 'conf',
                         'filepath': pamfile}
                self.statechglogger.recordchgevent(myid, event)
                self.statechglogger.recordfilechange(pamfile, tmpfile, myid)
                os.rename(tmpfile, pamfile)
                os.chown(pamfile, 0, 0)
                os.chmod(pamfile, 0o644)
                resetsecon(pamfile)
            else:
                self.detailedresults += "Unable to write to " + pamfile + "\n"
                success = False
        return success
    
    def setotherpamaccount(self):
        '''
        '''

        success = True
        pamfiles = []
        if self.ph.manager in ("yum", "dnf"):
            writecontents = self.auth + "\n" + self.acct + "\n" + \
                self.password + "\n" + self.session
            pamfiles.append(self.pamauthfile)
            pamfiles.append(self.pampassfile)
        else:
            writecontents = self.acct
            pamfiles.append(self.pamacctfile)
        for pamfile in pamfiles:
            if not os.path.exists(pamfile):
                self.detailedresults += pamfile + " doesn't exist.\n" + \
                    "Stonix will not attempt to create this file " + \
                    "and the fix for the this rule will not continue\n"
                return False
        for pamfile in pamfiles:
            if not checkPerms(pamfile, [0, 0, 0o644], self.logger):
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                if not setPerms(pamfile, [0, 0, 0o644], self.logger, self.statechglogger, myid):
                    success = False
                    self.detailedresults += "Unable to set " + \
                        "correct permissions on " + pamfile + "\n"
            tmpfile = pamfile + ".tmp"
            if writeFile(tmpfile, writecontents, self.logger):
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                event = {'eventtype': 'conf',
                         'filepath': pamfile}
                self.statechglogger.recordchgevent(myid, event)
                self.statechglogger.recordfilechange(pamfile, tmpfile, myid)
                os.rename(tmpfile, pamfile)
                os.chown(pamfile, 0, 0)
                os.chmod(pamfile, 0o644)
                resetsecon(pamfile)
            else:
                self.detailedresults += "Unable to write to " + pamfile + "\n"
                success = False
        return success
    
    def chkpwquality(self):
        '''
        '''

        compliant = True
        pwqfile = "/etc/security/pwquality.conf"
        if os.path.exists(pwqfile):
            tmpfile = pwqfile + ".tmp"
            if self.environ.getsystemfismacat() == "high":
                data = {"difok": "7",
                        "minlen": "14",
                        "dcredit": "0",
                        "ucredit": "0",
                        "lcredit": "0",
                        "ocredit": "0",
                        "maxrepeat": "3",
                        "minclass": "4"}
            else:
                data = {"difok": "7",
                        "minlen": "8",
                        "dcredit": "0",
                        "ucredit": "0",
                        "lcredit": "0",
                        "ocredit": "0",
                        "maxrepeat": "3",
                        "minclass": "3"}
            self.pwqeditor = KVEditorStonix(self.statechglogger, self.logger,
                                            "conf", pwqfile, tmpfile, data,
                                            "present", "openeq")
            if not self.pwqeditor.report():
                compliant = False
                self.detailedresults += "Not all correct contents were " + \
                    "found in " + pwqfile + "\n"
        else:
            compliant = False
            self.detailedresults += "System is using pwquality and " + \
                "crucial file /etc/security/pwquality doesn't exist\n"
        return compliant
    
    def setpwquality(self):
        '''
        '''

        success = True
        created = False
        pwqfile = "/etc/security/pwquality.conf"
        if not os.path.exists(pwqfile):
            createFile(pwqfile, self.logger)
            self.iditerator += 1
            myid = iterate(self.iditerator, self.rulenumber)
            event = {'eventtype': 'creation',
                     'filepath': pwqfile}
            self.statechglogger.recordchgevent(myid, event)
            created = True
        tmpfile = pwqfile + ".tmp"
        if self.environ.getsystemfismacat() == "high":
            data = {"difok": "7",
                    "minlen": "14",
                    "dcredit": "0",
                    "ucredit": "0",
                    "lcredit": "0",
                    "ocredit": "0",
                    "maxrepeat": "3",
                    "minclass": "4"}
        else:
            data = {"difok": "7",
                    "minlen": "8",
                    "dcredit": "0",
                    "ucredit": "0",
                    "lcredit": "0",
                    "ocredit": "0",
                    "maxrepeat": "3",
                    "minclass": "3"}
        self.pwqeditor = KVEditorStonix(self.statechglogger, self.logger,
                                        "conf", pwqfile, tmpfile, data,
                                        "present", "openeq")
        self.pwqeditor.report()
        if self.pwqeditor.fixables:
            if self.pwqeditor.fix():
                if not created:
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    self.pwqeditor.setEventID(myid)
                if not self.pwqeditor.commit():
                    success = False
                    self.detailedresults += "Unable to correct " + pwqfile + "\n"
            else:
                success = False
                self.detailedresults += "Unable to correct " + pwqfile + "\n"
        return success

    def __writeFile(self, path, contents, perms, created):
        '''
        '''

        try:
            tmppath = path + ".tmp"
            success = writeFile(tmppath, contents, self.logger)
            if not created:
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                event = {"eventtype": "conf",
                         "filepath": path}
                self.statechglogger.recordchgevent(myid, event)
                self.statechglogger.recordfilechange(path, tmppath, myid)
            os.rename(tmppath, path)
            success &= setPerms(path, perms, self.logger)
            resetsecon(path)
            return success
        except Exception:
            raise
