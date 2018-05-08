'''
Created on Oct 18, 2012
###############################################################################
#                                                                             #
# Copyright 2012-2018.  Los Alamos National Security, LLC. This material was  #
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

This module contains variables used to localize STONIX behavior for a given
site. It is intended to be edited by the personnel packaging STONIX for use and
is not intended to be modified by systems administrators or end users.

These variables will be referenced directly by STONIX with only nominal safety
checks. Mistakes made in this file may lead to errors in STONIX behavior or
run-time failures. Pay attention to comments documenting both the content and
format of entries.

@author: dkennel
@change: 2014/07/14 - ekkehard - added foo.bar.com = FOO.BAR.COM to
KERB5
@change: 2014/08/20 - Added version variable to here and updated all locations
that access the version variable to use this copy.
@change: 2015/03/01 - ekkehard - incremented STONIXVERSION = '0.8.15'
@change: 2015/04/07 - ekkehard - incremented STONIXVERSION = '0.8.16'
@change: 2015/12/07 - eball Renamed KERB5 to MACKRB5 and KRB5 to LINUXKRB5
@change: 2016/02/03 - ekkehard - incremented STONIXVERSION = '0.9.5'
@change: 2016/05/05 - eball Add LOCALDOMAINS for AuditFirefoxUsage(84)
@change: 2017/03/07 - dkennel add FISMACAT for FISMA/FIPS 199 risk category
@change: 2017/07/07 - ekkehard - incremented STONIXVERSION = '0.9.10'
@change: 2017/10/10 - ekkehard - incremented STONIXVERSION = '0.9.13'
@change: 2017/11/13 - ekkehard - incremented STONIXVERSION = '0.9.14'
@change: 2018/02/06 - ekkehard - incremented STONIXVERSION = '0.9.16'
@change: 2018/02/06 - ekkehard - incremented STONIXVERSION = '0.9.17'
@change: 2018/04/11 - ekkehard - incremented STONIXVERSION = '0.9.18'
'''

FISMACAT = 'low'

# The Version number of the STONIX application. Modify this only if you need to
# define a local version number. Caution should be used to not conflict with
# the upstream versioning numbers. The version is handled as a string so
# arbitrary values are fine. A recommended local version might look like this:
# 1.2.2-local3 or just 1.2.2-3 or 1.2.2.3

# Variable Type: String
STONIXVERSION = '0.9.18'

# The report server should be a string containing a valid FQDN or IP address
# for the host that STONIX should upload it's run report XML data to.
REPORTSERVER = 'foo.bar.com'

# If you are not using a central report server then set the value of
# sendreports to False. Please note no quotes.
# sendreports = False
SENDREPORTS = True

# The SoftwarePatching rule will check to see if local update sources are being
# used. If you have local update sources list them here. This check will be
# skipped if the list is empty. The list is in python list format:
# updateservers = ['myserver1.mydomain.tld', 'myserver2.mydomain.tld']
UPDATESERVERS = ['foo.bar.com',
                 'foo.bar.com',
                 'foo.bar.com',
                 'foo.bar.com',
                 'foo.bar.com',
                 'foo.bar.com']

# Stonix can set OS X systems to use a local Apple Software Update Server
# if you have an ASUS server on your network enter its FQDN here. A zero
# length entry will be ignored.
APPLESOFTUPDATESERVER = 'http://asus.lanl.gov:8088/'

# Repository used by the package helper to retrieve software for installation.
# Currently only uses "https" as a valid protocol
MACREPOROOT = 'https://example.com/reporoot/'

# If you are using central logging servers for catching syslog data you can
# configure that hostname here as either a FQDN or IP address.
CENTRALLOGHOST = 'foo.bar.com'

# Warning Banners are site-specific
# You may edit the text of the warning banner here to reflect your particular
# site
WARNINGBANNER = "**WARNING**WARNING**WARNING**WARNING**WARNING**\n\n" + \
"This is a Department of Energy (DOE) computer system. DOE computer\n" + \
"systems are provided for the processing of official U.S. Government\n" + \
"information only. All data contained within DOE computer systems is\n" + \
"owned by the DOE, and may be audited, intercepted, recorded, read,\n" + \
"copied, or captured in any manner and disclosed in any manner, by\n" + \
"authorized personnel. THERE IS NO RIGHT OF PRIVACY IN THIS SYSTEM.\n" + \
"System personnel may disclose any potential evidence of crime found on\n" + \
"DOE computer systems to appropriate authorities. USE OF THIS SYSTEM BY\n" + \
"ANY USER, AUTHORIZED OR UNAUTHORIZED, CONSTITUTES CONSENT TO THIS\n" + \
"AUDITING, INTERCEPTION, RECORDING, READING, COPYING, CAPTURING, and\n" + \
"DISCLOSURE OF COMPUTER ACTIVITY.\n\n" + \
"**WARNING**WARNING**WARNING**WARNING**WARNING**\n"

ALTWARNINGBANNER = "This is a Department of Energy (DOE) computer system. DOE computer\n" + \
"systems are provided for the processing of official U.S. Government\n" + \
"information only. All data contained within DOE computer systems is\n" + \
"owned by the DOE, and may be audited, intercepted, recorded, read,\n" + \
"copied, or captured in any manner and disclosed in any manner, by\n" + \
"authorized personnel. THERE IS NO RIGHT OF PRIVACY IN THIS SYSTEM.\n" + \
"System personnel may disclose any potential evidence of crime found on\n" + \
"DOE computer systems to appropriate authorities. USE OF THIS SYSTEM BY\n" + \
"ANY USER, AUTHORIZED OR UNAUTHORIZED, CONSTITUTES CONSENT TO THIS\n" + \
"AUDITING, INTERCEPTION, RECORDING, READING, COPYING, CAPTURING, and\n" + \
"DISCLOSURE OF COMPUTER ACTIVITY.\n\n"

# Warning Banners abbreviated for OS X login Screen
OSXSHORTWARNINGBANNER = "This is a U.S. Government Federal computer " + \
"system. Authorized use only. Users have no explicit/implicit expectation " + \
"of privacy. By using this system the user consents to monitoring and " + \
"disclosure. USE OF THIS SYSTEM BY ANY USER, AUTHORIZED OR UNAUTHORIZED, " + \
"CONSTITUTES CONSENT TO THIS AUDITING, INTERCEPTION, RECORDING, READING, " + \
"COPYING, CAPTURING, and DISCLOSURE OF COMPUTER ACTIVITY. " + \
"See http://foo.bar.com/copyright.shtml#disclaimers"

# Here you can specify the FQDN of your mail relay server
# Use the convention: hostname.domain
MAILRELAYSERVER = 'foo.bar.com'

# STONIX Error Message Source Address
# Set this to the email address that STONIX error messages should appear to
# come from.
STONIXERR = 'stonixerr@bar.com'

# STONIX Error Message Destination
# Set the email address that STONIX error messages should be delivered to.
STONIXDEVS = 'stonix-dev@bar.com'

# Set the URL and port of your proxy server if one is in use.
# If you do not use a proxy server set this to None.
# Note that STONIX will not work through authenticating proxies.
# PROXY = 'http://my.proxy.com:3128'
# PROXY = None
# Variable Type: String
PROXY = None
# Variable Type: String
PROXYCONFIGURATIONFILE = None
# Variable Type: String
PROXYDOMAIN = None
# Variable Type: String
PROXYDOMAINBYPASS = None

# Domain Name Server (DNS) defaults
DNS = "192.168.0.1 192.168.0.2"

# (for redhat 7 and later) Specify a subnet to allow services access to in /etc/hosts.allow
ALLOWNETS = ['192.168.0.1/24']

# Specify a subnet to use with XinetdAccessControl (/etc/xinetd.conf)
XINETDALLOW = '192.168.0.1/24'

# Specify a subnet to allow printer browsing on
# This will be written in the cups config file for the system
PRINTBROWSESUBNET = '192.168.0.1/24'

# Specify a list of internal Network Time Protocol (NTP) Servers
NTPSERVERSINTERNAL = ["foo.bar.com", "foo.bar.com"]

# Specify a list of external Network Time Protocol (NTP) Servers
NTPSERVERSEXTERNAL = ["0.us.pool.ntp.org", "1.us.pool.ntp.org",
                      "2.us.pool.ntp.org", "3.us.pool.ntp.org"]

# List Of Corporate Network Servers used to determine if we are on the
# corporate network they need to be reachable only internally on port 80
CORPORATENETWORKSERVERS = ["foo.bar.com"]

# Content of the kerb5.conf file
MACKRB5 = '''[libdefaults]
    default_realm = bar.com
    allow_weak_crypto = true
    forwardable = true
[realms]
    bar.com = {
    kdc = foo.bar.com
    kdc = foo.bar.com
    admin_server = foo.bar.com
    }
[pam]
    debug = false
    krb4_convert = false
[domain_realm]
    foo.bar.com = FOO.BAR.COM
    .example.com = EXAMPLE.COM
    example.com = EXAMPLE.COM
'''

LINUXKRB5 = '''[logging]
 default = FILE:/var/log/krb5libs.log
 kdc = FILE:/var/log/krb5kdc.log
 admin_server = FILE:/var/log/kadmind.log

[libdefaults]
 default_realm = bar.com
 dns_lookup_realm = false
 dns_lookup_kdc = false
 ticket_lifetime = 24h
 renew_lifetime = 7d
 forwardable = true
 allow_weak_crypto = true
 clockslew = 300

[realms]

 bar.com = {
  kdc = foo.bar.com
    kdc = foo.bar.com
  admin_server = foo.bar.com
  default_domain = bar.com
 }

[domain_realm]
 bar.com = bar.com
 .bar.com = bar.com
'''

# Self Update server - a web server that houses packages for Mac, Solaris and
# Gentoo, for a self update feature, since these OSs do not have good package
# management like yum and apt-get.
SELFUPDATESERVER = "foo.bar.com"

HOSTSDENYDEFAULT = """##########################################################################
#
# FILENAME: hosts.deny
#  LASTMOD: Thu Jan  4 12:35:00 MST 2001
#
#  DESCRIP: CTN standard hosts.deny file for tcp wrappers with banners
#       OS: common
#
#   AUTHOR:
#
# WARNINGS: By default if it's not allowed it is denied
#
##########################################################################

all : all : banners /etc/banners : DENY
"""

HOSTSALLOWDEFAULT = """##########################################################################
## Filename:            hosts.allow
## Description:         Access control file for TCP Wrappers 7.6
## Author:
## Notes:               By default all services are denied. Uncomment the
##                      relevant lines to allow access.
## Release/ver:         stor3.1
## Modified date:       10/30/2007
## Changelog:           Added commented entries for nfs services
##########################################################################

# Allow access to localhost
all : 127.0.0.1 : ALLOW

# Kerberized services (uncomment to allow access)
#ftpd : {allownet} : ALLOW
#kshd : {allownet} : ALLOW
#klogind : {allownet} : ALLOW
#telnetd : {allownet} : ALLOW

# Need special access for sgi_fam
# Should be temporary
#fam: ALL : ALLOW

# Services that may be needed for NFS
#sunrpc: {allownet} : ALLOW
#nfs: {allownet} : ALLOW
#portmap: {allownet} : ALLOW
#lockd: {allownet} : ALLOW
#mountd: {allownet} : ALLOW
#rquotad: {allownet} : ALLOW
#statd: {allownet} : ALLOW

# SSH access
sshd: {allownet} : ALLOW
sshdfwd-X11: {allownet} : ALLOW

# Other services (uncomment to allow access)
#in.fingerd : {allownet} : banners /etc/banners : ALLOW
#in.ftpd : {allownet} : banners /etc/banners/in.ftpd : ALLOW
#in.rexecd : {allownet} : banners /etc/banners : ALLOW
#in.rlogind : {allownet} : banners /etc/banners/in.rlogind : ALLOW
#in.rshd : {allownet} : banners /etc/banners/in.rshd : ALLOW
#in.telnetd : {allownet} : banners /etc/banners/in.telnetd : ALLOW

# Deny all other access
all : all : DENY
"""

# This is used in the SecureMailClient Rule to set up DomainForMatching
APPLEMAILDOMAINFORMATCHING = "bar.com"

# This list contains quoted strings that are fully qualified paths to
# world writable directories that are common at your site (possibly due to
# widely deployed software).
SITELOCALWWWDIRS = []

# Default messages for self.detailedresults initialization, report, fix, undo
DRINITIAL = "Neither report, fix, or revert have been run yet."
DRREPORTCOMPIANT = "Rule is Compliant."
DRREPORTNOTCOMPIANT = "Rule is not Compliant."
DRREPORTNOTAVAILABLE = "This Rule does not support report."
DRFIXSUCCESSFUL = "Rule was fixed successfully."
DRFIXFAILED = "The fix for this Rule failed."
DRFIXNOTAVAILABLE = "This Rule does not support fix."
DRREPORTAVAILABLE = "This Rule does not support report."
DRUNDOSUCCESSFUL = "Revert was completed successfully."
DRUNDOFAILED = "The revert for this Rule failed."
DRUNDONOTAVAILABLE = "No recoverable events are available for this Rule."
GATEKEEPER = "4BF178C7-A564-46BA-8BD1-9C374043CC17"
WINLOG = "@@foo.bar.com"
LANLLOGROTATE = "700.lanl.logrotate"

# These are accounts to exclude from DisableInactiveAccounts rule
EXCLUDEACCOUNTS = []

# The following list is used by AuditFirefoxUsage(84). It lists domains that
# are approved for browsing by the root user.
LOCALDOMAINS = ["127.0.0.1", "localhost", "bar.com"]

# these options will be set in /etc/dhcp/dhclient.conf
# a value of 'request' will cause the client to request that
# option's configuration from the dhcp server. a value of
# 'supersede' will cause the client to use the locally-defined
# value in the dhclient.conf configuration file
DHCPDict = {'subnet-mask': 'request',
            'broadcast-address': 'supersede',
            'time-offset': 'supersede',
            'routers': 'supersede',
            'domain-name': 'supersede',
            'domain-name-servers': 'supersede',
            'host-name': 'supersede',
            'nis-domain': 'supersede',
            'nis-servers': 'supersede',
            'ntp-servers': 'supersede'}

# these options will be used whenever a value of
# 'supersede' is specified for one of the options in
# DCHPDict. Change these to reflect your organization's
# actual servers/domains/settings
DHCPSup = {'subnet-mask': '"example.com"',
           'broadcast-address': '192.168.1.255',
           'time-offset': '-18000',
           'routers': '192.168.1.1',
           'domain-name': '"example.com"',
           'domain-name-servers': '192.168.1.2',
           'host-name': '"localhost"',
           'nis-domain': '""',
           'nis-servers': '""',
           'ntp-servers': '"ntp.example.com"'}

AUTH_APT = '''auth        required      pam_env.so
auth        required      pam_tally2.so deny=5 unlock_time=900 onerr=fail
auth        sufficient    pam_unix.so try_first_pass
auth        requisite     pam_succeed_if.so uid >= 500 quiet
auth        sufficient    pam_krb5.so use_first_pass
auth        required      pam_deny.so
'''

ACCOUNT_APT = '''account     required      pam_tally2.so
account     required      pam_access.so
account     required      pam_unix.so broken_shadow
account     sufficient    pam_localuser.so
account     sufficient    pam_succeed_if.so uid < 500 quiet
account     [default=bad success=ok user_unknown=ignore] pam_krb5.so
account     required      pam_permit.so
'''

PASSWORD_APT = '''password    requisite     \
pam_pwquality.so minlen=14 minclass=4 difok=7 dcredit=0 ucredit=0 lcredit=0 \
ocredit=0 retry=3 maxrepeat=3
password    sufficient    pam_unix.so sha512 shadow try_first_pass \
use_authtok remember=10
password    sufficient    pam_krb5.so use_authtok
password    required      pam_deny.so
'''

SESSION_APT = '''session     optional      pam_keyinit.so revoke
session     required      pam_limits.so
session     [success=1 default=ignore] pam_succeed_if.so service in crond \
quiet use_uid
session     required      pam_unix.so
session     optional      pam_krb5.so
-session    optional      pam_systemd.so
'''

SESSION_HOME_APT = '''session     optional      pam_keyinit.so revoke
session     required      pam_limits.so
session     [success=1 default=ignore] pam_succeed_if.so service in crond \
quiet use_uid
session     required      pam_unix.so
session     optional      pam_krb5.so
-session    optional      pam_systemd.so
session     required      pam_mkhomedir.so skel=/etc/skel umask=0077
'''

AUTH_ZYPPER = '''auth    required        pam_env.so
auth    required        pam_tally2.so deny=5 unlock_time=900 onerr=fail
auth    optional        pam_gnome_keyring.so
auth    sufficient      pam_unix.so     try_first_pass
auth    required        pam_sss.so      use_first_pass
'''

ACCOUNT_ZYPPER = '''account requisite       pam_unix.so     try_first_pass
account sufficient      pam_localuser.so
account required        pam_sss.so      use_first_pass
'''

PASSWORD_ZYPPER = '''password        requisite       \
pam_pwquality.so minlen=14 minclass=4 difok=7 dcredit=0 ucredit=0 lcredit=0 \
ocredit=0 retry=3 maxrepeat=3
password        sufficient      pam_unix.so sha512 shadow \
try_first_pass use_authtok remember=10
password        optional        pam_gnome_keyring.so    use_authtok
password        required        pam_sss.so      use_authtok
'''

SESSION_ZYPPER = '''session required        pam_limits.so
session required        pam_unix.so     try_first_pass
session optional        pam_sss.so
session optional        pam_umask.so
session optional        pam_systemd.so
session optional        pam_gnome_keyring.so    auto_start \
only_if=gdm,gdm-password,lxdm,lightdm
session optional        pam_env.so
'''

SESSION_HOME_ZYPPER = '''session required        pam_limits.so
session required        pam_unix.so     try_first_pass
session optional        pam_sss.so
session optional        pam_umask.so
session optional        pam_systemd.so
session optional        pam_gnome_keyring.so    auto_start \
only_if=gdm,gdm-password,lxdm,lightdm
session optional        pam_env.so
session     required      pam_mkhomedir.so skel=/etc/skel umask=0077
'''

AUTH_NSLCD = '''auth        required      pam_env.so
auth        required      pam_faillock.so preauth silent audit deny=5 \
unlock_time=900 fail_interval=900
auth        sufficient    pam_unix.so try_first_pass
auth        requisite     pam_succeed_if.so uid >= 500 quiet
auth        sufficient    pam_krb5.so use_first_pass
auth        [default=die] pam_faillock.so authfail audit deny=5 \
unlock_time=900 fail_interval=900
auth        required      pam_deny.so
'''

ACCOUNT_NSLCD = '''account     required      pam_faillock.so
account     required      pam_access.so
account     required      pam_unix.so broken_shadow
account     sufficient    pam_localuser.so
account     sufficient    pam_succeed_if.so uid < 500 quiet
account     [default=bad success=ok user_unknown=ignore] pam_krb5.so
account     required      pam_permit.so
'''

PASSWORD_NSLCD = '''password    requisite     pam_pwquality.so minlen=14 \
minclass=4 difok=7 dcredit=0 ucredit=0 lcredit=0 ocredit=0 retry=3 maxrepeat=3
password    sufficient    pam_unix.so sha512 shadow \
try_first_pass use_authtok remember=10
password    sufficient    pam_krb5.so use_authtok
password    required      pam_deny.so
'''

SESSION_NSLCD = '''session     optional      pam_keyinit.so revoke
session     required      pam_limits.so
session     [success=1 default=ignore] pam_succeed_if.so service in crond \
quiet use_uid
session     required      pam_unix.so
session     optional      pam_krb5.so
'''

SESSION_HOME_NSLCD = '''session     optional      pam_keyinit.so revoke
session     required      pam_limits.so
session     optional      pam_mkhomedir.so umask=0077
session     [success=1 default=ignore] pam_succeed_if.so service in crond \
quiet use_uid
session     required      pam_unix.so
session     optional      pam_krb5.so
'''

AUTH_YUM = '''auth        required      pam_env.so
auth        required      pam_faillock.so preauth silent audit deny=5 \
unlock_time=900 fail_interval=900
auth        sufficient    pam_unix.so try_first_pass
auth        requisite     pam_succeed_if.so uid >= 500 quiet
auth        sufficient    pam_sss.so use_first_pass
auth        sufficient    pam_krb5.so use_first_pass
auth        [default=die] pam_faillock.so authfail audit deny=5 \
unlock_time=900 fail_interval=900
auth        required      pam_deny.so
'''

ACCOUNT_YUM = '''account     required      pam_faillock.so
account     required      pam_access.so
account     required      pam_unix.so broken_shadow
account     sufficient    pam_localuser.so
account     sufficient    pam_succeed_if.so uid < 500 quiet
account     [default=bad success=ok user_unknown=ignore] pam_sss.so
account     [default=bad success=ok user_unknown=ignore] pam_krb5.so
account     required      pam_permit.so
'''

PASSWORD_YUM = '''password    requisite     pam_pwquality.so minlen=14 \
minclass=4 difok=7 dcredit=0 ucredit=0 lcredit=0 ocredit=0 retry=3 maxrepeat=3
password    sufficient    pam_unix.so sha512 shadow try_first_pass \
use_authtok remember=10
password    sufficient    pam_sss.so use_authtok
password    sufficient    pam_krb5.so use_authtok
password    required      pam_deny.so
'''

SESSION_YUM = '''session     optional      pam_keyinit.so revoke
session     required      pam_limits.so
-session    optional      pam_systemd.so
session     [success=1 default=ignore] pam_succeed_if.so service in crond \
quiet use_uid
session     required      pam_unix.so
session     optional      pam_sss.so
session     optional      pam_krb5.so
'''

SESSION_HOME_YUM = '''session     optional      pam_keyinit.so revoke
session     required      pam_limits.so
-session    optional      pam_systemd.so
session     optional      pam_mkhomedir.so umask=0077
session     [success=1 default=ignore] pam_succeed_if.so service in crond \
quiet use_uid
session     required      pam_unix.so
session     optional      pam_sss.so
session     optional      pam_krb5.so
'''
