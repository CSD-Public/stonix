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
Created on Oct 18, 2012

This module contains variables used to localize STONIX behavior for a given
site. It is intended to be edited by the personnel packaging STONIX for use and
is not intended to be modified by systems administrators or end users.

These variables will be referenced directly by STONIX with only nominal safety
checks. Mistakes made in this file may lead to errors in STONIX behavior or
run-time failures. Pay attention to comments documenting both the content and
format of entries.

@author: David Kennel

@change: 2014/08/20 - Added version variable to here and updated all locations
that access the version variable to use this copy.
@change: 2015/03/01 - Ekkehard - incremented STONIXVERSION to '0.8.15'
@change: 2015/04/07 - Ekkehard - incremented STONIXVERSION to '0.8.16'
@change: 2015/08/20 - Eric Ball - Added KRB5 for Linux Kerberos setup
@change: 2015/12/07 - Eric Ball Renamed KERB5 to MACKRB5 and KRB5 to LINUXKRB5
@change: 2015/12/14 - Ekkehard update os x kerberos option & stonixversion
@change: 2016/01/13 - Roy Nielsen Added MACREPOROOT
@change: 2016/02/03 - Ekkehard - incremented STONIXVERSION to '0.9.5'
@change: 2016/05/05 - Eric Ball Add LOCALDOMAINS for AuditFirefoxUsage(84)
@change: 2015/12/14 - Ekkehard update os x kerberos option & stonixversion
@change: 2016/01/13 - Roy Nielsen Added MACREPOROOT
@change: 2016/02/03 - Ekkehard - incremented STONIXVERSION to '0.9.5'
@change: 2017/03/07 - David Kennel add FISMACAT for FISMA/FIPS 199 risk category
@change: 2017/07/07 - Ekkehard - incremented STONIXVERSION to '0.9.10'
@change: 2017/10/10 - Ekkehard - incremented STONIXVERSION to '0.9.13'
@change: 2017/11/13 - Ekkehard - incremented STONIXVERSION to '0.9.14'
@change: 2018/02/06 - Ekkehard - incremented STONIXVERSION to '0.9.16'
@change: 2018/02/06 - Ekkehard - incremented STONIXVERSION to '0.9.17'
@change: 2018/04/11 - Ekkehard - incremented STONIXVERSION to '0.9.18' and krb5.conf
@change: 2018/05/08 - Ekkehard - incremented STONIXVERSION to '0.9.19'
@change: 2018/06/08 - Ekkehard - incremented STONIXVERSION to '0.9.20'
@change: 2018/08/21 - Brandon - changed CRACKLIB_HIGH_REGEX minlen and
                                PWQUALITY_HIGH_REGEX minlen from 12 to 14
@change: 2018/11/14 - Breen Malmberg - incremented STONIXVERSION to '0.9.26'
@change: 2019/02/05 - Breen Malmberg - incremented STONIXVERSION to '0.9.28'
@change: 2019/03/12 - Ekkehard - incremented STONIXVERSION to '0.9.29'
@change: 2019/04/08 - Breen Malmberg - incremented STONIXVERSION to '0.9.30'
"""

FISMACAT = 'med'

# The Version number of the STONIX application. Modify this only if you need to
# define a local version number. Caution should be used to not conflict with
# the upstream versioning numbers. The version is handled as a string so
# arbitrary values are fine. A recommended local version might look like this:
# 1.2.2-local3 or just 1.2.2-3 or 1.2.2.3
# Variable Type: String
STONIXVERSION = '0.9.41'

# The report server should be a string containing a valid FQDN or IP address
# for the host that STONIX should upload it's run report XML data to.
REPORTSERVER = None

# If you are not using a central report server then set the value of
# sendreports to False. Please note no quotes.
# sendreports = False
# Variable Type: Boolean
SENDREPORTS = False

# The SoftwarePatching rule will check to see if local update sources are being
# used. If you have local update sources list them here. This check will be
# skipped if the list is empty. The list is in python list format:
# updateservers = ['myserver1.mydomain.tld', 'myserver2.mydomain.tld']
# Variable Type: List (of strings)
UPDATESERVERS = None

# Stonix can set OS X systems to use a local Apple Software Update Server
# if you have an ASUS server on your network enter its FQDN here. A zero
# length entry will be ignored.
# Variable Type: String
# ex: "http://foo.bar.domain:port/"
APPLESOFTUPDATESERVER = None

# Repository used by the package helper to retrieve software for installation.
# Currently only uses "https" as a valid protocol
# Variable Type: String
MACREPOROOT = None

# If you are using central logging servers for catching syslog data you can
# configure that hostname here as either a FQDN or IP address.
# Variable Type: String
CENTRALLOGHOST = None

# Warning Banners are site-specific
# You may edit the text of the warning banner here to reflect your particular
# site
WARNINGBANNER = None

GDMWARNINGBANNER = None

GDM3WARNINGBANNER = None

# Variable Type: String
# Shorter version of warning banner
# Needed on some systems which have limited warning banner display area
ALTWARNINGBANNER = None

# Warning Banners abbreviated for OS X login Screen
# Variable Type: String
OSXSHORTWARNINGBANNER = None

# Variable Type: String
# Here you can specify the FQDN of your mail relay server
# Use the convention: hostname.domain
MAILRELAYSERVER = None

# Variable Type: String
# STONIX Error Message Source Address
# Set this to the email address that STONIX error messages should appear to
# come from.
STONIXERR = None

# Variable Type: String
# STONIX Error Message Destination
# Set the email address that STONIX error messages should be delivered to.
STONIXDEVS = None

# Variable Type: String
# Set the URL and port of your proxy server if one is in use.
# If you do not use a proxy server set this to None.
# Note that STONIX will not work through authenticating proxies.
# PROXY = 'http://my.proxy.com:3128'
# PROXY = None
PROXY = None

# Variable Type: String
PROXYCONFIGURATIONFILE = None

# Variable Type: String
PROXYDOMAIN = None

# Variable Type: String
PROXYDOMAINBYPASS = None

# Domain Name Server (DNS) defaults
# Variable Type: String
DNS = "192.168.0.1 192.168.0.2"

# (for redhat 7 and later) Specify a subnet to allow services access to in /etc/hosts.allow
# Variably Type: List (of strings)
ALLOWNETS = ['192.168.0.1/24']

# Specify a subnet to use with XinetdAccessControl (/etc/xinetd.conf)
# Variable Type: String
XINETDALLOW = '192.168.0.1/24'

# Specify a list of internal Network Time Protocol (NTP) Servers
# Variable Type: List (of strings)
NTPSERVERSINTERNAL = None

# Specify a list of external Network Time Protocol (NTP) Servers
# Variable Type: List (of strings)
NTPSERVERSEXTERNAL = ["0.us.pool.ntp.org", "1.us.pool.ntp.org",
                      "2.us.pool.ntp.org", "3.us.pool.ntp.org"]

# List Of Corporate Network Servers used to determine if we are on the
# corporate network they need to be reachable only internally on port 80
# Variable Type: List (of strings)
CORPORATENETWORKSERVERS = None

# Content of the krb5.conf file
# Variable Type: String
MACKRB5 = None

# Content of the krb5.conf file
# Variable Type: String
LINUXKRB5 = None

# Self Update server - a web server that houses packages for Mac, Solaris and
# Gentoo, for a self update feature, since these OSs do not have good package
# management like yum and apt-get.
# Variable Type: String
SELFUPDATESERVER = None

# Variable Type: String
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

# Variable Type: String
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
# Variable Type: String
APPLEMAILDOMAINFORMATCHING = None

# This list contains quoted strings that are fully qualified paths to
# world writable directories that are common at your site (possibly due to
# widely deployed software).
# Variable Type: List (of strings)
SITELOCALWWWDIRS = None

# Default messages for self.detailedresults initialization, report, fix, undo
# Variables Type: String
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
GATEKEEPER = None
WINLOG = None

# Variable Type: List (strings)
# The following should be system accounts which should not be disabled by DisableInactiveAccounts
EXCLUDEACCOUNTS = []

# Variable Type: List (strings)
# The following list is used by AuditFirefoxUsage(84). It lists domains that
# are approved for browsing by the root user.
LOCALDOMAINS = ["127.0.0.1", "localhost"]

# these options will be set in /etc/dhcp/dhclient.conf
# a value of 'request' will cause the client to request that
# option's configuration from the dhcp server. a value of
# 'supersede' will cause the client to use the locally-defined
# value in the DHCPSup dictionary, defined here in localize.py
DHCPDict = {'subnet-mask': 'request',
            'time-offset': 'supersede',
            'routers': 'request',
            'domain-name': 'supersede',
            'domain-name-servers': 'supersede',
            'nis-domain': 'supersede',
            'nis-servers': 'supersede',
            'ntp-servers': 'supersede'}

# these options will be used whenever a value of
# 'supersede' is specified for one of the options in
# DCHPDict. Change these to reflect your organization's
# actual servers/domains/settings
# Variable Type: Dictionary (of string keys and string values)
# EX:
# {'broadcast-address': '192.168.',
#            'time-offset': '3',
#            'routers': 'routername.foo.bar',
#            'domain-name': 'foo.bar',
#            'domain-name-servers': 'dns.foo.bar',
#            'host-name': 'host.foo.bar',
#            'nis-domain': 'foo.nis',
#            'nis-servers': 'nis.foo.bar',
#            'ntp-servers': 'ntp.foo.bar'}
# change the 'changeme' values if you choose to supersede
# them in the DHCPDict dictionary, above!
DHCPSup = {}

# Variable Type: String
ROOTCERT = None

# Variable Type: String
PWQUALITY_HIGH_REGEX =  "^password[ \t]+requisite[ \t]+pam_pwquality.so[ \t]+" + \
    "minlen=14[ \t]+minclass=4[ \t]+difok=7[ \t]+dcredit=0[ \t]ucredit=0[ \t]" + \
    "lcredit=0[ \t]+ocredit=0[ \t]+retry=3[ \t]+maxrepeat=3"

# Variable Type: String
PWQUALITY_REGEX = "^password[ \t]+requisite[ \t]+pam_pwquality.so[ \t]+" + \
    "minlen=8[ \t]+minclass=3[ \t]+difok=7[ \t]+dcredit=0[ \t]+ucredit=0[ \t]+" + \
    "lcredit=0[ \t]+ocredit=0[ \t]+retry=3[ \t]+maxrepeat=3"

# Variable Type: String
CRACKLIB_HIGH_REGEX = "^password[ \t]+requisite[ \t]+pam_cracklib.so[ \t]+" + \
    "minlen=14[ \t]+minclass=4[ \t]+difok=7[ \t]+dcredit=0[ \t]ucredit=0[ \t]" + \
    "lcredit=0[ \t]+ocredit=0[ \t]+retry=3[ \t]+maxrepeat=3"

# Variable Type: String
CRACKLIB_REGEX = "^password[ \t]+requisite[ \t]+pam_cracklib.so[ \t]+" + \
    "minlen=8[ \t]+minclass=3[ \t]+difok=7[ \t]+dcredit=0[ \t]ucredit=0[ \t]" + \
    "lcredit=0[ \t]+ocredit=0[ \t]+retry=3[ \t]+maxrepeat=3"

# Variable Type: String
PAMFAIL_REGEX = "^auth[ \t]+required[ \t]+pam_faillock.so preauth silent audit " + \
                        "deny=5 unlock_time=900 fail_interval=900"

# Variable Type: String
PAMTALLY_REGEX = "^auth[ \t]+required[ \t]+pam_tally2.so deny=5 " + \
                        "unlock_time=900 onerr=fail"

# Variable Type: String
AUTH_APT = '''auth        required      pam_env.so
auth        required      pam_tally2.so deny=5 unlock_time=900 onerr=fail
auth        sufficient    pam_unix.so try_first_pass
auth        requisite     pam_succeed_if.so uid >= 500 quiet
auth        sufficient    pam_krb5.so use_first_pass
auth        required      pam_deny.so
'''

# Variable Type: String
ACCOUNT_APT = '''account     required      pam_tally2.so
account     required      pam_access.so
account     required      pam_unix.so broken_shadow
account     sufficient    pam_localuser.so
account     sufficient    pam_succeed_if.so uid < 500 quiet
account     sufficient    pam_ldap.so
account     [default=bad success=ok user_unknown=ignore] pam_krb5.so
account     required      pam_permit.so
'''

# Variable Type: String
PASSWORD_APT = '''password    requisite     \
pam_pwquality.so minlen=8 minclass=3 difok=7 dcredit=0 ucredit=0 lcredit=0 \
ocredit=0 retry=3 maxrepeat=3
password    sufficient    pam_unix.so sha512 shadow try_first_pass \
use_authtok remember=10
password    sufficient    pam_krb5.so use_authtok
password    required      pam_deny.so
'''

# Variable Type: String
SESSION_APT = '''session     optional      pam_keyinit.so revoke
session     required      pam_limits.so
session     [success=1 default=ignore] pam_succeed_if.so service in crond \
quiet use_uid
session     required      pam_unix.so
session     optional      pam_krb5.so
-session    optional      pam_systemd.so
'''

# Variable Type: String
SESSION_HOME_APT = '''session     optional      pam_keyinit.so revoke
session     required      pam_limits.so
session     [success=1 default=ignore] pam_succeed_if.so service in crond \
quiet use_uid
session     required      pam_unix.so
session     optional      pam_krb5.so
-session    optional      pam_systemd.so
session     required      pam_mkhomedir.so skel=/etc/skel umask=0077
'''

# Variable Type: String
AUTH_ZYPPER = '''auth    required        pam_env.so
auth    required        pam_tally2.so deny=5 unlock_time=900 onerr=fail
auth    optional        pam_gnome_keyring.so
auth    sufficient      pam_unix.so     try_first_pass
auth    required        pam_sss.so      use_first_pass
'''

# Variable Type: String
ACCOUNT_ZYPPER = '''account requisite       pam_unix.so     try_first_pass
account sufficient      pam_localuser.so
account required        pam_sss.so      use_first_pass
'''

# Variable Type: String
PASSWORD_ZYPPER = '''password        requisite       \
pam_pwquality.so minlen=8 minclass=3 difok=7 dcredit=0 ucredit=0 lcredit=0 \
ocredit=0 retry=3 maxrepeat=3
password        sufficient      pam_unix.so sha512 shadow \
try_first_pass use_authtok remember=10
password        optional        pam_gnome_keyring.so    use_authtok
password        required        pam_sss.so      use_authtok
'''

# Variable Type: String
SESSION_ZYPPER = '''session required        pam_limits.so
session required        pam_unix.so     try_first_pass
session optional        pam_sss.so
session optional        pam_umask.so
session optional        pam_systemd.so
session optional        pam_gnome_keyring.so    auto_start \
only_if=gdm,gdm-password,lxdm,lightdm
session optional        pam_env.so
'''

# Variable Type: String
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

# Variable Type: String
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

# Variable Type: String
ACCOUNT_NSLCD = '''account     required      pam_faillock.so
account     required      pam_access.so
account     required      pam_unix.so broken_shadow
account     sufficient    pam_localuser.so
account     sufficient    pam_succeed_if.so uid < 500 quiet
account     sufficient    pam_ldap.so
account     [default=bad success=ok user_unknown=ignore] pam_krb5.so
account     required      pam_permit.so
'''

# Variable Type: String
PASSWORD_NSLCD = '''password    requisite     pam_pwquality.so minlen=8 \
minclass=3 difok=7 dcredit=0 ucredit=0 lcredit=0 ocredit=0 retry=3 maxrepeat=3
password    sufficient    pam_unix.so sha512 shadow \
try_first_pass use_authtok remember=10
password    sufficient    pam_krb5.so use_authtok
password    required      pam_deny.so
'''

# Variable Type: String
SESSION_NSLCD = '''session     optional      pam_keyinit.so revoke
session     required      pam_limits.so
session     [success=1 default=ignore] pam_succeed_if.so service in crond \
quiet use_uid
session     required      pam_unix.so
session     optional      pam_krb5.so
'''

# Variable Type: String
SESSION_HOME_NSLCD = '''session     optional      pam_keyinit.so revoke
session     required      pam_limits.so
session     optional      pam_mkhomedir.so umask=0077
session     [success=1 default=ignore] pam_succeed_if.so service in crond \
quiet use_uid
session     required      pam_unix.so
session     optional      pam_krb5.so
'''

# Variable Type: String
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

# Variable Type: String
ACCOUNT_YUM = '''account     required      pam_faillock.so
account     required      pam_access.so
account     required      pam_unix.so broken_shadow
account     sufficient    pam_localuser.so
account     sufficient    pam_succeed_if.so uid < 500 quiet
account     sufficient    pam_ldap.so
account     [default=bad success=ok user_unknown=ignore] pam_sss.so
account     [default=bad success=ok user_unknown=ignore] pam_krb5.so
account     required      pam_permit.so
'''

# Variable Type: String
PASSWORD_YUM = '''password    requisite     pam_pwquality.so minlen=8 \
minclass=3 difok=7 dcredit=0 ucredit=0 lcredit=0 ocredit=0 retry=3 maxrepeat=3
password    sufficient    pam_unix.so sha512 shadow try_first_pass \
use_authtok remember=10
password    sufficient    pam_sss.so use_authtok
password    sufficient    pam_krb5.so use_authtok
password    required      pam_deny.so
'''

# Variable Type: String
SESSION_YUM = '''session     optional      pam_keyinit.so revoke
session     required      pam_limits.so
-session    optional      pam_systemd.so
session     [success=1 default=ignore] pam_succeed_if.so service in crond \
quiet use_uid
session     required      pam_unix.so
session     optional      pam_sss.so
session     optional      pam_krb5.so
'''

# Variable Type: String
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
